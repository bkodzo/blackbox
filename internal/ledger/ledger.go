// Package ledger is an append-only, tamper-evident log.
//
// Each line is an envelope around one record:
//
//	{"seq":42,"prev":"<hex>","hash":"<hex>","sig":"<base64>","rec":{...}}
//
// hash = SHA-256(seq as 8 big-endian bytes, then prev hash, then rec bytes), and sig is
// an Ed25519 signature over hash. The rec bytes are hashed exactly as written,
// so verification never re-encodes JSON. Chaining catches edits, deletions and
// reordering; signatures stop an attacker without the key from rebuilding the
// chain; checkpoints kept elsewhere catch records cut from the end.
package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

// Entry is one line of the log: a record plus the fields that seal it.
type Entry struct {
	Seq  uint64          `json:"seq"`
	Prev string          `json:"prev"`
	Hash string          `json:"hash"`
	Sig  string          `json:"sig"`
	Rec  json.RawMessage `json:"rec"`
}

// GenesisPrev is the prev hash of the first entry.
var GenesisPrev = hex.EncodeToString(make([]byte, sha256.Size))

func chainHash(seq uint64, prev, rec []byte) [sha256.Size]byte {
	h := sha256.New()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], seq)
	h.Write(b[:])
	h.Write(prev)
	h.Write(rec)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// appendLine encodes e as a log line. Built by hand so rec is copied verbatim.
func (e *Entry) appendLine(b []byte) []byte {
	b = append(b, `{"seq":`...)
	b = strconv.AppendUint(b, e.Seq, 10)
	b = append(b, `,"prev":"`...)
	b = append(b, e.Prev...)
	b = append(b, `","hash":"`...)
	b = append(b, e.Hash...)
	b = append(b, `","sig":"`...)
	b = append(b, e.Sig...)
	b = append(b, `","rec":`...)
	b = append(b, e.Rec...)
	return append(b, "}\n"...)
}

// check recomputes the entry's hash from its own fields and verifies its
// signature. It returns the decoded hash, or a reason the entry is invalid.
func (e *Entry) check(pub ed25519.PublicKey) ([]byte, string) {
	prev, err := hex.DecodeString(e.Prev)
	if err != nil || len(prev) != sha256.Size {
		return nil, "malformed prev hash"
	}
	sum := chainHash(e.Seq, prev, e.Rec)
	if hex.EncodeToString(sum[:]) != e.Hash {
		return nil, "contents were modified (hash mismatch)"
	}
	sig, err := base64.StdEncoding.DecodeString(e.Sig)
	if err != nil || !ed25519.Verify(pub, sum[:], sig) {
		return nil, "signature is invalid (not written by this gateway's key)"
	}
	return sum[:], ""
}

// Options tune durability and checkpointing. Zero values pick defaults.
type Options struct {
	// Sync makes every Append durable before it returns. Otherwise appends are
	// group-committed: flushed every FlushInterval or FlushRecords appends.
	Sync          bool
	FlushInterval time.Duration // default 50ms
	FlushRecords  int           // default 64

	// CheckpointPath receives a signed copy of the head after durable flushes,
	// at most every CheckpointRecords records or CheckpointInterval.
	CheckpointPath     string
	CheckpointRecords  uint64        // default 1000
	CheckpointInterval time.Duration // default 5m
	// CheckpointMirror, if set, also receives every checkpoint line, so a copy
	// can live outside this machine (e.g. stdout shipped to a log collector).
	CheckpointMirror io.Writer
}

func (o *Options) setDefaults() {
	if o.FlushInterval <= 0 {
		o.FlushInterval = 50 * time.Millisecond
	}
	if o.FlushRecords <= 0 {
		o.FlushRecords = 64
	}
	if o.CheckpointRecords == 0 {
		o.CheckpointRecords = 1000
	}
	if o.CheckpointInterval <= 0 {
		o.CheckpointInterval = 5 * time.Minute
	}
}

// Checkpoint is a signed statement of the log's head at a point in time.
// Its signature is the head entry's own signature, so it cannot be forged
// without the key.
type Checkpoint struct {
	Seq  uint64    `json:"seq"`
	Hash string    `json:"hash"`
	Sig  string    `json:"sig"`
	Time time.Time `json:"ts"`
}

// Ledger appends entries to a log file. It is safe for concurrent use.
//
// Appends only touch an in-memory buffer under mu. A background flusher swaps
// that buffer out under mu, then writes and fsyncs without holding it, so
// appenders never wait on the disk unless Options.Sync is set. (On some
// systems a write blocks while an fsync of the same file is in progress, so
// even the write must happen outside mu.)
type Ledger struct {
	opt Options
	key ed25519.PrivateKey
	f   *os.File

	mu      sync.Mutex // guards the fields below
	pend    []byte     // encoded entries not yet written to the file
	size    int64      // bytes in the file, including pending ones
	seq     uint64
	head    []byte
	last    *Entry
	pending int   // appended but not yet written out
	err     error // sticky: once a write fails, the ledger stops accepting
	closing bool

	syncMu  sync.Mutex // serializes flushes; guards the fields below
	spare   []byte     // reused as the next pend buffer
	durable *Entry     // newest entry known to be on disk
	cp      *os.File
	cpSeq   uint64
	cpTime  time.Time

	torn int64 // bytes of an incomplete final line removed at Open
	kick chan struct{}
	stop chan struct{}
	done chan struct{}
}

// ErrClosed is returned by Append after Close.
var ErrClosed = errors.New("ledger: closed")

// Open opens or creates the log at path and resumes its chain. If the file
// ends in an incomplete line (a crash mid-write), that line is removed and
// reported by TornBytes. The last entry must verify against key.
func Open(path string, key ed25519.PrivateKey, opt Options) (*Ledger, error) {
	opt.setDefaults()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Ledger{opt: opt, key: key, f: f, head: make([]byte, sha256.Size), cpTime: time.Now()}

	line, torn, err := recoverTail(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	l.torn = torn
	if l.size, err = f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	if line != nil {
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			f.Close()
			return nil, fmt.Errorf("ledger: last entry is malformed: %w", err)
		}
		head, reason := e.check(key.Public().(ed25519.PublicKey))
		if reason != "" {
			f.Close()
			return nil, fmt.Errorf("ledger: last entry (seq %d) %s; run `blackbox verify`", e.Seq, reason)
		}
		l.seq, l.head, l.last, l.durable = e.Seq, head, &e, &e
	}

	if opt.CheckpointPath != "" {
		if l.cp, err = os.OpenFile(opt.CheckpointPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600); err != nil {
			f.Close()
			return nil, err
		}
		cpLine, _, err := recoverTail(l.cp)
		if err != nil {
			l.closeFiles()
			return nil, err
		}
		var c Checkpoint
		if cpLine != nil && json.Unmarshal(cpLine, &c) == nil {
			l.cpSeq = c.Seq
		}
	}

	l.kick = make(chan struct{}, 1)
	l.stop, l.done = make(chan struct{}), make(chan struct{})
	go l.loop()
	return l, nil
}

// recoverTail returns the last complete line of f and truncates any bytes
// after it (an interrupted write), returning how many were removed.
func recoverTail(f *os.File) (line []byte, torn int64, err error) {
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := st.Size()
	var buf []byte // holds file bytes [pos, size)
	pos, end := size, int64(-1)
	for chunk := int64(64 << 10); ; chunk *= 2 {
		if pos == 0 {
			if end > 0 {
				line = buf[:end-1]
			}
			break
		}
		n := min(chunk, pos)
		pos -= n
		b := make([]byte, n, n+int64(len(buf)))
		if _, err := f.ReadAt(b, pos); err != nil {
			return nil, 0, err
		}
		buf = append(b, buf...)
		if end < 0 {
			i := bytes.LastIndexByte(buf, '\n')
			if i < 0 {
				continue
			}
			end = pos + int64(i) + 1
		}
		last := int(end - pos - 1) // index of the final newline in buf
		if i := bytes.LastIndexByte(buf[:last], '\n'); i >= 0 {
			line = buf[i+1 : last]
			break
		}
	}
	if end < 0 {
		end = 0
	}
	if end < size {
		if err := f.Truncate(end); err != nil {
			return nil, 0, err
		}
		if err := f.Sync(); err != nil {
			return nil, 0, err
		}
	}
	return line, size - end, nil
}

// Append seals rec (single-line JSON) as the next entry and returns it with
// its byte offset in the file. Unless Options.Sync is set, the entry becomes
// durable at the next group commit.
func (l *Ledger) Append(rec []byte) (Entry, int64, error) {
	if len(rec) == 0 || bytes.IndexByte(rec, '\n') >= 0 {
		return Entry{}, 0, errors.New("ledger: record must be non-empty single-line JSON")
	}
	l.mu.Lock()
	if l.err != nil {
		defer l.mu.Unlock()
		return Entry{}, 0, l.err
	}
	if l.closing {
		l.mu.Unlock()
		return Entry{}, 0, ErrClosed
	}

	seq := l.seq + 1
	sum := chainHash(seq, l.head, rec)
	e := Entry{
		Seq:  seq,
		Prev: hex.EncodeToString(l.head),
		Hash: hex.EncodeToString(sum[:]),
		Sig:  base64.StdEncoding.EncodeToString(ed25519.Sign(l.key, sum[:])),
		Rec:  rec,
	}
	n := len(l.pend)
	l.pend = e.appendLine(l.pend)
	off := l.size
	l.size += int64(len(l.pend) - n)
	l.seq, l.head, l.last = seq, sum[:], &e
	l.pending++
	full := l.pending >= l.opt.FlushRecords
	l.mu.Unlock()

	if l.opt.Sync {
		return e, off, l.flush(false)
	}
	if full {
		select {
		case l.kick <- struct{}{}:
		default: // a flush is already requested
		}
	}
	return e, off, nil
}

// flush writes buffered entries to the file, fsyncs without holding mu, and
// then checkpoints if one is due (or forced).
func (l *Ledger) flush(forceCheckpoint bool) error {
	l.syncMu.Lock()
	defer l.syncMu.Unlock()

	l.mu.Lock()
	if l.err != nil {
		defer l.mu.Unlock()
		return l.err
	}
	data, last := l.pend, l.last
	l.pend, l.pending = l.spare[:0], 0
	l.mu.Unlock()

	if len(data) > 0 {
		if _, err := l.f.Write(data); err != nil {
			return l.fail("write", err)
		}
		if err := l.f.Sync(); err != nil {
			return l.fail("fsync", err)
		}
		l.durable = last
	}
	if cap(data) <= maxSpare {
		l.spare = data[:0]
	} else {
		l.spare = nil // do not hold on to a buffer grown by a burst
	}
	return l.checkpoint(forceCheckpoint)
}

// maxSpare caps the buffer kept for reuse between flushes.
const maxSpare = 4 << 20

// fail records a sticky I/O error. Entries that were swapped out but not
// written are lost from this process, so the ledger refuses further appends.
func (l *Ledger) fail(op string, err error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.err = fmt.Errorf("ledger: %s failed: %w", op, err)
	return l.err
}

// checkpoint records the durable head. Caller holds syncMu.
func (l *Ledger) checkpoint(force bool) error {
	d := l.durable
	if (l.cp == nil && l.opt.CheckpointMirror == nil) || d == nil || d.Seq == l.cpSeq {
		return nil
	}
	if !force && d.Seq-l.cpSeq < l.opt.CheckpointRecords && time.Since(l.cpTime) < l.opt.CheckpointInterval {
		return nil
	}
	b, err := json.Marshal(Checkpoint{Seq: d.Seq, Hash: d.Hash, Sig: d.Sig, Time: time.Now().UTC()})
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if l.cp != nil {
		if _, err := l.cp.Write(b); err != nil {
			return fmt.Errorf("ledger: checkpoint write failed: %w", err)
		}
		if err := l.cp.Sync(); err != nil {
			return fmt.Errorf("ledger: checkpoint fsync failed: %w", err)
		}
	}
	if l.opt.CheckpointMirror != nil {
		l.opt.CheckpointMirror.Write(b) // best effort: the file copy is authoritative
	}
	l.cpSeq, l.cpTime = d.Seq, time.Now()
	return nil
}

func (l *Ledger) loop() {
	defer close(l.done)
	t := time.NewTicker(l.opt.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
		case <-l.kick:
		}
		l.flush(false) // errors are sticky and surface on the next Append
	}
}

// Last returns the most recent entry, if any.
func (l *Ledger) Last() (Entry, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		return Entry{}, false
	}
	return *l.last, true
}

// TornBytes reports how many bytes of an incomplete final line Open removed.
func (l *Ledger) TornBytes() int64 { return l.torn }

// Close flushes, writes a final checkpoint, and closes the log.
func (l *Ledger) Close() error {
	l.mu.Lock()
	if l.closing {
		l.mu.Unlock()
		return ErrClosed
	}
	l.closing = true
	l.mu.Unlock()

	close(l.stop)
	<-l.done
	return errors.Join(l.flush(true), l.closeFiles())
}

func (l *Ledger) closeFiles() error {
	err := l.f.Close()
	if l.cp != nil {
		err = errors.Join(err, l.cp.Close())
	}
	return err
}
