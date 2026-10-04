// Package ledger is an append-only, tamper-evident log.
//
// Each line is an entry that seals one record:
//
//	{"v":2,"seq":42,"kid":"<key id>","prev":"<hex>","hash":"<hex>","sig":"<base64>","rec":{...}}
//
// The hash covers the sequence number, key ID, previous hash, and the record
// bytes exactly as written; the signature covers the hash. Both are
// domain-separated. Chaining catches edits, deletions, and reordering;
// signatures stop anyone without the key from rebuilding the chain; signed
// checkpoints kept elsewhere catch entries cut from the end. Every entry and
// checkpoint has exactly one valid encoding, so other JSON parsers cannot be
// shown different content than the verifier checked.
package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Options tune durability, memory, and checkpointing. Zero values pick defaults.
type Options struct {
	// Sync makes every Append durable before it returns. Otherwise appends are
	// group-committed: flushed every FlushInterval or FlushRecords appends.
	Sync          bool
	FlushInterval time.Duration // default 50ms
	FlushRecords  int           // default 64
	// MaxPending bounds encoded entries waiting to be written. Append blocks
	// once it is reached, so a slow disk slows the gateway down instead of
	// growing memory without limit.
	MaxPending int // default 64 MiB

	// CheckpointPath receives a signed checkpoint after durable flushes, at
	// most every CheckpointRecords records or CheckpointInterval.
	CheckpointPath     string
	CheckpointRecords  uint64        // default 1000
	CheckpointInterval time.Duration // default 5m
	// CheckpointMirror, if set, also receives every checkpoint line, so a copy
	// can live outside this machine. It is written from its own goroutine and
	// never blocks the ledger; lines are dropped (and counted) if it falls behind.
	CheckpointMirror io.Writer
}

func (o *Options) setDefaults() {
	if o.FlushInterval <= 0 {
		o.FlushInterval = 50 * time.Millisecond
	}
	if o.FlushRecords <= 0 {
		o.FlushRecords = 64
	}
	if o.MaxPending <= 0 {
		o.MaxPending = 64 << 20
	}
	if o.CheckpointRecords == 0 {
		o.CheckpointRecords = 1000
	}
	if o.CheckpointInterval <= 0 {
		o.CheckpointInterval = 5 * time.Minute
	}
}

// Recovery describes what Open found after the last complete line.
type Recovery struct {
	// RepairedSeq is set when the final entry was complete and validly signed
	// but missing its newline; the newline was added and the entry kept.
	RepairedSeq uint64
	// QuarantinedBytes are bytes of an incomplete final line (an interrupted
	// write). They are moved to QuarantineFile, never discarded.
	QuarantinedBytes int64
	QuarantineFile   string
	QuarantineSHA256 string
}

// Ledger appends entries to a log file. It is safe for concurrent use.
//
// Appends only touch an in-memory buffer under mu. A background flusher swaps
// that buffer out under mu, then writes and fsyncs without holding it, so
// appenders never wait on the disk unless Options.Sync is set or the buffer
// is full. (On some systems a write blocks while an fsync of the same file is
// in progress, so even the write must happen outside mu.)
type Ledger struct {
	opt Options
	key ed25519.PrivateKey
	kid string
	f   *os.File
	rec Recovery

	mu      sync.Mutex // guards the fields below
	drained *sync.Cond // signalled when pend is swapped out or the ledger fails
	pend    []byte     // encoded entries not yet written to the file
	size    int64      // bytes in the file, including pending ones
	seq     uint64
	head    []byte
	logID   string // hash of entry 1
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

	mirror        chan []byte
	mirrorDone    chan struct{}
	mirrorDropped atomic.Uint64

	kick chan struct{}
	stop chan struct{}
	done chan struct{}
}

// mirrorCloseTimeout bounds how long Close waits for the checkpoint mirror.
const mirrorCloseTimeout = 2 * time.Second

// ErrClosed is returned by Append after Close.
var ErrClosed = errors.New("ledger: closed")

// Open opens or creates the log at path and resumes its chain.
//
// If the file ends without a newline, the trailing bytes are kept if they are
// the next validly signed entry, and otherwise moved to a quarantine file.
// Open refuses a log that is shorter than, or disagrees with, its own latest
// checkpoint: that means entries were removed and the chain must not be
// extended over the gap.
func Open(path string, key ed25519.PrivateKey, opt Options) (*Ledger, error) {
	opt.setDefaults()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	pub := key.Public().(ed25519.PublicKey)
	l := &Ledger{opt: opt, key: key, kid: KeyID(pub), f: f, head: make([]byte, sha256.Size), cpTime: time.Now()}
	l.drained = sync.NewCond(&l.mu)

	// Work out the log's state and any repair it needs, check it against the
	// checkpoints, and only then change the file. A log that will be refused
	// is left exactly as it was found.
	fix, err := l.inspect(pub)
	if err != nil {
		f.Close()
		return nil, err
	}
	if err := l.openCheckpoints(pub); err != nil {
		l.closeFiles()
		return nil, err
	}
	if err := l.repair(path, fix); err != nil {
		l.closeFiles()
		return nil, err
	}

	if opt.CheckpointMirror != nil {
		l.mirror, l.mirrorDone = make(chan []byte, 64), make(chan struct{})
		go l.mirrorLoop(opt.CheckpointMirror)
	}
	l.kick = make(chan struct{}, 1)
	l.stop, l.done = make(chan struct{}), make(chan struct{})
	go l.loop()
	return l, nil
}

// tailFix is what Open must do about bytes after the last newline.
type tailFix struct {
	tail     []byte // bytes after the last newline
	end      int64  // offset of the first of them
	complete bool   // tail is the next validly signed entry, missing only its newline
}

// inspect reads the end of the log without changing it and restores the
// chain state as it will be after repair.
func (l *Ledger) inspect(pub ed25519.PublicKey) (tailFix, error) {
	line, end, size, err := readTail(l.f)
	if err != nil {
		return tailFix{}, err
	}
	if line != nil {
		e, err := ParseEntry(line)
		if err != nil {
			return tailFix{}, fmt.Errorf("ledger: last entry is malformed (%v); run `blackbox verify`", err)
		}
		head, reason := e.check(pub, l.kid)
		if reason != "" {
			return tailFix{}, fmt.Errorf("ledger: last entry (seq %d) %s; run `blackbox verify`", e.Seq, reason)
		}
		l.seq, l.head, l.last, l.durable = e.Seq, head, &e, &e
	}

	var fix tailFix
	if end < size {
		fix.tail, fix.end = make([]byte, size-end), end
		if _, err := l.f.ReadAt(fix.tail, end); err != nil {
			return tailFix{}, err
		}
		if e, head, ok := l.continues(fix.tail, pub); ok {
			fix.complete = true
			l.seq, l.head, l.last, l.durable = e.Seq, head, &e, &e
		}
	}

	switch {
	case l.seq == 1:
		l.logID = hex.EncodeToString(l.head)
	case l.seq > 1:
		first, err := readFirstLine(l.f)
		if err != nil {
			return tailFix{}, err
		}
		e, err := ParseEntry(first)
		if err != nil {
			return tailFix{}, fmt.Errorf("ledger: first entry is malformed (%v); run `blackbox verify`", err)
		}
		if _, reason := e.check(pub, l.kid); reason != "" || e.Seq != 1 {
			return tailFix{}, fmt.Errorf("ledger: first entry is invalid; run `blackbox verify`")
		}
		l.logID = e.Hash
	}
	return fix, nil
}

// repair applies fix: it adds the missing newline to a complete final entry,
// or moves an incomplete one to a quarantine file.
func (l *Ledger) repair(path string, fix tailFix) error {
	switch {
	case fix.tail == nil:
	case fix.complete:
		if _, err := l.f.Write([]byte{'\n'}); err != nil {
			return err
		}
		l.rec.RepairedSeq = l.seq
	default:
		if err := l.quarantine(path, fix.tail, fix.end); err != nil {
			return err
		}
	}
	if fix.tail != nil {
		if err := l.f.Sync(); err != nil {
			return err
		}
	}
	var err error
	l.size, err = l.f.Seek(0, io.SeekEnd)
	return err
}

// mirrorLoop copies checkpoint lines to w. After a write error (a closed pipe,
// for example) it stops writing and counts the remaining lines as dropped.
func (l *Ledger) mirrorLoop(w io.Writer) {
	defer close(l.mirrorDone)
	broken := false
	for b := range l.mirror {
		if broken {
			l.mirrorDropped.Add(1)
			continue
		}
		if _, err := w.Write(b); err != nil {
			broken = true
			l.mirrorDropped.Add(1)
		}
	}
}

// continues reports whether tail is the complete, validly signed next entry.
func (l *Ledger) continues(tail []byte, pub ed25519.PublicKey) (Entry, []byte, bool) {
	e, err := ParseEntry(tail)
	if err != nil || e.Seq != l.seq+1 || e.Prev != hex.EncodeToString(l.head) {
		return Entry{}, nil, false
	}
	head, reason := e.check(pub, l.kid)
	return e, head, reason == ""
}

// quarantine moves an incomplete final line into a side file, then removes it
// from the log so the chain can continue. Nothing is discarded.
func (l *Ledger) quarantine(path string, tail []byte, end int64) error {
	sum := sha256.Sum256(tail)
	name := fmt.Sprintf("%s.torn-%d", path, time.Now().UnixNano())
	q, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("ledger: saving incomplete final line: %w", err)
	}
	_, werr := q.Write(tail)
	serr := q.Sync()
	if err := errors.Join(werr, serr, q.Close()); err != nil {
		return fmt.Errorf("ledger: saving incomplete final line: %w", err)
	}
	// Truncate by path: on Windows an append-only handle cannot truncate.
	if err := os.Truncate(path, end); err != nil {
		return err
	}
	l.rec.QuarantinedBytes = int64(len(tail))
	l.rec.QuarantineFile = name
	l.rec.QuarantineSHA256 = hex.EncodeToString(sum[:])
	return nil
}

// openCheckpoints opens the checkpoint file and checks the log against it.
func (l *Ledger) openCheckpoints(pub ed25519.PublicKey) error {
	if l.opt.CheckpointPath == "" {
		return nil
	}
	var err error
	if l.cp, err = os.OpenFile(l.opt.CheckpointPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600); err != nil {
		return err
	}
	cps, torn, err := readCheckpoints(l.cp)
	if err != nil {
		return fmt.Errorf("ledger: %s: %w", l.opt.CheckpointPath, err)
	}
	if torn > 0 {
		// A checkpoint only restates a signed entry, so an interrupted
		// checkpoint write loses nothing; drop it so the file stays parseable.
		st, err := l.cp.Stat()
		if err != nil {
			return err
		}
		if err := os.Truncate(l.opt.CheckpointPath, st.Size()-torn); err != nil {
			return err
		}
	}
	for _, c := range cps {
		if err := c.verify(pub, l.kid); err != nil {
			return fmt.Errorf("ledger: %v; run `blackbox verify`", err)
		}
		if c.Seq > l.seq {
			return fmt.Errorf("ledger: the log ends at seq %d but a signed checkpoint covers seq %d; "+
				"entries were removed. Refusing to continue the chain; run `blackbox verify`", l.seq, c.Seq)
		}
		if c.Log != l.logID {
			return fmt.Errorf("ledger: checkpoint at seq %d belongs to a different log; run `blackbox verify`", c.Seq)
		}
		if c.Seq == l.seq && c.Hash != l.last.Hash {
			return fmt.Errorf("ledger: entry %d differs from its signed checkpoint; run `blackbox verify`", c.Seq)
		}
		l.cpSeq = max(l.cpSeq, c.Seq)
	}
	return nil
}

// readTail returns the last complete line of f (without its newline), the
// offset just after it, and the file size. Nothing is modified.
func readTail(f *os.File) (line []byte, end, size int64, err error) {
	st, err := f.Stat()
	if err != nil {
		return nil, 0, 0, err
	}
	size = st.Size()
	var buf []byte // holds file bytes [pos, size)
	pos := size
	end = -1
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
			return nil, 0, 0, err
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
	return line, max(end, 0), size, nil
}

func readFirstLine(f *os.File) ([]byte, error) {
	var line []byte
	buf := make([]byte, 64<<10)
	for off := int64(0); ; {
		n, err := f.ReadAt(buf, off)
		if i := bytes.IndexByte(buf[:n], '\n'); i >= 0 {
			return append(line, buf[:i]...), nil
		}
		line = append(line, buf[:n]...)
		off += int64(n)
		if err != nil {
			return nil, fmt.Errorf("ledger: reading first entry: %w", err)
		}
	}
}

// Append seals rec (a single-line JSON object) as the next entry and returns
// it with its byte offset in the file. Unless Options.Sync is set, the entry
// becomes durable at the next group commit.
func (l *Ledger) Append(rec []byte) (Entry, int64, error) {
	if len(rec) == 0 || rec[0] != '{' || bytes.IndexByte(rec, '\n') >= 0 {
		return Entry{}, 0, errors.New("ledger: record must be a single-line JSON object")
	}
	l.mu.Lock()
	for len(l.pend) >= l.opt.MaxPending && l.err == nil && !l.closing {
		l.requestFlush()
		l.drained.Wait()
	}
	if l.err != nil {
		defer l.mu.Unlock()
		return Entry{}, 0, l.err
	}
	if l.closing {
		l.mu.Unlock()
		return Entry{}, 0, ErrClosed
	}

	seq := l.seq + 1
	sum := entryHash(seq, l.kid, l.head, rec)
	e := Entry{
		V:    Version,
		Seq:  seq,
		Kid:  l.kid,
		Prev: hex.EncodeToString(l.head),
		Hash: hex.EncodeToString(sum[:]),
		Sig:  base64.StdEncoding.EncodeToString(ed25519.Sign(l.key, entrySigMessage(sum[:]))),
		Rec:  rec,
	}
	n := len(l.pend)
	l.pend = e.appendLine(l.pend)
	off := l.size
	l.size += int64(len(l.pend) - n)
	l.seq, l.head, l.last = seq, sum[:], &e
	if seq == 1 {
		l.logID = e.Hash
	}
	l.pending++
	full := l.pending >= l.opt.FlushRecords
	l.mu.Unlock()

	if l.opt.Sync {
		return e, off, l.flush(false)
	}
	if full {
		l.requestFlush()
	}
	return e, off, nil
}

func (l *Ledger) requestFlush() {
	select {
	case l.kick <- struct{}{}:
	default: // a flush is already requested
	}
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
	data, last, logID := l.pend, l.last, l.logID
	l.pend, l.pending = l.spare[:0], 0
	l.drained.Broadcast()
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
	return l.checkpoint(logID, forceCheckpoint)
}

// maxSpare caps the buffer kept for reuse between flushes.
const maxSpare = 4 << 20

// fail records a sticky I/O error. Entries that were swapped out but not
// written are lost from this process, so the ledger refuses further appends.
func (l *Ledger) fail(op string, err error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err == nil {
		l.err = fmt.Errorf("ledger: %s failed: %w", op, err)
	}
	l.drained.Broadcast()
	return l.err
}

// checkpoint records the durable head. Caller holds syncMu.
func (l *Ledger) checkpoint(logID string, force bool) error {
	d := l.durable
	if (l.cp == nil && l.mirror == nil) || d == nil || d.Seq <= l.cpSeq {
		return nil
	}
	if !force && d.Seq-l.cpSeq < l.opt.CheckpointRecords && time.Since(l.cpTime) < l.opt.CheckpointInterval {
		return nil
	}
	c, err := newCheckpoint(l.key, l.kid, logID, d, time.Now())
	if err != nil {
		return err
	}
	b := c.appendLine(nil)
	if l.cp != nil {
		if _, err := l.cp.Write(b); err != nil {
			return l.fail("checkpoint write", err)
		}
		if err := l.cp.Sync(); err != nil {
			return l.fail("checkpoint fsync", err)
		}
	}
	if l.mirror != nil {
		select {
		case l.mirror <- b:
		default:
			l.mirrorDropped.Add(1)
		}
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
		l.flush(false) // errors are sticky and surface through Append and Err
	}
}

// Sync makes every entry appended so far durable before returning.
func (l *Ledger) Sync() error { return l.flush(false) }

// Last returns the most recent entry, if any.
func (l *Ledger) Last() (Entry, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		return Entry{}, false
	}
	return *l.last, true
}

// Err returns the sticky write error, if the ledger has failed.
func (l *Ledger) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// LogID returns the hash of entry 1, or "" for an empty log.
func (l *Ledger) LogID() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.logID
}

// KeyID returns the ID of the signing key.
func (l *Ledger) KeyID() string { return l.kid }

// Recovery reports what Open did with an unterminated final line.
func (l *Ledger) Recovery() Recovery { return l.rec }

// MirrorDropped reports checkpoint lines the mirror could not keep up with.
func (l *Ledger) MirrorDropped() uint64 { return l.mirrorDropped.Load() }

// Close flushes, writes a final checkpoint, and closes the log.
func (l *Ledger) Close() error {
	l.mu.Lock()
	if l.closing {
		l.mu.Unlock()
		return ErrClosed
	}
	l.closing = true
	l.drained.Broadcast()
	l.mu.Unlock()

	close(l.stop)
	<-l.done
	err := l.flush(true)
	if l.mirror != nil {
		close(l.mirror)
		select {
		case <-l.mirrorDone:
		case <-time.After(mirrorCloseTimeout):
			// The mirror's reader has stalled. Do not let it hold up shutdown;
			// the checkpoint file has every line.
			l.mirrorDropped.Add(uint64(len(l.mirror)) + 1)
		}
	}
	return errors.Join(err, l.closeFiles())
}

func (l *Ledger) closeFiles() error {
	err := l.f.Close()
	if l.cp != nil {
		err = errors.Join(err, l.cp.Close())
	}
	return err
}
