package ledger

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

// VerifyError pinpoints where the log stops being trustworthy.
type VerifyError struct {
	Seq    uint64 // entry where the problem was found (0 if not tied to one)
	Reason string
}

func (e *VerifyError) Error() string {
	if e.Seq == 0 {
		return e.Reason
	}
	return fmt.Sprintf("seq %d: %s", e.Seq, e.Reason)
}

// Result summarizes a verification.
type Result struct {
	Entries          uint64
	Head             string // hash of the last entry
	LogID            string // hash of entry 1
	Checkpoints      int    // checkpointed entries matched against the log
	CheckpointsTotal int    // distinct checkpointed entries
	// Unterminated is set when the last entry is valid but lacks its newline.
	// The gateway adds the newline on its next start.
	Unterminated bool
	// TornBytes counts bytes of an incomplete final line (an interrupted
	// write). The gateway moves them to a quarantine file on its next start.
	TornBytes int64
}

// ReadCheckpoints loads a checkpoint file. A missing file yields none. An
// incomplete final line (an interrupted write) is ignored and its size
// returned; it carries no information that the log does not.
func ReadCheckpoints(path string) ([]Checkpoint, int64, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	return readCheckpoints(f)
}

func readCheckpoints(r io.Reader) ([]Checkpoint, int64, error) {
	var cps []Checkpoint
	br := bufio.NewReader(r)
	for n := 1; ; n++ {
		line, err := br.ReadBytes('\n')
		if err == io.EOF {
			return cps, int64(len(line)), nil
		}
		if err != nil {
			return nil, 0, err
		}
		c, err := parseCheckpoint(bytes.TrimSuffix(line, []byte{'\n'}))
		if err != nil {
			return nil, 0, &VerifyError{0, fmt.Sprintf("checkpoint line %d is not a valid checkpoint: %v", n, err)}
		}
		cps = append(cps, c)
	}
}

// verifyBatch is how many entries are read before their signatures are
// checked in parallel. Bounds memory while keeping all cores busy.
const verifyBatch = 1024

// Verify checks the whole log in one streaming pass with bounded memory:
// canonical encoding, contiguous sequence numbers, intact back-links, correct
// hashes, valid signatures by pub, and agreement with every checkpoint.
// Checkpoints that disagree with each other, belong to another log, or cover
// entries the log no longer has are reported as tampering. visit, if non-nil,
// sees each entry in order after it passes. The first problem in log order is
// reported.
func Verify(r io.Reader, pub ed25519.PublicKey, cps []Checkpoint, visit func(Entry)) (Result, error) {
	kid := KeyID(pub)
	want := make(map[uint64]Checkpoint, len(cps))
	var maxCP uint64
	for _, c := range cps {
		if err := c.verify(pub, kid); err != nil {
			return Result{}, &VerifyError{0, err.Error()}
		}
		if prev, ok := want[c.Seq]; ok && (prev.Hash != c.Hash || prev.Log != c.Log) {
			if prev.Log != c.Log {
				return Result{}, &VerifyError{0, "the checkpoints come from more than one log"}
			}
			return Result{}, &VerifyError{0, fmt.Sprintf(
				"two signed checkpoints disagree about entry %d: the log was rewritten after a checkpoint", c.Seq)}
		}
		want[c.Seq] = c
		maxCP = max(maxCP, c.Seq)
	}
	res := Result{CheckpointsTotal: len(want)}

	prev := GenesisPrev
	br := bufio.NewReaderSize(r, 1<<20)
	batch := make([]Entry, 0, verifyBatch)
	reasons := make([]string, verifyBatch)
	eof := false

	for !eof {
		// Read a batch sequentially, checking encoding, order and links (cheap).
		batch = batch[:0]
		var linkErr error
		for len(batch) < verifyBatch {
			line, err := readLine(br)
			if err != nil && err != io.EOF {
				return res, err
			}
			terminated := err == nil
			if !terminated && len(line) == 0 {
				eof = true
				break
			}
			next := res.Entries + uint64(len(batch)) + 1
			e, perr := ParseEntry(bytes.TrimSuffix(line, []byte{'\n'}))
			switch {
			case perr != nil && !terminated:
				res.TornBytes = int64(len(line))
			case perr != nil:
				linkErr = &VerifyError{next, "not a valid entry: " + perr.Error()}
			case e.Seq != next:
				linkErr = &VerifyError{next, fmt.Sprintf("found seq %d: an entry was removed, inserted or reordered", e.Seq)}
			case e.Prev != prev:
				linkErr = &VerifyError{e.Seq, "does not link to the previous entry"}
			default:
				batch = append(batch, e)
				prev = e.Hash
				res.Unterminated = !terminated
			}
			if linkErr != nil || !terminated {
				eof = true
				break
			}
		}

		// Recompute hashes and verify signatures in parallel (expensive).
		checkParallel(batch, reasons, pub, kid)

		// Report in log order: a bad signature before a broken link wins.
		for i, e := range batch {
			if reasons[i] != "" {
				return res, &VerifyError{e.Seq, reasons[i]}
			}
			if e.Seq == 1 {
				res.LogID = e.Hash
			}
			if c, ok := want[e.Seq]; ok {
				if c.Log != res.LogID {
					return res, &VerifyError{0, fmt.Sprintf("the checkpoint for entry %d belongs to a different log", e.Seq)}
				}
				if c.Hash != e.Hash {
					return res, &VerifyError{e.Seq, "differs from a signed checkpoint (log was rewritten)"}
				}
				res.Checkpoints++
			}
			if visit != nil {
				visit(e)
			}
			res.Entries, res.Head = e.Seq, e.Hash
		}
		if linkErr != nil {
			return res, linkErr
		}
	}

	if res.Entries == 0 {
		res.Head = GenesisPrev
	}
	if maxCP > res.Entries {
		return res, &VerifyError{0, fmt.Sprintf(
			"log ends at seq %d but a signed checkpoint covers seq %d: %d entries were removed from the end",
			res.Entries, maxCP, maxCP-res.Entries)}
	}
	for _, c := range cps {
		if c.Log != res.LogID {
			return res, &VerifyError{c.Seq, "a signed checkpoint belongs to a different log"}
		}
	}
	return res, nil
}

// readLine returns the next line including its newline. At EOF it returns any
// trailing bytes without a newline together with io.EOF.
func readLine(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		// Rare: a line larger than the buffer. Copy it out before reading on.
		head := append([]byte(nil), line...)
		rest, rerr := br.ReadBytes('\n')
		return append(head, rest...), rerr
	}
	return line, err
}

func checkParallel(batch []Entry, reasons []string, pub ed25519.PublicKey, kid string) {
	workers := min(runtime.GOMAXPROCS(0), len(batch))
	if workers == 0 {
		return
	}
	per := (len(batch) + workers - 1) / workers
	var wg sync.WaitGroup
	for lo := 0; lo < len(batch); lo += per {
		hi := min(lo+per, len(batch))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				_, reasons[i] = batch[i].check(pub, kid)
			}
		}()
	}
	wg.Wait()
}

// Scan calls fn for each complete, well-formed entry in r, in order, without
// checking hashes or signatures. Use Verify when the result must be trusted.
func Scan(r io.Reader, fn func(Entry) error) error {
	br := bufio.NewReaderSize(r, 1<<20)
	var last uint64
	for {
		line, err := readLine(br)
		if err == io.EOF {
			return nil // a trailing partial line is not an entry
		}
		if err != nil {
			return err
		}
		e, err := ParseEntry(bytes.TrimSuffix(line, []byte{'\n'}))
		if err != nil {
			return fmt.Errorf("malformed entry after seq %d: %w", last, err)
		}
		if err := fn(e); err != nil {
			return err
		}
		last = e.Seq
	}
}
