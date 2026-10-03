package ledger

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

// Result summarizes a successful verification.
type Result struct {
	Entries     uint64
	Head        string // hash of the last entry
	Checkpoints int    // checkpoints matched against the log
	TornTail    bool   // log ends in an incomplete line (crash mid-write)
}

// ReadCheckpoints loads a checkpoint file. A missing file yields none.
func ReadCheckpoints(path string) ([]Checkpoint, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cps []Checkpoint
	dec := json.NewDecoder(f)
	for {
		var c Checkpoint
		if err := dec.Decode(&c); err == io.EOF {
			return cps, nil
		} else if err != nil {
			return nil, fmt.Errorf("checkpoints: %w", err)
		}
		cps = append(cps, c)
	}
}

// verifyBatch is how many entries are read before their signatures are
// checked in parallel. Bounds memory while keeping all cores busy.
const verifyBatch = 1024

// Verify checks the whole log in one streaming pass with bounded memory:
// contiguous sequence numbers, intact back-links, correct hashes, valid
// signatures, and agreement with every checkpoint (which also catches entries
// removed from the end). visit, if non-nil, sees each entry in order after it
// passes. The first problem in log order is reported.
func Verify(r io.Reader, pub ed25519.PublicKey, cps []Checkpoint, visit func(Entry)) (Result, error) {
	want := make(map[uint64]string, len(cps))
	var maxCP uint64
	for _, c := range cps {
		sig, err := base64.StdEncoding.DecodeString(c.Sig)
		hash, herr := hex.DecodeString(c.Hash)
		if err != nil || herr != nil || !ed25519.Verify(pub, hash, sig) {
			return Result{}, &VerifyError{c.Seq, "checkpoint has an invalid signature (forged checkpoint)"}
		}
		want[c.Seq] = c.Hash
		maxCP = max(maxCP, c.Seq)
	}

	var res Result
	prev := GenesisPrev
	br := bufio.NewReaderSize(r, 1<<20)
	batch := make([]Entry, 0, verifyBatch)
	reasons := make([]string, verifyBatch)
	eof := false

	for !eof {
		// Read a batch sequentially, checking order and links (cheap).
		batch = batch[:0]
		var linkErr error
		for len(batch) < verifyBatch {
			line, err := readLine(br)
			if err == io.EOF {
				res.TornTail = len(line) > 0
				eof = true
				break
			}
			if err != nil {
				return res, err
			}
			next := res.Entries + uint64(len(batch)) + 1
			var e Entry
			if err := json.Unmarshal(line, &e); err != nil {
				linkErr = &VerifyError{next, "line is not a valid entry: " + err.Error()}
			} else if e.Seq != next {
				linkErr = &VerifyError{next, fmt.Sprintf("found seq %d: an entry was removed, inserted or reordered", e.Seq)}
			} else if e.Prev != prev {
				linkErr = &VerifyError{e.Seq, "does not link to the previous entry"}
			}
			if linkErr != nil {
				eof = true
				break
			}
			batch = append(batch, e)
			prev = e.Hash
		}

		// Recompute hashes and verify signatures in parallel (expensive).
		checkParallel(batch, reasons, pub)

		// Report in log order: a bad signature before a broken link wins.
		for i, e := range batch {
			if reasons[i] != "" {
				return res, &VerifyError{e.Seq, reasons[i]}
			}
			if h, ok := want[e.Seq]; ok {
				if h != e.Hash {
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
	return res, nil
}

// readLine returns the next line including its newline. At EOF it returns any
// trailing bytes without a newline (a torn write) together with io.EOF.
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

func checkParallel(batch []Entry, reasons []string, pub ed25519.PublicKey) {
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
				_, reasons[i] = batch[i].check(pub)
			}
		}()
	}
	wg.Wait()
}

// Scan calls fn for each complete entry in r, in order, without verifying
// anything. Use Verify when the result must be trusted.
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
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("malformed entry after seq %d: %w", last, err)
		}
		if err := fn(e); err != nil {
			return err
		}
		last = e.Seq
	}
}
