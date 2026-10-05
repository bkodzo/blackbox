package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	dir, log, cps string
	pub           ed25519.PublicKey
	priv          ed25519.PrivateKey
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{dir, filepath.Join(dir, "log.jsonl"), filepath.Join(dir, "cp.jsonl"), pub, priv}
}

func (f *fixture) open(t testing.TB, opt Options) *Ledger {
	t.Helper()
	opt.CheckpointPath = f.cps
	l, err := Open(f.log, f.priv, opt)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// write appends n records and closes the ledger (which writes a checkpoint).
func (f *fixture) write(t testing.TB, n int) {
	t.Helper()
	l := f.open(t, Options{})
	for i := range n {
		if _, _, err := l.Append(fmt.Appendf(nil, `{"type":"test","i":%d}`, i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) verify(t testing.TB) (Result, error) {
	t.Helper()
	cps, _, err := ReadCheckpoints(f.cps)
	if err != nil {
		t.Fatal(err)
	}
	r, err := os.Open(f.log)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	return Verify(r, f.pub, cps, nil)
}

func (f *fixture) lines(t testing.TB) []string {
	t.Helper()
	b, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	return strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
}

func (f *fixture) setLines(t testing.TB, lines []string) {
	t.Helper()
	s := strings.Join(lines, "")
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	if err := os.WriteFile(f.log, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func wantTampered(t *testing.T, err error, seq uint64, reason string) {
	t.Helper()
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("want VerifyError, got %v", err)
	}
	if ve.Seq != seq || !strings.Contains(ve.Reason, reason) {
		t.Fatalf("want seq %d %q, got seq %d %q", seq, reason, ve.Seq, ve.Reason)
	}
}

func TestIntactLogVerifies(t *testing.T) {
	f := newFixture(t)
	f.write(t, 10)
	res, err := f.verify(t)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 10 || res.Checkpoints != 1 || res.TornBytes != 0 || res.Unterminated || res.LogID == "" {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestReopenContinuesChain(t *testing.T) {
	f := newFixture(t)
	f.write(t, 3)
	f.write(t, 4)
	res, err := f.verify(t)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 7 || res.Checkpoints != 2 {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestDetectsEditedRecord(t *testing.T) {
	f := newFixture(t)
	f.write(t, 5)
	lines := f.lines(t)
	lines[2] = strings.Replace(lines[2], `"i":2`, `"i":9`, 1)
	f.setLines(t, lines)
	_, err := f.verify(t)
	wantTampered(t, err, 3, "contents were modified")
}

func TestDetectsDeletedRecord(t *testing.T) {
	f := newFixture(t)
	f.write(t, 5)
	lines := f.lines(t)
	f.setLines(t, append(lines[:2:2], lines[3:]...))
	_, err := f.verify(t)
	wantTampered(t, err, 3, "removed, inserted or reordered")
}

func TestDetectsReorderedRecords(t *testing.T) {
	f := newFixture(t)
	f.write(t, 5)
	lines := f.lines(t)
	lines[1], lines[2] = lines[2], lines[1]
	f.setLines(t, lines)
	_, err := f.verify(t)
	wantTampered(t, err, 2, "removed, inserted or reordered")
}

func TestDetectsTruncatedTail(t *testing.T) {
	f := newFixture(t)
	f.write(t, 5)
	f.setLines(t, f.lines(t)[:3])
	_, err := f.verify(t)
	wantTampered(t, err, 0, "2 entries were removed from the end")
}

// Lines that decode to the same entry but are not the exact bytes blackbox
// writes must be rejected: other JSON parsers may read them differently.
func TestRejectsNonCanonicalLines(t *testing.T) {
	cases := map[string]func(line string) string{
		"duplicate rec key": func(l string) string {
			i := strings.Index(l, `"rec":`)
			return l[:i] + `"rec":{"type":"forged"},"REC":` + l[i+len(`"rec":`):]
		},
		"extra field":      func(l string) string { return strings.Replace(l, `{"v":2,`, `{"v":2,"note":"x",`, 1) },
		"added whitespace": func(l string) string { return strings.Replace(l, `"seq":2`, `"seq": 2`, 1) },
		"escaped key": func(l string) string {
			backslash := string(rune(92))
			return strings.Replace(l, `"seq":`, `"`+backslash+`u0073eq":`, 1)
		},
		"uppercase hex": func(l string) string {
			i := strings.Index(l, `"prev":"`) + len(`"prev":"`)
			return l[:i] + strings.ToUpper(l[i:i+64]) + l[i+64:]
		},
		"escaped newline in base64": func(l string) string { return strings.Replace(l, `"sig":"`, `"sig":"\n`, 1) },
		"record is an array":        func(l string) string { return l[:strings.Index(l, `"rec":`)] + `"rec":[1]}` },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.write(t, 3)
			lines := f.lines(t)
			lines[1] = mutate(strings.TrimSuffix(lines[1], "\n")) + "\n"
			f.setLines(t, lines)
			if _, err := f.verify(t); err == nil {
				t.Fatal("verify accepted a modified line")
			}
		})
	}
}

// An attacker who edits a record and rebuilds the whole chain with their own
// key produces a log that links and hashes correctly but fails signatures.
func TestDetectsChainRebuiltWithoutKey(t *testing.T) {
	f := newFixture(t)
	f.write(t, 5)
	_, evil, _ := ed25519.GenerateKey(rand.Reader)

	prev := make([]byte, 32)
	var out []string
	for i, line := range f.lines(t) {
		e, err := ParseEntry([]byte(strings.TrimSuffix(line, "\n")))
		if err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			e.Rec = json.RawMessage(`{"type":"test","i":999}`)
		}
		sum := entryHash(e.Seq, e.Kid, prev, e.Rec)
		e.Prev, e.Hash = hex.EncodeToString(prev), hex.EncodeToString(sum[:])
		e.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(evil, entrySigMessage(sum[:])))
		out = append(out, string(e.appendLine(nil)))
		prev = sum[:]
	}
	f.setLines(t, out)
	os.Remove(f.cps) // the attacker also deletes local checkpoints
	_, err := f.verify(t)
	wantTampered(t, err, 1, "signature is invalid")
}

func TestOpenRefusesLogShorterThanCheckpoint(t *testing.T) {
	f := newFixture(t)
	f.write(t, 5)
	f.setLines(t, f.lines(t)[:2])
	_, err := Open(f.log, f.priv, Options{CheckpointPath: f.cps})
	if err == nil || !strings.Contains(err.Error(), "entries were removed") {
		t.Fatalf("Open on a truncated log: %v", err)
	}
}

// The attack the review found: truncate the log, delete the local
// checkpoints, and let the gateway write new entries up to the old length.
// Checkpoints shipped off the host still hold the original seq 5, so the
// combined set disagrees about seq 5.
func TestDetectsRewriteAfterCheckpoint(t *testing.T) {
	f := newFixture(t)
	f.write(t, 5)
	shipped, _ := os.ReadFile(f.cps)

	f.setLines(t, f.lines(t)[:2])
	os.Remove(f.cps)
	f.write(t, 3)
	local, _ := os.ReadFile(f.cps)
	os.WriteFile(f.cps, append(shipped, local...), 0o600)

	_, err := f.verify(t)
	wantTampered(t, err, 0, "disagree about entry 5")
}

func TestDetectsTamperedCheckpointFields(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"seq":  func(s string) string { return strings.Replace(s, `"seq":3`, `"seq":999`, 1) },
		"time": func(s string) string { return strings.Replace(s, `"ts":"20`, `"ts":"19`, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.write(t, 3)
			b, _ := os.ReadFile(f.cps)
			os.WriteFile(f.cps, []byte(mutate(string(b))), 0o600)
			_, err := f.verify(t)
			wantTampered(t, err, 0, "invalid signature")
		})
	}
}

func TestDetectsCheckpointFromAnotherLog(t *testing.T) {
	a := newFixture(t)
	a.write(t, 3)
	b := newFixture(t)
	b.priv, b.pub = a.priv, a.pub // same gateway key, different log
	l := b.open(t, Options{})
	for i := range 3 {
		l.Append(fmt.Appendf(nil, `{"type":"other","i":%d}`, i))
	}
	l.Close()
	other, _ := os.ReadFile(b.cps)
	os.WriteFile(a.cps, other, 0o600)
	if _, err := a.verify(t); err == nil {
		t.Fatal("accepted a checkpoint from another log")
	}
}

func TestQuarantinesIncompleteLine(t *testing.T) {
	f := newFixture(t)
	f.write(t, 3)
	fh, _ := os.OpenFile(f.log, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString(`{"v":2,"seq":4,"kid":"ab`) // crash mid-write
	fh.Close()

	if res, err := f.verify(t); err != nil || res.TornBytes == 0 {
		t.Fatalf("verify before recovery: res %+v err %v", res, err)
	}
	l := f.open(t, Options{})
	rec := l.Recovery()
	if rec.QuarantinedBytes == 0 || rec.QuarantineFile == "" || rec.QuarantineSHA256 == "" {
		t.Fatalf("recovery %+v", rec)
	}
	if saved, _ := os.ReadFile(rec.QuarantineFile); string(saved) != `{"v":2,"seq":4,"kid":"ab` {
		t.Fatalf("quarantine file holds %q", saved)
	}
	l.Append([]byte(`{"type":"test"}`))
	l.Close()
	if res, err := f.verify(t); err != nil || res.Entries != 4 || res.TornBytes != 0 {
		t.Fatalf("after recovery: res %+v err %v", res, err)
	}
}

func TestKeepsValidEntryMissingNewline(t *testing.T) {
	f := newFixture(t)
	f.write(t, 3)
	b, _ := os.ReadFile(f.log)
	os.WriteFile(f.log, bytes.TrimSuffix(b, []byte("\n")), 0o600)

	res, err := f.verify(t)
	if err != nil || res.Entries != 3 || !res.Unterminated {
		t.Fatalf("verify: res %+v err %v", res, err)
	}
	l := f.open(t, Options{})
	if l.Recovery().RepairedSeq != 3 || l.Recovery().QuarantinedBytes != 0 {
		t.Fatalf("recovery %+v", l.Recovery())
	}
	l.Close()
	if res, err := f.verify(t); err != nil || res.Entries != 3 || res.Unterminated {
		t.Fatalf("after repair: res %+v err %v", res, err)
	}
}

func TestOpenRejectsForeignKey(t *testing.T) {
	f := newFixture(t)
	f.write(t, 2)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Open(f.log, other, Options{}); err == nil {
		t.Fatal("opened a log signed by a different key")
	}
}

func TestAppendRejectsBadRecords(t *testing.T) {
	f := newFixture(t)
	l := f.open(t, Options{})
	defer l.Close()
	for _, rec := range []string{"{\n}", "[1]", ""} {
		if _, _, err := l.Append([]byte(rec)); err == nil {
			t.Fatalf("accepted record %q", rec)
		}
	}
}

func TestOffsetsPointAtEntries(t *testing.T) {
	f := newFixture(t)
	l := f.open(t, Options{})
	var offs []int64
	for i := range 3 {
		_, off, err := l.Append(fmt.Appendf(nil, `{"i":%d}`, i))
		if err != nil {
			t.Fatal(err)
		}
		offs = append(offs, off)
	}
	l.Close()
	b, _ := os.ReadFile(f.log)
	for i, off := range offs {
		if !bytes.HasPrefix(b[off:], fmt.Appendf(nil, `{"v":2,"seq":%d,`, i+1)) {
			t.Fatalf("offset %d does not point at seq %d", off, i+1)
		}
	}
}

func TestConcurrentAppendsWithBackPressure(t *testing.T) {
	f := newFixture(t)
	l := f.open(t, Options{MaxPending: 4 << 10}) // small buffer forces Append to wait
	done := make(chan struct{})
	for g := range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := range 100 {
				if _, _, err := l.Append(fmt.Appendf(nil, `{"g":%d,"i":%d}`, g, i)); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	for range 8 {
		<-done
	}
	l.Close()
	if res, err := f.verify(t); err != nil || res.Entries != 800 {
		t.Fatalf("res %+v err %v", res, err)
	}
}

func TestWriteFailureIsSticky(t *testing.T) {
	f := newFixture(t)
	failures := make(chan error, 1)
	l := f.open(t, Options{FlushInterval: 1 << 40, OnFailure: func(err error) { failures <- err }}) // no background flushes
	l.Append([]byte(`{"i":1}`))
	l.f.Close() // make the next write fail
	if err := l.flush(false); err == nil {
		t.Fatal("flush succeeded on a closed file")
	}
	select {
	case <-failures:
	case <-time.After(5 * time.Second):
		t.Fatal("OnFailure was not called")
	}
	if l.Err() == nil {
		t.Fatal("Err() is nil after a failed write")
	}
	if _, _, err := l.Append([]byte(`{"i":2}`)); err == nil {
		t.Fatal("Append succeeded after a failed write")
	}
	l.Close() // release the checkpoint file so the temp dir can be removed everywhere
}

func TestMirrorReceivesCheckpoints(t *testing.T) {
	f := newFixture(t)
	var buf bytes.Buffer
	l := f.open(t, Options{CheckpointMirror: &buf})
	l.Append([]byte(`{"i":1}`))
	l.Close()
	cps, _, err := readCheckpoints(&buf)
	if err != nil || len(cps) != 1 || cps[0].Seq != 1 {
		t.Fatalf("mirror got %q (%v)", buf.String(), err)
	}
}

func TestCheckpointFileTornLineIsTolerated(t *testing.T) {
	f := newFixture(t)
	f.write(t, 2)
	fh, _ := os.OpenFile(f.cps, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString(`{"v":2,"log":"ab`)
	fh.Close()
	if _, torn, err := ReadCheckpoints(f.cps); err != nil || torn == 0 {
		t.Fatalf("torn %d err %v", torn, err)
	}
	l := f.open(t, Options{}) // Open drops the partial checkpoint line and reports it
	if l.Recovery().CheckpointTornBytes == 0 {
		t.Fatal("the removed checkpoint bytes were not reported")
	}
	l.Append([]byte(`{"i":1}`))
	l.Close()
	if _, err := f.verify(t); err != nil {
		t.Fatal(err)
	}
}

func TestKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k"), filepath.Join(dir, "k.pub")
	want, err := GenerateKey(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKey(priv, pub); err == nil {
		t.Fatal("overwrote an existing key")
	}
	gotPriv, err := LoadPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := LoadPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !want.Equal(gotPub) || !want.Equal(gotPriv.Public()) {
		t.Fatal("loaded keys do not match generated keys")
	}
	if st, _ := os.Stat(priv); os.PathSeparator == '/' && st.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v, want 0600", st.Mode().Perm())
	}
}

var benchRec = []byte(`{"type":"llm_call","model":"test-model","usage":{"input":402,"output":38},"request_body":"` +
	strings.Repeat("x", 2048) + `"}`)

// BenchmarkAppend measures sealing and buffering one entry: hashing,
// signing, and encoding. Writing to disk is done by the background flusher.
func BenchmarkAppend(b *testing.B) {
	f := newFixture(b)
	l := f.open(b, Options{})
	defer l.Close()
	b.SetBytes(int64(len(benchRec)))
	for b.Loop() {
		l.Append(benchRec)
	}
}

// BenchmarkAppendDurable measures entries per second from 8 goroutines,
// including every write and fsync until all entries are on disk.
func BenchmarkAppendDurable(b *testing.B) {
	f := newFixture(b)
	l := f.open(b, Options{})
	b.SetBytes(int64(len(benchRec)))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.Append(benchRec)
		}
	})
	if err := l.Close(); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkAppendSyncEach measures --sync always: one fsync per entry.
func BenchmarkAppendSyncEach(b *testing.B) {
	f := newFixture(b)
	l := f.open(b, Options{Sync: true})
	defer l.Close()
	b.SetBytes(int64(len(benchRec)))
	for b.Loop() {
		l.Append(benchRec)
	}
}

func BenchmarkVerify(b *testing.B) {
	f := newFixture(b)
	l := f.open(b, Options{})
	for range 10000 {
		l.Append(benchRec)
	}
	l.Close()
	data, _ := os.ReadFile(f.log)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := Verify(bytes.NewReader(data), f.pub, nil, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func TestUppercaseHexCannotFakeARewrite(t *testing.T) {
	f := newFixture(t)
	f.write(t, 3)
	b, _ := os.ReadFile(f.cps)
	line := string(b)
	i := strings.Index(line, `"hash":"`) + len(`"hash":"`)
	upper := line[:i] + strings.ToUpper(line[i:i+64]) + line[i+64:]
	os.WriteFile(f.cps, []byte(line+upper), 0o600)
	if _, _, err := ReadCheckpoints(f.cps); err == nil {
		t.Fatal("an uppercase checkpoint hash was accepted")
	}
	if _, err := ParseEntry([]byte(strings.Replace(strings.TrimSuffix(f.lines(t)[1], "\n"), `"kid":"`, `"kid":"A`, 1))); err == nil {
		t.Fatal("a malformed key ID was accepted")
	}
}

func TestRefusedOpenLeavesTheLogUntouched(t *testing.T) {
	f := newFixture(t)
	f.write(t, 5)
	lines := f.lines(t)
	torn := strings.Join(lines[:2], "") + lines[2][:20] // cut mid-line, below the checkpoint
	os.WriteFile(f.log, []byte(torn), 0o600)
	fh, _ := os.OpenFile(f.cps, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString(`{"v":2,"log":"ab`) // and a torn checkpoint line
	fh.Close()
	cpsBefore, _ := os.ReadFile(f.cps)
	if _, err := Open(f.log, f.priv, Options{CheckpointPath: f.cps}); err == nil {
		t.Fatal("opened a log below its checkpoint")
	}
	after, _ := os.ReadFile(f.log)
	if string(after) != torn {
		t.Fatal("a refused Open changed the log")
	}
	if m, _ := filepath.Glob(f.log + ".torn-*"); len(m) != 0 {
		t.Fatalf("a refused Open created %v", m)
	}
	if cpsAfter, _ := os.ReadFile(f.cps); string(cpsAfter) != string(cpsBefore) {
		t.Fatal("a refused Open changed the checkpoint file")
	}
}

// stallWriter blocks forever, like a pipe nobody reads.
type stallWriter struct{}

func (stallWriter) Write([]byte) (int, error) { select {} }

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestStalledMirrorDoesNotBlockClose(t *testing.T) {
	f := newFixture(t)
	l := f.open(t, Options{CheckpointMirror: stallWriter{}})
	l.Append([]byte(`{"i":1}`))
	done := make(chan error, 1)
	go func() { done <- l.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked on a stalled mirror")
	}
	if l.MirrorDropped() == 0 {
		t.Fatal("dropped checkpoint lines were not counted")
	}
}

func TestBrokenMirrorIsCountedNotFatal(t *testing.T) {
	f := newFixture(t)
	l := f.open(t, Options{CheckpointMirror: brokenWriter{}})
	l.Append([]byte(`{"i":1}`))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if l.MirrorDropped() != 1 {
		t.Fatalf("dropped %d", l.MirrorDropped())
	}
	if _, err := f.verify(t); err != nil {
		t.Fatal(err)
	}
}

func TestUnterminatedCheckpointIsKept(t *testing.T) {
	f := newFixture(t)
	f.write(t, 3)
	b, _ := os.ReadFile(f.cps)
	os.WriteFile(f.cps, bytes.TrimSuffix(b, []byte("\n")), 0o600) // removing the newline must not hide it
	cps, torn, err := ReadCheckpoints(f.cps)
	if err != nil || len(cps) != 1 || torn != 0 {
		t.Fatalf("cps %d torn %d err %v", len(cps), torn, err)
	}
	f.write(t, 1) // Open ends the line, so the next checkpoint starts on its own line
	if cps, _, err := ReadCheckpoints(f.cps); err != nil || len(cps) != 2 {
		t.Fatalf("after reopening: %d checkpoints, err %v", len(cps), err)
	}
	if _, err := f.verify(t); err != nil {
		t.Fatal(err)
	}
}

func TestMissingCheckpointFileIsRecorded(t *testing.T) {
	f := newFixture(t)
	f.write(t, 2)
	os.Remove(f.cps)
	l := f.open(t, Options{})
	defer l.Close()
	if !l.Recovery().CheckpointsMissing {
		t.Fatal("a deleted checkpoint file was not reported")
	}
}

func TestFailedRepairLeavesCheckpointsUntouched(t *testing.T) {
	if os.PathSeparator != '/' || os.Getuid() == 0 {
		t.Skip("needs a read-only directory")
	}
	f := newFixture(t)
	f.write(t, 3)
	fh, _ := os.OpenFile(f.log, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString(`{"v":2,"seq":4,"kid":"ab`) // a torn log line needs a quarantine file
	fh.Close()
	fh, _ = os.OpenFile(f.cps, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString(`{"v":2,"log":"ab`) // and a torn checkpoint line
	fh.Close()
	before, _ := os.ReadFile(f.cps)

	os.Chmod(f.dir, 0o500) // the quarantine file cannot be created
	defer os.Chmod(f.dir, 0o700)
	if _, err := Open(f.log, f.priv, Options{CheckpointPath: f.cps}); err == nil {
		t.Fatal("Open succeeded although the repair could not be saved")
	}
	if after, _ := os.ReadFile(f.cps); string(after) != string(before) {
		t.Fatal("a failed repair changed the checkpoint file")
	}
}
