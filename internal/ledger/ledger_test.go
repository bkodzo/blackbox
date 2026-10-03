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
	cps, err := ReadCheckpoints(f.cps)
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
	if res.Entries != 10 || res.Checkpoints != 1 || res.TornTail {
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

// An attacker who edits a record and rebuilds the whole chain with their own
// key produces a log that links and hashes correctly but fails signatures.
func TestDetectsChainRebuiltWithoutKey(t *testing.T) {
	f := newFixture(t)
	f.write(t, 5)
	_, evil, _ := ed25519.GenerateKey(rand.Reader)

	prev := make([]byte, 32)
	var out []string
	for i, line := range f.lines(t) {
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if i == 2 {
			e.Rec = json.RawMessage(`{"type":"test","i":999}`)
		}
		sum := chainHash(e.Seq, prev, e.Rec)
		e.Prev, e.Hash = hex.EncodeToString(prev), hex.EncodeToString(sum[:])
		e.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(evil, sum[:]))
		out = append(out, string(e.appendLine(nil)))
		prev = sum[:]
	}
	f.setLines(t, out)
	os.Remove(f.cps) // the attacker also deletes local checkpoints
	_, err := f.verify(t)
	wantTampered(t, err, 1, "signature is invalid")
}

func TestDetectsForgedCheckpoint(t *testing.T) {
	f := newFixture(t)
	f.write(t, 3)
	b, _ := os.ReadFile(f.cps)
	forged := strings.Replace(string(b), `"seq":3`, `"seq":2`, 1)
	os.WriteFile(f.cps, []byte(forged), 0o600)
	// seq 2's hash differs from the checkpoint's, and the signature still
	// covers seq 3, so verification must fail.
	if _, err := f.verify(t); err == nil {
		t.Fatal("forged checkpoint was accepted")
	}
}

func TestRecoversTornWrite(t *testing.T) {
	f := newFixture(t)
	f.write(t, 3)
	fh, _ := os.OpenFile(f.log, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString(`{"seq":4,"prev":"ab`) // crash mid-write
	fh.Close()

	if res, err := f.verify(t); err != nil || !res.TornTail {
		t.Fatalf("verify before recovery: res %+v err %v", res, err)
	}
	l := f.open(t, Options{})
	if l.TornBytes() == 0 {
		t.Fatal("torn bytes not reported")
	}
	if _, _, err := l.Append([]byte(`{"type":"test"}`)); err != nil {
		t.Fatal(err)
	}
	l.Close()
	res, err := f.verify(t)
	if err != nil || res.Entries != 4 || res.TornTail {
		t.Fatalf("after recovery: res %+v err %v", res, err)
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

func TestAppendRejectsMultilineRecord(t *testing.T) {
	f := newFixture(t)
	l := f.open(t, Options{})
	defer l.Close()
	if _, _, err := l.Append([]byte("{\n}")); err == nil {
		t.Fatal("accepted a multi-line record")
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
		if !bytes.HasPrefix(b[off:], fmt.Appendf(nil, `{"seq":%d,`, i+1)) {
			t.Fatalf("offset %d does not point at seq %d", off, i+1)
		}
	}
}

func TestConcurrentAppends(t *testing.T) {
	f := newFixture(t)
	l := f.open(t, Options{})
	done := make(chan struct{})
	for g := range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := range 100 {
				l.Append(fmt.Appendf(nil, `{"g":%d,"i":%d}`, g, i))
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
	if st, _ := os.Stat(priv); st.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v, want 0600", st.Mode().Perm())
	}
}

var benchRec = []byte(`{"type":"llm_call","model":"test-model","usage":{"input":402,"output":38},"request_body":"` +
	strings.Repeat("x", 2048) + `"}`)

func BenchmarkAppendGroupCommit(b *testing.B) {
	f := newFixture(b)
	l := f.open(b, Options{})
	defer l.Close()
	b.SetBytes(int64(len(benchRec)))
	for b.Loop() {
		l.Append(benchRec)
	}
}

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
