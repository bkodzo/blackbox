package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
)

// logFixture writes a small signed log with a checkpoint and returns the
// paths of the log, checkpoint file, and public key.
func logFixture(t *testing.T) (logPath, cpPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	if code := runInit([]string{"--dir", dir}); code != 0 {
		t.Fatal("init failed")
	}
	key, err := ledger.LoadPrivateKey(filepath.Join(dir, "key.ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	logPath, cpPath = filepath.Join(dir, "log.jsonl"), filepath.Join(dir, "cp.jsonl")
	l, err := ledger.Open(logPath, key, ledger.Options{CheckpointPath: cpPath})
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range []string{`{"type":"gateway_start"}`, `{"type":"llm_call"}`, `{"type":"gateway_stop"}`} {
		l.Append([]byte(rec))
	}
	l.Close()
	return logPath, cpPath, filepath.Join(dir, "key.pub")
}

func TestVerifyExitCodes(t *testing.T) {
	logPath, cpPath, pubPath := logFixture(t)
	args := func(extra ...string) []string {
		return append([]string{"--log", logPath, "--checkpoints", cpPath, "--pub", pubPath}, extra...)
	}

	if code := runVerify(args()); code != exitIntact {
		t.Fatalf("intact log: exit %d", code)
	}
	missing := []string{"--log", logPath, "--checkpoints", filepath.Join(t.TempDir(), "none"), "--pub", pubPath}
	if code := runVerify(missing); code != exitError {
		t.Fatalf("missing checkpoint file: exit %d", code)
	}
	if code := runVerify(append(missing, "--no-checkpoints")); code != exitWarnings {
		t.Fatalf("explicitly without checkpoints: exit %d", code)
	}
	if code := runVerify([]string{"--log", logPath, "--pub", "/nonexistent/key.pub"}); code != exitError {
		t.Fatalf("missing key: exit %d", code)
	}
	if code := runVerify([]string{"--pubkey", pubPath}); code != exitError {
		t.Fatalf("unknown flag: exit %d", code)
	}
	if code := runVerify([]string{"-h"}); code != exitIntact {
		t.Fatalf("help: exit %d", code)
	}

	b, _ := os.ReadFile(logPath)
	os.WriteFile(logPath, []byte(strings.Replace(string(b), "llm_call", "llm_cal1", 1)), 0o600)
	if code := runVerify(args()); code != exitTampered {
		t.Fatalf("tampered log: exit %d", code)
	}
}

func TestSafeEscapesTerminalControls(t *testing.T) {
	in := "rm\x1b[1A\x1b[2K\r" + string(rune(0x202e)) + "evil" + string(rune(0x2066))
	out := safe(in)
	for _, r := range out {
		if r < 0x20 || r == 0x7f || isDirectionControl(r) {
			t.Fatalf("control character %U survived: %q", r, out)
		}
	}
	if !strings.HasPrefix(out, "rm") || !strings.Contains(out, "evil") {
		t.Fatalf("visible text was lost: %q", out)
	}
	if got := clip("a\n\tb", 80); got != "a b" {
		t.Fatalf("clip %q", got)
	}
}

func TestCorruptCheckpointFileIsTampering(t *testing.T) {
	logPath, cpPath, pubPath := logFixture(t)
	b, _ := os.ReadFile(cpPath)
	os.WriteFile(cpPath, []byte(strings.Replace(string(b), `"v":2`, `"v":2,"x":1`, 1)), 0o600)
	if code := runVerify([]string{"--log", logPath, "--checkpoints", cpPath, "--pub", pubPath}); code != exitTampered {
		t.Fatalf("exit %d", code)
	}
}

func TestSessionsEscapesSessionIDs(t *testing.T) {
	dir := t.TempDir()
	runInit([]string{"--dir", dir})
	key, _ := ledger.LoadPrivateKey(filepath.Join(dir, "key.ed25519"))
	logPath := filepath.Join(dir, "log.jsonl")
	l, _ := ledger.Open(logPath, key, ledger.Options{})
	evil := "run" + string(rune(0x202e)) + "\x1b[2K"
	rec, _ := json.Marshal(record.LLMCall{Type: record.TypeLLMCall, Session: record.Session{ID: evil}})
	l.Append(rec)
	l.Close()

	out := captureStdout(t, func() { runSessions([]string{"--log", logPath}) })
	for _, r := range out {
		if r == 0x1b || isDirectionControl(r) {
			t.Fatalf("control character %U in sessions output: %q", r, out)
		}
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	f()
	os.Stdout = old
	w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

func TestShowPrintsReasoning(t *testing.T) {
	dir := t.TempDir()
	runInit([]string{"--dir", dir})
	key, _ := ledger.LoadPrivateKey(filepath.Join(dir, "key.ed25519"))
	logPath := filepath.Join(dir, "log.jsonl")
	l, _ := ledger.Open(logPath, key, ledger.Options{})
	c := record.LLMCall{Type: record.TypeLLMCall, Session: record.Session{ID: "s"}}
	c.Response.Reasoning = &record.Reasoning{Preview: "The admin approved it,\x1b[2K so I will delete the files.", Chars: 50}
	b, _ := json.Marshal(c)
	l.Append(b)
	l.Close()

	out := captureStdout(t, func() { runShow([]string{"--log", logPath, "s"}) })
	if !strings.Contains(out, "reasoning The admin approved it,") || strings.ContainsRune(out, 0x1b) {
		t.Fatalf("show output %q", out)
	}
}

func TestUncoveredCleanShutdownIsTampering(t *testing.T) {
	logPath, cpPath, pubPath := logFixture(t)
	// A second run, so there are two checkpoints.
	key, _ := ledger.LoadPrivateKey(filepath.Join(filepath.Dir(pubPath), "key.ed25519"))
	l, err := ledger.Open(logPath, key, ledger.Options{CheckpointPath: cpPath})
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range []string{`{"type":"gateway_start"}`, `{"type":"llm_call"}`, `{"type":"gateway_stop"}`} {
		l.Append([]byte(rec))
	}
	l.Close()
	args := []string{"--log", logPath, "--checkpoints", cpPath, "--pub", pubPath}
	if code := runVerify(args); code != exitIntact {
		t.Fatalf("intact: exit %d", code)
	}

	// Removing the newest checkpoint's newline changes nothing.
	b, _ := os.ReadFile(cpPath)
	os.WriteFile(cpPath, []byte(strings.TrimSuffix(string(b), "\n")), 0o600)
	if code := runVerify(args); code != exitIntact {
		t.Fatalf("checkpoint without its newline: exit %d", code)
	}

	// Deleting the newest checkpoint leaves a clean shutdown no checkpoint covers.
	lines := strings.SplitAfter(string(b), "\n")
	os.WriteFile(cpPath, []byte(lines[0]), 0o600)
	if code := runVerify(args); code != exitTampered {
		t.Fatalf("newest checkpoint deleted: exit %d", code)
	}
}
