package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bkodzo/blackbox/internal/ledger"
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
	noCPs := []string{"--log", logPath, "--checkpoints", filepath.Join(t.TempDir(), "none"), "--pub", pubPath}
	if code := runVerify(noCPs); code != exitWarnings {
		t.Fatalf("no checkpoints: exit %d", code)
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
