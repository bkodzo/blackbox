package audit

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
)

// writeLog writes a clean run of one call and returns the paths and key.
func writeLog(t *testing.T) (logPath, cpPath string, pub ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(nil)
	logPath, cpPath = filepath.Join(dir, "log.jsonl"), filepath.Join(dir, "cp.jsonl")
	l, err := ledger.Open(logPath, key, ledger.Options{CheckpointPath: cpPath})
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range []any{
		record.GatewayStart{Type: record.TypeGatewayStart},
		record.LLMCall{Type: record.TypeLLMCall},
		record.GatewayStop{Type: record.TypeGatewayStop},
	} {
		b, _ := json.Marshal(rec)
		l.Append(b)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return logPath, cpPath, pub
}

func TestVerdicts(t *testing.T) {
	logPath, cpPath, pub := writeLog(t)
	rep, err := Check(logPath, cpPath, pub)
	if err != nil || rep.Verdict != Intact || rep.Calls != 1 || rep.Running || rep.Result.Entries != 3 {
		t.Fatalf("clean log: %+v, %v", rep, err)
	}

	rep, _ = Check(logPath, "", pub)
	if rep.Verdict != Warnings || !strings.Contains(strings.Join(rep.Warnings, " "), "no checkpoints") {
		t.Fatalf("without checkpoints: %+v", rep)
	}

	b, _ := os.ReadFile(logPath)
	os.WriteFile(logPath, []byte(strings.Replace(string(b), `"llm_call"`, `"llm_cal_"`, 1)), 0o600)
	rep, _ = Check(logPath, cpPath, pub)
	if rep.Verdict != Tampered || !strings.Contains(rep.Problem, "seq 2") {
		t.Fatalf("edited entry: %+v", rep)
	}

	os.WriteFile(cpPath, []byte("{not a checkpoint}\n"), 0o600)
	rep, _ = Check(logPath, cpPath, pub)
	if rep.Verdict != Tampered || !rep.CheckpointsBad {
		t.Fatalf("altered checkpoint file: %+v", rep)
	}
}

func TestMissingFilesAreErrors(t *testing.T) {
	logPath, cpPath, pub := writeLog(t)
	if _, err := Check(logPath, cpPath+".missing", pub); err == nil {
		t.Fatal("a missing checkpoint file gave a verdict")
	}
	if _, err := Check(logPath+".missing", cpPath, pub); err == nil {
		t.Fatal("a missing log gave a verdict")
	}
}
