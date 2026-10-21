package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bkodzo/blackbox/internal/audit"
	"github.com/bkodzo/blackbox/internal/dashboard"
	"github.com/bkodzo/blackbox/internal/ledger"
)

func TestSampleVerifiesAndTheCopyDoesNot(t *testing.T) {
	dir := t.TempDir()
	calls, err := generate(dir, 30, 1)
	if err != nil {
		t.Fatal(err)
	}
	if calls < 100 {
		t.Fatalf("only %d calls", calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "key.ed25519")); err == nil {
		t.Fatal("the signing key was left in the sample")
	}
	pub, err := ledger.LoadPublicKey(filepath.Join(dir, "key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	check := func(d string) audit.Report {
		rep, err := audit.Check(filepath.Join(d, "sample.jsonl"), filepath.Join(d, "sample.checkpoints.jsonl"), pub)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	if rep := check(dir); rep.Verdict != audit.Intact || rep.Calls != calls {
		t.Fatalf("sample: %v, %d calls", rep.Verdict, rep.Calls)
	}
	if rep := check(filepath.Join(dir, "tampered")); rep.Verdict != audit.Tampered || !strings.Contains(rep.Problem, "modified") {
		t.Fatalf("tampered copy: %v %s", rep.Verdict, rep.Problem)
	}

	// The flags are what the gateway's own checks found.
	b, _ := os.ReadFile(filepath.Join(dir, "sample.jsonl"))
	kinds := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e struct {
			Rec struct {
				Anomalies []struct{ Kind string } `json:"anomalies"`
			} `json:"rec"`
		}
		json.Unmarshal([]byte(line), &e)
		for _, a := range e.Rec.Anomalies {
			kinds[a.Kind] = true
		}
	}
	for _, k := range []string{"orphan_tool_result", "history_rewritten", "high_risk_tool", "tool_call_in_text", "system_prompt_changed"} {
		if !kinds[k] {
			t.Errorf("the sample has no %s", k)
		}
	}

	// And the dashboard exports it.
	s, err := dashboard.New(dashboard.Config{Log: filepath.Join(dir, "sample.jsonl"), Checkpoints: filepath.Join(dir, "sample.checkpoints.jsonl"), Pub: pub})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Export(t.TempDir(), "Sample."); err != nil {
		t.Fatal(err)
	}
}
