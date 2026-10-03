package risk

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "risk.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAndLookup(t *testing.T) {
	m, err := Load(write(t, `{"run_shell":{"risk":"high","category":"execute","says":"ran a command: {cmd}"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if r := m.Lookup("run_shell"); r.Risk != High || r.Category != "execute" || r.Says == "" {
		t.Fatalf("rule %+v", r)
	}
	if r := m.Lookup("anything_else"); r.Risk != Unknown {
		t.Fatalf("unlisted tool rule %+v", r)
	}
}

func TestLoadRejectsBadLevel(t *testing.T) {
	if _, err := Load(write(t, `{"run_shell":{"risk":"severe"}}`)); err == nil {
		t.Fatal("accepted an invalid risk level")
	}
}

func TestEmptyPath(t *testing.T) {
	m, err := Load("")
	if err != nil || len(m) != 0 {
		t.Fatalf("map %v err %v", m, err)
	}
}
