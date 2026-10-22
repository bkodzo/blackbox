package dashboard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestExportIsSelfContained(t *testing.T) {
	checkExport(t, newFixture(t), 5+2+6+1, "The log is intact")
}

func TestExportOfALogWithAGap(t *testing.T) {
	// Entry 2 is missing, so entry 3 has no previous page to link to.
	f := newFixture(t)
	b, _ := os.ReadFile(f.logPath)
	lines := strings.SplitAfter(string(b), "\n")
	os.WriteFile(f.logPath, []byte(lines[0]+lines[2]), 0o600)
	srv, err := New(Config{Log: f.logPath, Checkpoints: f.cpPath, Pub: f.pub})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = srv
	checkExport(t, f, 5+4+1, "The log was tampered with")
}

func checkExport(t *testing.T, f *fixture, files int, verdict string) {
	t.Helper()
	dir := t.TempDir()
	n, err := f.srv.Export(dir, "Scripted <b>sample</b>.")
	if err != nil {
		t.Fatal(err)
	}
	if n != files {
		t.Fatalf("wrote %d files", n)
	}
	link := regexp.MustCompile(`(?:href|src|action)="([^"]*)"`)
	pages, _ := filepath.Glob(filepath.Join(dir, "*.html"))
	for _, p := range pages {
		b, _ := os.ReadFile(p)
		page := string(b)
		for _, raw := range []string{"<script", "<form", "<img src=x"} {
			if strings.Contains(page, raw) {
				t.Fatalf("%s contains %q", filepath.Base(p), raw)
			}
		}
		if !strings.Contains(page, "Content-Security-Policy") || !strings.Contains(page, "A static snapshot of") || !strings.Contains(page, "Scripted &lt;b&gt;sample&lt;/b&gt;.") {
			t.Fatalf("%s lacks the snapshot policy or notice", filepath.Base(p))
		}
		for _, m := range link.FindAllStringSubmatch(page, -1) {
			target := m[1]
			if strings.HasPrefix(target, "/") || strings.Contains(target, "?") || strings.Contains(target, "://") {
				t.Fatalf("%s links to %q, which a static host cannot serve", filepath.Base(p), target)
			}
			if _, err := os.Stat(filepath.Join(dir, target)); err != nil {
				t.Fatalf("%s links to %q, which was not exported", filepath.Base(p), target)
			}
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "integrity.html")); !strings.Contains(string(b), verdict) {
		t.Fatal("the export does not carry the integrity result")
	}
}
