package dashboard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestExportIsSelfContained(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	n, err := f.srv.Export(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 5 pages, a session page and report, 3 entries with their raw files,
	// and the stylesheet.
	if n != 5+2+6+1 {
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
		if !strings.Contains(page, "Content-Security-Policy") || !strings.Contains(page, "A static snapshot of") {
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
	if b, _ := os.ReadFile(filepath.Join(dir, "integrity.html")); !strings.Contains(string(b), "The log is intact") {
		t.Fatal("the export does not carry the integrity result")
	}
}
