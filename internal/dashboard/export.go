package dashboard

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Export writes every page of the dashboard to dir as static files, for
// sharing a snapshot or publishing a demo. Pages link to each other by file
// name, so the directory can be opened from disk or served under any path.
// Each entry gets a page of its own, so it suits small logs. note, if not
// empty, is shown at the top of every page. It returns the number of files
// written.
func (s *Server) Export(dir, note string) (int, error) {
	<-s.startCheck()
	pages, err := parsePages(true)
	if err != nil {
		return 0, err
	}
	s.pages, s.static, s.made, s.note = pages, true, time.Now(), note
	if err := os.MkdirAll(filepath.Join(dir, "static"), 0o755); err != nil {
		return 0, err
	}
	n := 0
	write := func(name string, b []byte) error {
		n++
		return os.WriteFile(filepath.Join(dir, name), b, 0o644)
	}
	css, err := fs.ReadFile(files, "static/style.css")
	if err != nil {
		return 0, err
	}
	if err := write("static/style.css", css); err != nil {
		return n, err
	}

	targets := map[string]string{
		"index.html":     "/",
		"sessions.html":  "/sessions",
		"flags.html":     "/flags",
		"integrity.html": "/integrity",
		"report.html":    "/report?all=1",
	}
	for _, ss := range s.idx.Sessions() {
		k := url.QueryEscape(ss.Key)
		targets["session-"+fileKey(ss.Key)+".html"] = "/session?key=" + k
		targets["report-"+fileKey(ss.Key)+".html"] = "/report?key=" + k
	}
	entries, _ := s.idx.Entries(nil, 0)
	for _, e := range entries {
		targets[fmt.Sprintf("call-%d.html", e.Seq)] = fmt.Sprintf("/call/%d", e.Seq)
		targets[fmt.Sprintf("call-%d.json", e.Seq)] = fmt.Sprintf("/call/%d/raw", e.Seq)
	}
	for name, path := range targets {
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			return n, fmt.Errorf("exporting %s: status %d", path, w.Code)
		}
		if err := write(name, w.Body.Bytes()); err != nil {
			return n, err
		}
	}
	return n, nil
}
