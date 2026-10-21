package dashboard

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
)

const hostile = `<script>alert(1)</script><img src=x onerror=alert(2)>`

type fixture struct {
	logPath, cpPath string
	pub             ed25519.PublicKey
	srv             *Server
}

// newFixture writes a clean run whose recorded text is hostile HTML, and
// serves a dashboard for it.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(nil)
	f := &fixture{logPath: filepath.Join(dir, "log.jsonl"), cpPath: filepath.Join(dir, "cp.jsonl"), pub: pub}
	l, err := ledger.Open(f.logPath, key, ledger.Options{CheckpointPath: f.cpPath})
	if err != nil {
		t.Fatal(err)
	}
	call := record.LLMCall{Type: record.TypeLLMCall, Agent: record.Agent{ID: hostile}, Principal: hostile,
		Session: record.Session{ID: hostile}, Anomalies: []record.Anomaly{{Kind: record.AnomalyOrphanToolResult, Detail: hostile}}}
	call.Request.Body.Text = `{"messages":[{"role":"user","content":"` + strings.ReplaceAll(hostile, `"`, `\"`) + `"}]}`
	call.Response.Body.Text = hostile
	call.Response.ToolCalls = []record.ToolCall{{Name: hostile, Arguments: hostile, Risk: `high" onmouseover="alert(3)`}}
	call.Timing.ReceivedAt = time.Now()
	for _, rec := range []any{record.GatewayStart{Type: record.TypeGatewayStart}, call, record.GatewayStop{Type: record.TypeGatewayStop}} {
		b, _ := json.Marshal(rec)
		if _, _, err := l.Append(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	f.srv, err = New(Config{Log: f.logPath, Checkpoints: f.cpPath, Pub: pub})
	if err != nil {
		t.Fatal(err)
	}
	<-f.srv.startCheck()
	return f
}

func (f *fixture) get(t *testing.T, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", "http://127.0.0.1:8090"+path, nil)
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, req)
	b, _ := io.ReadAll(w.Result().Body)
	return w.Code, string(b)
}

var pages = []string{"/", "/sessions", "/sessions?q=script", "/session?key=" + url.QueryEscape("s:"+hostile), "/flags", "/flags?kind=orphan_tool_result", "/call/1", "/call/2", "/call/3", "/integrity"}

func TestEveryPageEscapesRecordedText(t *testing.T) {
	f := newFixture(t)
	for _, p := range pages {
		code, body := f.get(t, p)
		if code != http.StatusOK {
			t.Fatalf("%s: status %d", p, code)
		}
		for _, raw := range []string{"<script>alert", "<img src=x", `" onmouseover=`} {
			if strings.Contains(body, raw) {
				t.Fatalf("%s: recorded text reached the page unescaped (%q)", p, raw)
			}
		}
	}
	// The text is shown, escaped, where it belongs.
	if _, body := f.get(t, "/call/2"); !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("the escaped text is missing from the call page")
	}
}

func TestRawDownloadIsNeverRendered(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest("GET", "http://127.0.0.1:8090/call/2/raw", nil)
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, req)
	h := w.Result().Header
	if h.Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(h.Get("Content-Disposition"), "attachment") || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("raw entry served with %v", h)
	}
	line, _ := os.ReadFile(f.logPath)
	if want := strings.SplitAfter(string(line), "\n")[1]; w.Body.String()+"\n" != want {
		t.Fatal("the raw entry is not the line as stored")
	}
}

func TestUnknownPagesAndEntries(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/nope", "/call/99", "/call/x", "/session?key=nope"} {
		if code, _ := f.get(t, p); code != http.StatusNotFound {
			t.Fatalf("%s: status %d", p, code)
		}
	}
}

func TestHostsAndOrigins(t *testing.T) {
	f := newFixture(t)
	f.srv.hosts["audit.internal"] = true
	for _, c := range []struct {
		host string
		want int
	}{
		{"127.0.0.1:8090", 200}, {"localhost:8090", 200}, {"[::1]:8090", 200}, {"LOCALHOST.", 200},
		{"audit.internal:8090", 200}, {"evil.example", 421}, {"127.0.0.1.evil.example", 421}, {"", 421},
	} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = c.host
		w := httptest.NewRecorder()
		f.srv.ServeHTTP(w, req)
		if w.Code != c.want {
			t.Errorf("Host %q: status %d, want %d", c.host, w.Code, c.want)
		}
	}
	for _, c := range []struct {
		name   string
		header map[string]string
		want   int
	}{
		{"same origin", map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusSeeOther},
		{"origin header", map[string]string{"Origin": "http://127.0.0.1:8090"}, http.StatusSeeOther},
		{"other site", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "http://127.0.0.1:8090"}, http.StatusForbidden},
		{"other origin", map[string]string{"Origin": "http://evil.example"}, http.StatusForbidden},
		{"no origin", nil, http.StatusForbidden},
	} {
		req := httptest.NewRequest("POST", "http://127.0.0.1:8090/verify", nil)
		for k, v := range c.header {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		f.srv.ServeHTTP(w, req)
		if w.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, w.Code, c.want)
		}
	}
}

func TestTamperingIsShown(t *testing.T) {
	f := newFixture(t)
	if _, body := f.get(t, "/integrity"); !strings.Contains(body, "The log is intact") || !strings.Contains(body, `class="status ok"`) {
		t.Fatal("a clean log is not shown as intact")
	}
	b, _ := os.ReadFile(f.logPath)
	os.WriteFile(f.logPath, []byte(strings.Replace(string(b), `"gateway_stop"`, `"gateway_stoP"`, 1)), 0o600)
	<-f.srv.startCheck()
	_, body := f.get(t, "/integrity")
	if !strings.Contains(body, "The log was tampered with") || !strings.Contains(body, "seq 3") || !strings.Contains(body, `class="status bad"`) {
		t.Fatal("an edited entry is not shown as tampering")
	}
	if _, body := f.get(t, "/"); !strings.Contains(body, "Log tampered") {
		t.Fatal("the header does not show the tampering on other pages")
	}
}

func TestShrinkingLogIsShown(t *testing.T) {
	f := newFixture(t)
	b, _ := os.ReadFile(f.logPath)
	os.WriteFile(f.logPath, []byte(strings.SplitAfter(string(b), "\n")[0]), 0o600)
	f.srv.idx.Refresh()
	if _, body := f.get(t, "/"); !strings.Contains(body, "entries were removed from its end") {
		t.Fatal("a log that became shorter is not reported")
	}
}

func TestTheLogIsNeverWritten(t *testing.T) {
	f := newFixture(t)
	before, _ := os.ReadFile(f.logPath)
	cps, _ := os.ReadFile(f.cpPath)
	stat, _ := os.Stat(f.logPath)
	for _, p := range append(pages, "/call/2/raw", "/status.json") {
		f.get(t, p)
	}
	req := httptest.NewRequest("POST", "http://127.0.0.1:8090/verify", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	f.srv.ServeHTTP(httptest.NewRecorder(), req)
	f.srv.idx.Refresh()
	after, _ := os.ReadFile(f.logPath)
	cpsAfter, _ := os.ReadFile(f.cpPath)
	statAfter, _ := os.Stat(f.logPath)
	if string(after) != string(before) || string(cpsAfter) != string(cps) || !statAfter.ModTime().Equal(stat.ModTime()) {
		t.Fatal("the dashboard changed the log or its checkpoints")
	}
}
