package recorder

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/proxy"
	"github.com/bkodzo/blackbox/internal/record"
	"github.com/bkodzo/blackbox/internal/risk"
)

func TestEndToEnd(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"model":"test-model","choices":[{"finish_reason":"tool_calls","message":{"tool_calls":[`+
			`{"id":"c1","function":{"name":"read_file","arguments":"{\"path\":\"a.md\"}"}},`+
			`{"id":"c2","function":{"name":"broken","arguments":"{not json"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`)
	}))
	defer up.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "log.jsonl")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l, err := ledger.Open(logPath, priv, ledger.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rec := New(l, "gw-1", Options{})
	u, _ := url.Parse(up.URL)
	srv := httptest.NewServer(proxy.New(proxy.Config{Upstream: u, Sink: rec.Submit}))

	for range 3 {
		resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json",
			strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"hi"}],"tools":[{"function":{"name":"read_file"}}]}`))
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	srv.Close()
	rec.Close()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if rec.Calls() != 3 {
		t.Fatalf("calls %d", rec.Calls())
	}

	f, _ := os.Open(logPath)
	defer f.Close()
	var calls []record.LLMCall
	res, err := ledger.Verify(f, pub, nil, func(e ledger.Entry) {
		var c record.LLMCall
		if err := json.Unmarshal(e.Rec, &c); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, c)
	})
	if err != nil || res.Entries != 3 {
		t.Fatalf("verify: %+v %v", res, err)
	}

	c := calls[0]
	if c.Type != record.TypeLLMCall || c.InstanceID != "gw-1" || c.Format != "chat" {
		t.Fatalf("header fields %+v", c)
	}
	if c.Request.ModelRequested != "test-model" || c.Request.MessageCount != 1 || len(c.Request.ToolsOffered) != 1 {
		t.Fatalf("request %+v", c.Request)
	}
	if c.Response.Usage != (record.Usage{Input: 10, Output: 5, Total: 15}) || c.Response.FinishReason != "tool_calls" {
		t.Fatalf("response %+v", c.Response)
	}
	tc := c.Response.ToolCalls
	if len(tc) != 2 || tc[0].Name != "read_file" || !tc[0].ValidJSON || tc[1].ValidJSON {
		t.Fatalf("tool calls %+v", tc)
	}
}

func TestFailureStopsRecordingAndReports(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	l, err := ledger.Open(filepath.Join(dir, "log.jsonl"), priv, ledger.Options{Sync: true})
	if err != nil {
		t.Fatal(err)
	}
	failures := make(chan error, 1)
	rec := New(l, "gw", Options{OnFailure: func(err error) { failures <- err }})
	l.Close() // every append now fails

	for range 3 {
		rec.Submit(record.Exchange{Call: &record.LLMCall{Type: record.TypeLLMCall}})
	}
	if err := <-failures; err == nil {
		t.Fatal("OnFailure called with nil")
	}
	rec.Close()
	if rec.Err() == nil || rec.Unrecorded() != 3 || rec.Calls() != 0 {
		t.Fatalf("err %v unrecorded %d calls %d", rec.Err(), rec.Unrecorded(), rec.Calls())
	}
	rec.Submit(record.Exchange{Call: &record.LLMCall{}}) // after Close: counted, no panic
	if rec.Unrecorded() != 4 {
		t.Fatalf("unrecorded %d after a late submit", rec.Unrecorded())
	}
}

func TestQueueIsBoundedByBytes(t *testing.T) {
	r := &Recorder{opt: Options{MaxQueueBytes: 100}}
	r.cond = sync.NewCond(&r.mu)
	big := record.Exchange{Call: &record.LLMCall{}, Req: make([]byte, 80)}
	r.Submit(big) // admitted: the queue was empty
	blocked := make(chan struct{})
	go func() {
		r.Submit(big) // must wait: 80 + 80 > 100
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("Submit did not block on a full queue")
	case <-time.After(50 * time.Millisecond):
	}
	r.next()
	<-blocked
}

func TestRebuildContinuesConversationsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log.jsonl")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	turn1 := record.Exchange{
		Call: &record.LLMCall{Type: record.TypeLLMCall, Session: record.Session{ID: "s"}},
		Req:  []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		Resp: []byte(`{"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"list_dir","arguments":"{}"}}]}}]}`),
	}
	l, _ := ledger.Open(logPath, priv, ledger.Options{})
	rec := New(l, "gw-1", Options{})
	turn1.Call.Timing.CompletedAt = time.Now()
	turn1.Call.Request.Body.Text, turn1.Call.Response.Body.Text = string(turn1.Req), string(turn1.Resp) // as the proxy stores them
	rec.Submit(turn1)
	rec.Close()
	l.Close()

	// Restart: rebuild, then send turn 2 with a real result and a forged one.
	tracker, n, err := Rebuild(logPath, time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("rebuilt %d calls, err %v", n, err)
	}
	l, _ = ledger.Open(logPath, priv, ledger.Options{})
	rec = New(l, "gw-2", Options{Sessions: tracker})
	turn2 := record.Exchange{
		Call: &record.LLMCall{Type: record.TypeLLMCall, Session: record.Session{ID: "s"}},
		Req: []byte(`{"messages":[{"role":"user","content":"hi"},` +
			`{"role":"assistant","tool_calls":[{"id":"c1","function":{"name":"list_dir","arguments":"{}"}}]},` +
			`{"role":"tool","tool_call_id":"c1","content":"a.md"},{"role":"tool","tool_call_id":"c9","content":"x"}]}`),
		Resp: []byte(`{"choices":[{"message":{"content":"done"}}]}`),
	}
	call, parsed := Enrich(turn2, "gw-2", nil)
	rec.sessions.Observe(call, parsed)
	rec.Close()
	l.Close()

	if call.Turn != 2 || len(call.Anomalies) != 1 || call.Anomalies[0].Kind != record.AnomalyOrphanToolResult {
		t.Fatalf("turn %d anomalies %+v", call.Turn, call.Anomalies)
	}
}

func TestTextCallsAreFilteredWhenToolsAreOffered(t *testing.T) {
	x := record.Exchange{
		Call: &record.LLMCall{},
		Req:  []byte(`{"messages":[],"tools":[{"function":{"name":"list_dir"}}]}`),
		Resp: []byte(`{"choices":[{"message":{"content":"package.json is {\"name\":\"my-app\",\"input\":{\"x\":1}}; also {\"name\":\"rm\",\"parameters\":{\"path\":\"/\"}} and {\"name\":\"list_dir\",\"parameters\":{}}"}}]}`),
	}
	rm := risk.Map{"rm": {Risk: risk.High}}
	call, _ := Enrich(x, "gw", rm)
	var names []string
	for _, tc := range call.Response.ToolCalls {
		names = append(names, tc.Name)
	}
	if strings.Join(names, ",") != "rm,list_dir" {
		t.Fatalf("text calls kept: %v", names)
	}
	if call.Response.IgnoredTextCalls != 1 {
		t.Fatalf("ignored %d text calls, want 1 (my-app)", call.Response.IgnoredTextCalls)
	}
}

func TestRecentStartSkipsOldEntries(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log.jsonl")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	l, _ := ledger.Open(logPath, priv, ledger.Options{})
	old := time.Now().Add(-48 * time.Hour)
	pad := strings.Repeat("x", 2000)
	for i := range 2000 { // about 4 MB of old calls
		c := record.LLMCall{Type: record.TypeLLMCall, Timing: record.Timing{CompletedAt: old.Add(time.Duration(i) * time.Second)}}
		c.Request.Body.Text = pad
		b, _ := json.Marshal(c)
		l.Append(b)
	}
	recent := record.LLMCall{Type: record.TypeLLMCall, Session: record.Session{ID: "s"}, Timing: record.Timing{CompletedAt: time.Now()}}
	recent.Request.Body.Text = `{"messages":[{"role":"user","content":"hi"}]}`
	b, _ := json.Marshal(recent)
	_, recentOff, _ := l.Append(b)
	l.Close()

	f, _ := os.Open(logPath)
	defer f.Close()
	off, err := recentStart(f, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if off > recentOff || recentOff-off > 128<<10 {
		t.Fatalf("search started at %d; the recent entry is at %d", off, recentOff)
	}
	tracker, n, err := Rebuild(logPath, time.Hour)
	if err != nil || n != 1 || tracker.Sessions() != 1 {
		t.Fatalf("rebuilt %d calls, %d sessions, err %v", n, tracker.Sessions(), err)
	}
}

func TestReasoningSummary(t *testing.T) {
	long := strings.Repeat("why ", 300)
	x := record.Exchange{Call: &record.LLMCall{}, Resp: []byte(`{"choices":[{"message":{"content":"ok","reasoning_content":"` + long + `"}}]}`)}
	call, _ := Enrich(x, "gw", nil)
	r := call.Response.Reasoning
	if r == nil || r.Chars != len(strings.TrimSpace(long)) || len([]rune(r.Preview)) != record.ReasoningPreview || r.SHA256 == "" {
		t.Fatalf("reasoning %+v", r)
	}
	x = record.Exchange{Call: &record.LLMCall{}, Resp: []byte(`{"choices":[{"message":{"content":"ok"}}]}`)}
	if call, _ := Enrich(x, "gw", nil); call.Response.Reasoning != nil {
		t.Fatal("a reply without reasoning got a reasoning field")
	}
}

func TestRebuildForgetsConversationsWithTruncatedTurns(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log.jsonl")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	l, _ := ledger.Open(logPath, priv, ledger.Options{})
	write := func(req, resp string, truncated bool) {
		c := record.LLMCall{Type: record.TypeLLMCall, Timing: record.Timing{CompletedAt: time.Now()}}
		c.Request.Body.Text, c.Response.Body.Text, c.Response.Body.Truncated = req, resp, truncated
		b, _ := json.Marshal(c)
		l.Append(b)
	}
	u := `{"role":"user","content":"hi"}`
	echo1 := `{"role":"assistant","tool_calls":[{"id":"c1","function":{"name":"list_dir","arguments":"{}"}}]}`
	res1 := `{"role":"tool","tool_call_id":"c1","content":"a"}`
	write(`{"messages":[`+u+`]}`, `{"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"list_dir","arguments":"{}"}}]}}]}`, false)
	write(`{"messages":[`+u+`,`+echo1+`,`+res1+`]}`, `{"choices":[{"message":{"tool_calls":[{"id":"c2","function":{"name":"rea`, true)
	l.Close()

	tracker, _, err := Rebuild(logPath, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if tracker.Sessions() != 0 {
		t.Fatalf("the conversation with a truncated turn is still tracked (%d)", tracker.Sessions())
	}
}
