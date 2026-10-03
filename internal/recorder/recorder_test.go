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
