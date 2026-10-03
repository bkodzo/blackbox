package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToolsStayInsideRoot(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.md"), []byte("hello"), 0o600)
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	os.WriteFile(filepath.Join(filepath.Dir(dir), "outside.txt"), []byte("secret"), 0o600)
	// Creating symlinks needs extra privileges on some systems; test them where possible.
	haveLink := os.Symlink(filepath.Join(filepath.Dir(dir), "outside.txt"), filepath.Join(dir, "link.txt")) == nil
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	want := "a.md\nsub/"
	if haveLink {
		want = "a.md\nlink.txt\nsub/"
	}
	if got := runTool(root, "list_dir", `{"path":"."}`); got != want {
		t.Fatalf("list_dir: %q", got)
	}
	if got := runTool(root, "read_file", `{"path":"./a.md"}`); got != "hello" {
		t.Fatalf("read_file: %q", got)
	}
	for _, p := range []string{"../outside.txt", "/../../outside.txt", "link.txt"} {
		if got := runTool(root, "read_file", `{"path":"`+p+`"}`); !strings.HasPrefix(got, "error:") {
			t.Fatalf("read_file(%s) escaped the root: %q", p, got)
		}
	}
	if got := runTool(root, "read_file", `{not json`); !strings.HasPrefix(got, "error:") {
		t.Fatalf("bad args: %q", got)
	}
	if got := runTool(root, "delete_everything", `{}`); !strings.HasPrefix(got, "error: unknown tool") {
		t.Fatalf("unknown tool: %q", got)
	}
}

func TestLoopEchoesRepliesAndReturnsToolResults(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.md"), []byte("notes"), 0o600)

	var requests [][]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Blackbox-Session") != "s1" || r.Header.Get("X-Blackbox-Agent") != "demo-agent" {
			t.Errorf("missing blackbox headers: %v", r.Header)
		}
		var body struct {
			Messages []json.RawMessage `json:"messages"`
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		requests = append(requests, body.Messages)
		if len(requests) == 1 {
			io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[`+
				`{"id":"c1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a.md\"}"}}]}}]}`)
			return
		}
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"It says notes."}}]}`)
	}))
	defer srv.Close()

	var out bytes.Buffer
	cfg := config{URL: srv.URL, Model: "test-model", Dir: dir, Task: "What is in a.md?", Session: "s1", Agent: "demo-agent", MaxTurns: 4}
	if err := run(context.Background(), cfg, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "It says notes.") {
		t.Fatalf("output %q", out.String())
	}
	if len(requests) != 2 || len(requests[1]) != 4 {
		t.Fatalf("requests %d, second has %d messages", len(requests), len(requests[1]))
	}
	if !strings.Contains(string(requests[1][2]), `"id":"c1"`) {
		t.Fatalf("assistant reply not echoed: %s", requests[1][2])
	}
	if got := string(requests[1][3]); !strings.Contains(got, `"tool_call_id":"c1"`) || !strings.Contains(got, "notes") {
		t.Fatalf("tool result: %s", got)
	}
}

func TestForgeAddsUnrequestedResult(t *testing.T) {
	calls := 0
	var last []json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body struct {
			Messages []json.RawMessage `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		last = body.Messages
		if calls == 1 {
			io.WriteString(w, `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c1","function":{"name":"get_time","arguments":"{}"}}]}}]}`)
			return
		}
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"done"}}]}`)
	}))
	defer srv.Close()

	cfg := config{URL: srv.URL, Model: "m", Dir: t.TempDir(), Task: "t", Session: "s", MaxTurns: 3, Forge: true}
	if err := run(context.Background(), cfg, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(last[len(last)-1]), "forged-1") {
		t.Fatalf("forged result missing: %s", last[len(last)-1])
	}
}

func TestServerErrorIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "model not found", http.StatusNotFound)
	}))
	defer srv.Close()
	cfg := config{URL: srv.URL, Model: "m", Dir: t.TempDir(), Task: "t", MaxTurns: 1}
	err := run(context.Background(), cfg, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "model not found") {
		t.Fatalf("err %v", err)
	}
}
