package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
)

type gateway struct {
	cfg  config
	url  string
	pub  string
	stop context.CancelFunc
	done chan int
}

// startGateway runs serve against upstream in a temporary directory.
func startGateway(t *testing.T, upstream string, edit func(*config)) *gateway {
	t.Helper()
	dir := t.TempDir()
	if code := runInit([]string{"--dir", dir}); code != 0 {
		t.Fatalf("init exited %d", code)
	}
	cfg := defaultConfig()
	cfg.Upstream = upstream
	cfg.Key = filepath.Join(dir, "key.ed25519")
	cfg.Log = filepath.Join(dir, "log.jsonl")
	cfg.Checkpoints = filepath.Join(dir, "cp.jsonl")
	cfg.MirrorCPs = false
	if edit != nil {
		edit(&cfg)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &gateway{cfg: cfg, url: "http://" + ln.Addr().String(), pub: filepath.Join(dir, "key.pub"), stop: cancel, done: make(chan int, 1)}
	go func() { g.done <- serve(ctx, cfg, ln, io.Discard) }()
	return g
}

func (g *gateway) shutdown(t *testing.T) int {
	t.Helper()
	g.stop()
	select {
	case code := <-g.done:
		return code
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not exit")
		return -1
	}
}

// records verifies the log and returns its records' types and contents.
func (g *gateway) records(t *testing.T) []json.RawMessage {
	t.Helper()
	pub, err := ledger.LoadPublicKey(g.pub)
	if err != nil {
		t.Fatal(err)
	}
	cps, _, err := ledger.ReadCheckpoints(g.cfg.Checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(g.cfg.Log)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []json.RawMessage
	if _, err := ledger.Verify(f, pub, cps, func(e ledger.Entry) { recs = append(recs, e.Rec) }); err != nil {
		t.Fatal(err)
	}
	return recs
}

func typeOf(rec json.RawMessage) string {
	var h struct {
		Type string `json:"type"`
	}
	json.Unmarshal(rec, &h)
	return h.Type
}

func TestServeRecordsCallsAndShutsDownCleanly(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"content":"hi"}}]}`)
	}))
	defer up.Close()
	g := startGateway(t, up.URL, nil)

	waitHealthy(t, g.url)
	for range 3 {
		post(t, g.url+"/v1/chat/completions", `{"model":"m","messages":[]}`)
	}
	if code := g.shutdown(t); code != 0 {
		t.Fatalf("serve exited %d", code)
	}

	recs := g.records(t)
	var types []string
	for _, r := range recs {
		types = append(types, typeOf(r))
	}
	if got := strings.Join(types, ","); got != "gateway_start,llm_call,llm_call,llm_call,gateway_stop" {
		t.Fatalf("records %s", got)
	}
	var stop record.GatewayStop
	json.Unmarshal(recs[len(recs)-1], &stop)
	if stop.Calls != 3 || stop.Unrecorded != 0 {
		t.Fatalf("stop %+v", stop)
	}
}

func TestServeCancelsAndRecordsCallsInFlightAtShutdown(t *testing.T) {
	started := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {}\n\n")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done() // a stream that outlives the grace period
	}))
	defer up.Close()
	g := startGateway(t, up.URL, func(c *config) { c.ShutdownTimeout = duration(200 * time.Millisecond) })
	waitHealthy(t, g.url)

	go func() {
		resp, err := http.Post(g.url+"/v1/chat/completions", "application/json", strings.NewReader(`{}`))
		if err == nil {
			io.ReadAll(resp.Body)
			resp.Body.Close()
		}
	}()
	<-started
	if code := g.shutdown(t); code != 0 {
		t.Fatalf("serve exited %d", code)
	}

	recs := g.records(t)
	var call record.LLMCall
	json.Unmarshal(recs[1], &call)
	if call.Error == nil || call.Error.Class != record.ErrorGatewayShutdown {
		t.Fatalf("in-flight call recorded as %+v", call.Error)
	}
	var stop record.GatewayStop
	json.Unmarshal(recs[len(recs)-1], &stop)
	if typeOf(recs[len(recs)-1]) != record.TypeGatewayStop || stop.AbortedAtShutdown != 1 {
		t.Fatalf("stop %+v", stop)
	}
}

func TestServeRefusesTruncatedLog(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()
	g := startGateway(t, up.URL, nil)
	waitHealthy(t, g.url)
	post(t, g.url+"/v1/x", `{}`)
	g.shutdown(t)

	b, _ := os.ReadFile(g.cfg.Log)
	lines := strings.SplitAfter(string(b), "\n")
	os.WriteFile(g.cfg.Log, []byte(strings.Join(lines[:1], "")), 0o600)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	if code := serve(context.Background(), g.cfg, ln, io.Discard); code == 0 {
		t.Fatal("serve started on a log shorter than its checkpoint")
	}
}

func waitHealthy(t *testing.T, base string) {
	t.Helper()
	for range 100 {
		resp, err := http.Get(base + "/_blackbox/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("gateway never became healthy")
}

func post(t *testing.T, url, body string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
}

func TestSlowRecorderAtShutdownStillClosesTheLog(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer up.Close()
	// A grace period far shorter than the time needed to record a backlog
	// of large calls.
	g := startGateway(t, up.URL, func(c *config) { c.ShutdownTimeout = duration(time.Millisecond) })
	waitHealthy(t, g.url)
	body := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("x", 4<<20) + `"}]}`
	for range 30 {
		post(t, g.url+"/v1/chat/completions", body)
	}
	if code := g.shutdown(t); code == 0 {
		t.Skip("the recorder kept up, so this run did not exercise a slow shutdown")
	}

	// Whatever was written must be flushed and covered by a final
	// checkpoint by the time serve returns, as the process exits then.
	data, err := os.ReadFile(g.cfg.Log)
	if err != nil {
		t.Fatal(err)
	}
	entries := uint64(strings.Count(string(data), "\n"))
	cps, _, err := ledger.ReadCheckpoints(g.cfg.Checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	var covered uint64
	for _, c := range cps {
		covered = max(covered, c.Seq)
	}
	if entries == 0 || covered != entries {
		t.Fatalf("serve returned with %d entries in the log, %d covered by a checkpoint", entries, covered)
	}
	recs := g.records(t)
	if last := typeOf(recs[len(recs)-1]); last == record.TypeGatewayStop {
		t.Fatal("gateway_stop was written although the recorder did not finish")
	}
}
