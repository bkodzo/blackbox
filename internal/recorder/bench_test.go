package recorder

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/proxy"
	"github.com/bkodzo/blackbox/internal/record"
)

// A typical tool-calling exchange: a few KB of conversation in, a tool call out.
var (
	benchReq  = `{"model":"test-model","messages":[{"role":"system","content":"You are a file helper."},{"role":"user","content":"` + strings.Repeat("Summarize the notes. ", 150) + `"}],"tools":[{"type":"function","function":{"name":"read_file","parameters":{}}}]}`
	benchResp = `{"model":"test-model","choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a.md\"}"}}]}}],"usage":{"prompt_tokens":800,"completion_tokens":20}}`
)

func benchUpstream(b *testing.B) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, benchResp)
	}))
	b.Cleanup(srv.Close)
	return srv.URL
}

func benchLedger(b *testing.B) *ledger.Ledger {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	l, err := ledger.Open(filepath.Join(b.TempDir(), "log.jsonl"), priv, ledger.Options{})
	if err != nil {
		b.Fatal(err)
	}
	return l
}

// benchGateway starts the full gateway in front of upstream.
func benchGateway(b *testing.B, upstream string) string {
	l := benchLedger(b)
	rec := New(l, "bench", Options{})
	u, _ := url.Parse(upstream)
	gw := httptest.NewServer(proxy.New(proxy.Config{Upstream: u, Sink: rec.Submit}))
	b.Cleanup(func() {
		gw.Close()
		rec.Close()
		l.Close()
	})
	return gw.URL
}

func call(b *testing.B, client *http.Client, base string) {
	req, _ := http.NewRequest("POST", base+"/v1/chat/completions", strings.NewReader(benchReq))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Blackbox-Session", "bench") // so session checks run on every call
	resp, err := client.Do(req)
	if err != nil {
		b.Error(err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func newClient() *http.Client {
	return &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
}

// BenchmarkLatency is one call at a time: the delay an agent sees.
func BenchmarkLatency(b *testing.B) {
	for _, mode := range []string{"direct", "gateway"} {
		b.Run(mode, func(b *testing.B) {
			base := benchUpstream(b)
			if mode == "gateway" {
				base = benchGateway(b, base)
			}
			client := newClient()
			for b.Loop() {
				call(b, client, base)
			}
		})
	}
}

// BenchmarkThroughput is many concurrent agents.
func BenchmarkThroughput(b *testing.B) {
	for _, mode := range []string{"direct", "gateway"} {
		b.Run(mode, func(b *testing.B) {
			base := benchUpstream(b)
			if mode == "gateway" {
				base = benchGateway(b, base)
			}
			client := newClient()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					call(b, client, base)
				}
			})
		})
	}
}

// BenchmarkRecordPipeline is the work done per call off the request path:
// parsing, session checks against the previous turn, encoding, hashing,
// signing, and appending. Disk writes happen in the background.
func BenchmarkRecordPipeline(b *testing.B) {
	l := benchLedger(b)
	defer l.Close()
	rec := New(l, "bench", Options{})
	defer rec.Close()
	b.SetBytes(int64(len(benchReq) + len(benchResp)))
	for b.Loop() {
		x := record.Exchange{
			Call: &record.LLMCall{Type: record.TypeLLMCall, Session: record.Session{ID: "s"}},
			Req:  []byte(benchReq), Resp: []byte(benchResp),
		}
		call, parsed := Enrich(x, "bench", nil)
		obs := rec.sessions.Observe(call, parsed)
		line, err := json.Marshal(call)
		if err != nil {
			b.Fatal(err)
		}
		e, _, err := l.Append(line)
		if err != nil {
			b.Fatal(err)
		}
		rec.sessions.Commit(obs, e.Seq)
	}
}
