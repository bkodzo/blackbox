package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bkodzo/blackbox/internal/record"
)

// harness runs a proxy in front of upstream and collects captures.
type harness struct {
	srv  *httptest.Server
	caps chan record.Exchange
}

func newHarness(t *testing.T, upstream http.Handler, maxBody int64) *harness {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL + "/base")
	h := &harness{caps: make(chan record.Exchange, 4)}
	h.srv = httptest.NewServer(New(Config{Upstream: u, MaxBody: maxBody, Sink: func(c record.Exchange) { h.caps <- c }}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *harness) capture(t *testing.T) record.Exchange {
	t.Helper()
	select {
	case c := <-h.caps:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no capture")
		return record.Exchange{}
	}
}

func hexSum(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}

func TestForwardsAndCaptures(t *testing.T) {
	const reqBody = `{"model":"test-model","messages":[]}`
	const respBody = `{"choices":[]}`
	var got *http.Request
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-123")
		io.WriteString(w, respBody)
	}), 0)

	req, _ := http.NewRequest("POST", h.srv.URL+"/v1/chat/completions", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer secret-key")
	req.Header.Set(HeaderSession, "run-1")
	req.Header.Set(HeaderAgent, "file-helper")
	req.Header.Set(HeaderPrincipal, "alice")
	req.Header.Set("Traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != respBody {
		t.Fatalf("agent got %q", body)
	}

	// Upstream view: path joined, identity headers stripped, auth passed through.
	if got.URL.Path != "/base/v1/chat/completions" {
		t.Fatalf("upstream path %q", got.URL.Path)
	}
	if got.Header.Get(HeaderSession) != "" || got.Header.Get(HeaderAgent) != "" {
		t.Fatal("identity headers leaked upstream")
	}
	if got.Header.Get("Authorization") != "Bearer secret-key" {
		t.Fatal("auth header not forwarded")
	}
	if tp := got.Header.Get("Traceparent"); !strings.HasPrefix(tp, "00-0af7651916cd43dd8448eb211c80319c-") {
		t.Fatalf("traceparent %q", tp)
	}

	c := h.capture(t).Call
	if c.Session.ID != "run-1" || c.Agent.ID != "file-helper" || c.Principal != "alice" || c.Identity != "self_declared" {
		t.Fatalf("who: %+v", c)
	}
	if c.CredentialFP == "" || strings.Contains(c.CredentialFP, "secret") {
		t.Fatalf("credential fp %q", c.CredentialFP)
	}
	if c.Trace.TraceID != "0af7651916cd43dd8448eb211c80319c" || c.Trace.ParentSpanID != "b7ad6b7169203331" || len(c.Trace.SpanID) != 16 {
		t.Fatalf("trace %+v", c.Trace)
	}
	if c.Request.Body.SHA256 != hexSum(reqBody) || c.Request.Body.Text != reqBody {
		t.Fatalf("request body %+v", c.Request.Body)
	}
	if c.Response.Body.SHA256 != hexSum(respBody) || c.Response.Body.Bytes != int64(len(respBody)) || c.Response.Status != 200 {
		t.Fatalf("response %+v", c.Response)
	}
	if c.Upstream.RequestID != "req-123" || c.Error != nil || c.Response.Stream != nil {
		t.Fatalf("upstream %+v error %+v", c.Upstream, c.Error)
	}
	tm := c.Timing
	if tm.UpstreamSentAt.Before(tm.ReceivedAt) || tm.FirstByteAt.Before(tm.UpstreamSentAt) || tm.CompletedAt.Before(tm.FirstByteAt) {
		t.Fatalf("timing out of order %+v", tm)
	}
}

func TestStreamsWithoutBuffering(t *testing.T) {
	release := make(chan struct{})
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-release // hold the stream open until the agent has seen chunk one
		io.WriteString(w, "data: two\n\n")
	}), 0)

	resp, err := http.Post(h.srv.URL+"/v1/x", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(resp.Body)
	if line, _ := br.ReadString('\n'); line != "data: one\n" {
		t.Fatalf("first chunk %q", line)
	}
	close(release)
	io.ReadAll(br)
	resp.Body.Close()

	c := h.capture(t)
	if !c.SSE || c.Call.Response.Stream == nil || c.Call.Response.Stream.Outcome != record.StreamCompleted {
		t.Fatalf("stream %+v", c.Call.Response.Stream)
	}
	if string(c.Resp) != "data: one\n\ndata: two\n\n" {
		t.Fatalf("captured %q", c.Resp)
	}
}

func TestClientAbortIsRecorded(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for {
			if _, err := io.WriteString(w, "data: tick\n\n"); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}), 0)

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "POST", h.srv.URL+"/v1/x", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	bufio.NewReader(resp.Body).ReadString('\n')
	cancel()
	resp.Body.Close()

	c := h.capture(t).Call
	if c.Response.Stream == nil || c.Response.Stream.Outcome != record.StreamClientAborted {
		t.Fatalf("stream %+v", c.Response.Stream)
	}
	if c.Error == nil || c.Error.Class != "client_aborted" {
		t.Fatalf("error %+v", c.Error)
	}
}

func TestUpstreamDown(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1") // nothing listens here
	caps := make(chan record.Exchange, 1)
	srv := httptest.NewServer(New(Config{Upstream: u, Sink: func(c record.Exchange) { caps <- c }}))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/x", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
	c := (<-caps).Call
	if c.Error == nil || c.Error.Class != "upstream_unreachable" || c.Response.Status != http.StatusBadGateway {
		t.Fatalf("call %+v", c)
	}
}

func TestUpstreamErrorStatus(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"no such model"}`, http.StatusNotFound)
	}), 0)
	resp, _ := http.Post(h.srv.URL+"/v1/x", "application/json", strings.NewReader(`{}`))
	resp.Body.Close()
	c := h.capture(t).Call
	if c.Error == nil || c.Error.Class != "upstream_status" || c.Response.Status != 404 {
		t.Fatalf("call %+v", c)
	}
}

func TestLargeBodiesAreCappedButFullyHashed(t *testing.T) {
	big := strings.Repeat("x", 1000)
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, big)
	}), 100)
	resp, _ := http.Post(h.srv.URL+"/v1/x", "application/json", strings.NewReader(big))
	io.ReadAll(resp.Body)
	resp.Body.Close()

	c := h.capture(t)
	for name, b := range map[string]record.Body{"request": c.Call.Request.Body, "response": c.Call.Response.Body} {
		if !b.Truncated || b.Bytes != 1000 || len(b.Text) != 100 || b.SHA256 != hexSum(big) {
			t.Fatalf("%s body: truncated=%v bytes=%d stored=%d", name, b.Truncated, b.Bytes, len(b.Text))
		}
	}
	if len(c.Req) != 100 || len(c.Resp) != 100 {
		t.Fatalf("capture sizes %d %d", len(c.Req), len(c.Resp))
	}
}

func TestBinaryBodyStoredAsBase64(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte{0xff, 0xfe, 0x00})
	}), 0)
	resp, _ := http.Post(h.srv.URL+"/v1/x", "application/octet-stream", strings.NewReader(`{}`))
	io.ReadAll(resp.Body)
	resp.Body.Close()
	b := h.capture(t).Call.Response.Body
	if b.Base64 != "//4A" || b.Text != "" {
		t.Fatalf("body %+v", b)
	}
}

func TestRequestTooLargeIsRefusedAndRecorded(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("an oversized request reached the upstream")
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	caps := make(chan record.Exchange, 1)
	srv := httptest.NewServer(New(Config{Upstream: u, MaxRequest: 100, MaxBody: 50, Sink: func(c record.Exchange) { caps <- c }}))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/x", "application/json", strings.NewReader(strings.Repeat("x", 1000)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", resp.StatusCode)
	}
	c := <-caps
	if c.Call.Error == nil || c.Call.Error.Class != record.ErrorRequestTooLarge || len(c.Req) > 50 {
		t.Fatalf("call %+v, stored %d bytes", c.Call.Error, len(c.Req))
	}
}

func TestGateRefusesWhenAuditUnavailable(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request forwarded while the audit log was down")
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	srv := httptest.NewServer(New(Config{Upstream: u, Gate: func() error { return errors.New("disk full") }}))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/x", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// The agent learns the request was refused, not the internal cause.
	if resp.StatusCode != http.StatusServiceUnavailable || strings.Contains(string(body), "disk full") {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
}

func TestProtocolUpgradePassesThrough(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		rw.Flush()
		line, _ := rw.ReadString('\n')
		rw.WriteString("echo: " + line)
		rw.Flush()
	}))
	defer up.Close()
	h := &harness{caps: make(chan record.Exchange, 1)}
	u, _ := url.Parse(up.URL)
	h.srv = httptest.NewServer(New(Config{Upstream: u, Sink: func(c record.Exchange) { h.caps <- c }}))
	defer h.srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET /v1/ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	io.WriteString(conn, "hello\n")
	if line, _ := br.ReadString('\n'); line != "echo: hello\n" {
		t.Fatalf("after upgrade got %q", line)
	}
	conn.Close()
	if c := h.capture(t).Call; !c.Response.Upgraded || c.Response.Status != 101 {
		t.Fatalf("call %+v", c.Response)
	}
}

func TestShutdownCancellationIsRecorded(t *testing.T) {
	started := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	caps := make(chan record.Exchange, 1)
	p := New(Config{Upstream: u, Sink: func(c record.Exchange) { caps <- c }})

	base, cancel := context.WithCancelCause(context.Background())
	srv := httptest.NewUnstartedServer(p)
	srv.Config.BaseContext = func(net.Listener) context.Context { return base }
	srv.Start()
	defer srv.Close()

	go func() {
		resp, err := http.Post(srv.URL+"/v1/x", "application/json", strings.NewReader(`{}`))
		if err == nil {
			io.ReadAll(resp.Body)
			resp.Body.Close()
		}
	}()
	<-started
	cancel(ErrShutdown)
	p.Wait()
	c := (<-caps).Call
	if c.Error == nil || c.Error.Class != record.ErrorGatewayShutdown || p.Aborted() != 1 {
		t.Fatalf("error %+v aborted %d", c.Error, p.Aborted())
	}
}

func TestRequestsBeyondTheLimitAreRefusedAndRecorded(t *testing.T) {
	arrived, release := make(chan struct{}), make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-release
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	caps := make(chan record.Exchange, 4)
	srv := httptest.NewServer(New(Config{Upstream: u, MaxInFlight: 1, Sink: func(c record.Exchange) { caps <- c }}))
	defer srv.Close()

	first := make(chan struct{})
	go func() {
		defer close(first)
		if resp, err := http.Post(srv.URL+"/v1/x", "application/json", strings.NewReader(`{}`)); err == nil {
			resp.Body.Close()
		}
	}()
	<-arrived // the first request now holds the only slot

	resp, err := http.Post(srv.URL+"/v1/x", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", resp.StatusCode)
	}
	if c := <-caps; c.Call.Error == nil || c.Call.Error.Class != record.ErrorGatewayBusy {
		t.Fatalf("refused request recorded as %+v", c.Call.Error)
	}
	close(release)
	<-first
}
