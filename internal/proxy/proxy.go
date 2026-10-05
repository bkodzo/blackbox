// Package proxy forwards agent traffic to the upstream model server and
// captures each exchange byte for byte.
//
// The proxy does not interpret payloads. It records who sent the request,
// the exact bytes in both directions with their SHA-256, timing, and how the
// exchange ended, then hands an Exchange to the sink. Interpretation happens
// later, off the request path.
package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/bkodzo/blackbox/internal/record"
)

// Headers an agent can send to describe itself. They are removed before the
// request is forwarded.
const (
	HeaderSession       = "X-Blackbox-Session"
	HeaderParentSession = "X-Blackbox-Parent-Session"
	HeaderAgent         = "X-Blackbox-Agent"
	HeaderAgentVersion  = "X-Blackbox-Agent-Version"
	HeaderPrincipal     = "X-Blackbox-Principal"
)

// Defaults for Config.
const (
	DefaultMaxBody         = 32 << 20
	DefaultMaxRequest      = 32 << 20 // equal to DefaultMaxBody, so requests are never stored truncated
	DefaultBodyReadTimeout = time.Minute
	DefaultUpstreamTimeout = 10 * time.Minute
	DefaultMaxInFlight     = 32
	DefaultMaxPerClient    = 8
	DefaultStreamIdle      = 5 * time.Minute
)

// ErrShutdown is the cancellation cause the gateway uses for calls still in
// flight when its shutdown grace period ends.
var ErrShutdown = errors.New("gateway shutting down")

// errStreamIdle cancels a call whose response made no progress for the
// stream idle limit.
var errStreamIdle = errors.New("the response made no progress")

// Config configures a Proxy.
type Config struct {
	Upstream *url.URL
	// Sink receives every exchange, from the handler goroutine.
	Sink func(record.Exchange)
	// Gate, if set, is called before forwarding. A non-nil error refuses the
	// request with 503, so traffic is never forwarded unrecorded.
	Gate func() error

	MaxBody    int64 // bytes of each body to store; hashes cover all bytes
	MaxRequest int64 // larger requests are refused with 413
	// MaxInFlight bounds requests handled at once, and so memory: at most
	// MaxInFlight * (MaxRequest + MaxBody) bytes of bodies. Requests beyond
	// it are refused with 503 and recorded.
	MaxInFlight int
	// MaxPerClient bounds requests handled at once for one client address,
	// so a single client cannot take every slot (for example with slow
	// uploads). Requests beyond either limit are refused with 503 and
	// counted, not recorded one by one, so a flood cannot grow the log.
	MaxPerClient    int
	BodyReadTimeout time.Duration // limit for reading a request body
	UpstreamTimeout time.Duration // limit for the upstream's response headers
	// StreamIdle bounds how long a response may go without progress in
	// either direction, the upstream sending nothing or the client reading
	// nothing. The call is then cancelled and recorded, freeing its slot.
	StreamIdle time.Duration
	// AllowUpgrades lets requests switch protocols (to a WebSocket, for
	// example). Traffic after a switch is passed through but not recorded, so
	// upgrades are refused unless this is set.
	AllowUpgrades bool
	Transport     http.RoundTripper
}

// Proxy is an http.Handler that forwards every request to Config.Upstream.
type Proxy struct {
	cfg      Config
	rp       *httputil.ReverseProxy
	slots    chan struct{}
	mu       sync.Mutex // guards closing, and inflight.Add against Close
	closing  bool
	clients  map[string]int // requests in flight per client address
	inflight sync.WaitGroup
	aborted  atomic.Uint64
	refused  atomic.Uint64 // requests refused for capacity
}

type ctxKey struct{}

// New returns a Proxy for cfg.
func New(cfg Config) *Proxy {
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = DefaultMaxBody
	}
	if cfg.MaxRequest <= 0 {
		cfg.MaxRequest = DefaultMaxRequest
	}
	if cfg.BodyReadTimeout <= 0 {
		cfg.BodyReadTimeout = DefaultBodyReadTimeout
	}
	if cfg.UpstreamTimeout <= 0 {
		cfg.UpstreamTimeout = DefaultUpstreamTimeout
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = DefaultMaxInFlight
	}
	if cfg.MaxPerClient <= 0 {
		cfg.MaxPerClient = DefaultMaxPerClient
	}
	if cfg.StreamIdle <= 0 {
		cfg.StreamIdle = DefaultStreamIdle
	}
	base := cfg.Transport
	if base == nil {
		// All traffic goes to one host. The default pool keeps only two idle
		// connections per host, which under concurrent load means a new
		// connection per request and, eventually, exhausted local ports.
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConns = 256
		t.MaxIdleConnsPerHost = 256
		t.ResponseHeaderTimeout = cfg.UpstreamTimeout
		base = t
	}
	p := &Proxy{cfg: cfg, slots: make(chan struct{}, cfg.MaxInFlight), clients: map[string]int{}}
	p.rp = &httputil.ReverseProxy{
		Rewrite:   p.rewrite,
		Transport: timedTransport{base},
		// Zero disables periodic flushing for ordinary responses. ReverseProxy
		// still flushes event streams and unknown-length bodies after every
		// write, so streamed tokens reach the agent immediately.
		FlushInterval:  0,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
	}
	return p
}

// Close refuses new requests, then waits up to d for every request being
// handled to finish and be handed to the sink. It reports whether they did.
func (p *Proxy) Close(d time.Duration) bool {
	p.mu.Lock()
	p.closing = true
	p.mu.Unlock()
	done := make(chan struct{})
	go func() {
		p.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// Aborted reports calls cancelled with ErrShutdown.
func (p *Proxy) Aborted() uint64 { return p.aborted.Load() }

// Refused reports requests refused because a capacity limit was reached.
func (p *Proxy) Refused() uint64 { return p.refused.Load() }

// busy refuses a request for capacity. It is counted rather than recorded.
func (p *Proxy) busy(w http.ResponseWriter, why string) {
	p.refused.Add(1)
	http.Error(w, "blackbox: "+why, http.StatusServiceUnavailable)
}

// exchange is the per-request state. All access happens on the handler
// goroutine (ReverseProxy calls hooks and reads the body there).
type exchange struct {
	call  *record.LLMCall
	req   []byte
	resp  *capture
	sse   bool
	span  string
	ctx   context.Context // the call's context; its cause says why it ended early
	rc    *http.ResponseController
	idle  time.Duration
	timer *time.Timer // cancels the call when the response stalls
}

// progress pushes back the idle limits after the response moved.
func (ex *exchange) progress() {
	ex.timer.Reset(ex.idle)
	ex.rc.SetWriteDeadline(time.Now().Add(ex.idle)) // writers without deadlines skip this
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Gate != nil {
		if err := p.cfg.Gate(); err != nil {
			// The cause is logged by the gateway; agents only learn that
			// the request was refused.
			http.Error(w, "blackbox: the audit log is unavailable, so the request was not forwarded",
				http.StatusServiceUnavailable)
			return
		}
	}
	client := clientAddr(r)
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		http.Error(w, "blackbox: the gateway is shutting down", http.StatusServiceUnavailable)
		return
	}
	if p.clients[client] >= p.cfg.MaxPerClient {
		p.mu.Unlock()
		p.busy(w, "too many requests from this client")
		return
	}
	p.clients[client]++
	p.inflight.Add(1)
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if p.clients[client]--; p.clients[client] == 0 {
			delete(p.clients, client)
		}
		p.mu.Unlock()
		p.inflight.Done()
	}()

	received := time.Now().UTC()
	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	ex := &exchange{call: newCall(r, p.cfg.Upstream, received), span: randomHex(8),
		ctx: ctx, rc: http.NewResponseController(w), idle: p.cfg.StreamIdle}
	ex.timer = time.AfterFunc(ex.idle, func() { cancel(errStreamIdle) })
	ex.timer.Stop() // armed once the response starts
	defer ex.timer.Stop()
	ex.call.Trace = trace(r.Header.Get("Traceparent"), ex.span)

	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		p.busy(w, "too many requests in flight")
		return
	}

	reqBody, err := p.readBody(w, r)
	ex.req = p.stored(reqBody)
	ex.call.Request.Body = makeBody(ex.req, int64(len(reqBody)), sha256Hex(reqBody), p.cfg.MaxBody)
	if err != nil {
		status, class := http.StatusBadRequest, record.ErrorClientAborted
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status, class = http.StatusRequestEntityTooLarge, record.ErrorRequestTooLarge
			ex.call.Request.Body.Truncated = true
		}
		ex.call.Error = &record.Error{Class: class, Message: err.Error()}
		ex.call.Response.Status = status
		http.Error(w, "blackbox: reading request body: "+err.Error(), status)
		p.finish(ex, false)
		return
	}
	if r.Header.Get("Upgrade") != "" && !p.cfg.AllowUpgrades {
		ex.call.Error = &record.Error{Class: record.ErrorUpgradeRefused,
			Message: "protocol upgrades are refused, since traffic after one cannot be recorded"}
		ex.call.Response.Status = http.StatusNotImplemented
		http.Error(w, "blackbox: protocol upgrades are not allowed", http.StatusNotImplemented)
		p.finish(ex, false)
		return
	}

	out := r.WithContext(context.WithValue(ctx, ctxKey{}, ex))
	out.Body = io.NopCloser(bytes.NewReader(reqBody))
	out.ContentLength = int64(len(reqBody))

	defer func() {
		// ReverseProxy panics with http.ErrAbortHandler when a copy fails
		// mid-response. Record the exchange before letting it propagate.
		v := recover()
		p.finish(ex, v != nil)
		if v != nil {
			panic(v)
		}
	}()
	p.rp.ServeHTTP(w, out)
}

// readBody reads the request body within the size and time limits.
func (p *Proxy) readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(p.cfg.BodyReadTimeout)) // writers without deadlines skip the limit
	defer rc.SetReadDeadline(time.Time{})
	return io.ReadAll(http.MaxBytesReader(w, r.Body, p.cfg.MaxRequest))
}

// stored returns the part of b that is kept, copying it when it is a prefix
// so the full request can be released after forwarding.
func (p *Proxy) stored(b []byte) []byte {
	if int64(len(b)) <= p.cfg.MaxBody {
		return b
	}
	return bytes.Clone(b[:p.cfg.MaxBody])
}

func newCall(r *http.Request, upstream *url.URL, received time.Time) *record.LLMCall {
	h := r.Header
	ip := clientAddr(r)
	return &record.LLMCall{
		Type:         record.TypeLLMCall,
		Agent:        record.Agent{ID: h.Get(HeaderAgent), Version: h.Get(HeaderAgentVersion)},
		Session:      record.Session{ID: h.Get(HeaderSession), ParentID: h.Get(HeaderParentSession)},
		Principal:    h.Get(HeaderPrincipal),
		CredentialFP: credentialFingerprint(h),
		Client:       record.Client{IP: ip, UserAgent: h.Get("User-Agent")},
		Identity:     "self_declared",
		Request:      record.Request{Method: r.Method, Path: r.URL.Path},
		Upstream:     record.Upstream{URL: upstream.String()},
		Timing:       record.Timing{ReceivedAt: received},
	}
}

func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	ex := pr.In.Context().Value(ctxKey{}).(*exchange)
	pr.SetURL(p.cfg.Upstream)
	for _, k := range []string{HeaderSession, HeaderParentSession, HeaderAgent, HeaderAgentVersion, HeaderPrincipal} {
		pr.Out.Header.Del(k)
	}
	// Let the transport negotiate compression and decompress for us, so the
	// captured response is the readable payload.
	pr.Out.Header.Del("Accept-Encoding")
	pr.Out.Header.Set("Traceparent", "00-"+ex.call.Trace.TraceID+"-"+ex.span+"-01")
}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	ex := resp.Request.Context().Value(ctxKey{}).(*exchange)
	c := ex.call
	c.Response.Status = resp.StatusCode
	c.Response.ContentType = resp.Header.Get("Content-Type")
	c.Upstream.RequestID = firstHeader(resp.Header, "X-Request-Id", "Request-Id")
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// ReverseProxy needs the original body to splice the connection.
		c.Response.Upgraded = true
		return nil
	}
	ex.sse = strings.HasPrefix(c.Response.ContentType, "text/event-stream")
	ex.resp = &capture{rc: resp.Body, h: sha256.New(), max: p.cfg.MaxBody, progress: ex.progress}
	resp.Body = ex.resp
	ex.progress() // arm the idle limits for the response
	return nil
}

func (p *Proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	ex := r.Context().Value(ctxKey{}).(*exchange)
	ex.call.Error = &record.Error{Class: abortClass(r.Context(), record.ErrorUpstreamUnreachable), Message: err.Error()}
	ex.call.Response.Status = http.StatusBadGateway
	w.WriteHeader(http.StatusBadGateway)
}

// abortClass explains a failure: the gateway shutting down, the response
// stalling, the client leaving, or otherwise def.
func abortClass(ctx context.Context, def string) string {
	switch {
	case errors.Is(context.Cause(ctx), ErrShutdown):
		return record.ErrorGatewayShutdown
	case errors.Is(context.Cause(ctx), errStreamIdle):
		return record.ErrorStreamIdle
	case ctx.Err() != nil:
		return record.ErrorClientAborted
	}
	return def
}

// finish records the exchange. aborted is set when copying the response
// failed (for example a client that stopped reading).
func (p *Proxy) finish(ex *exchange, aborted bool) {
	c := ex.call
	c.Timing.CompletedAt = time.Now().UTC()
	if errors.Is(context.Cause(ex.ctx), ErrShutdown) {
		p.aborted.Add(1)
	}
	if rc := ex.resp; rc != nil {
		c.Timing.FirstByteAt = rc.first
		c.Response.Body = makeBody(rc.buf.Bytes(), rc.n, hex.EncodeToString(rc.h.Sum(nil)), p.cfg.MaxBody)
		outcome := record.StreamCompleted
		switch {
		case !rc.eof && (ex.ctx.Err() != nil || aborted):
			outcome = record.StreamClientAborted
			if c.Error == nil {
				msg := "the exchange ended before the response finished"
				if ex.ctx.Err() == nil {
					msg = "the client stopped reading the response"
				}
				c.Error = &record.Error{Class: abortClass(ex.ctx, record.ErrorClientAborted), Message: msg}
			}
		case rc.err != nil:
			outcome = record.StreamUpstreamError
			if c.Error == nil {
				c.Error = &record.Error{Class: record.ErrorUpstreamRead, Message: rc.err.Error()}
			}
		}
		if ex.sse {
			c.Response.Stream = &record.Stream{Outcome: outcome}
		}
	}
	if c.Error == nil && c.Response.Status >= 400 {
		c.Error = &record.Error{Class: record.ErrorUpstreamStatus, Message: http.StatusText(c.Response.Status)}
	}
	if p.cfg.Sink != nil {
		var resp []byte
		if ex.resp != nil {
			resp = ex.resp.buf.Bytes()
		}
		p.cfg.Sink(record.Exchange{Call: c, Req: ex.req, Resp: resp, SSE: ex.sse})
	}
}

// capture is the response body seen by ReverseProxy. It hashes and counts
// every byte, and keeps up to max bytes.
type capture struct {
	rc       io.ReadCloser
	h        hash.Hash
	buf      bytes.Buffer
	n        int64
	max      int64
	first    time.Time
	eof      bool
	err      error
	progress func() // called after each chunk
}

func (c *capture) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		if c.first.IsZero() {
			c.first = time.Now().UTC()
		}
		c.h.Write(p[:n])
		if room := c.max - int64(c.buf.Len()); room > 0 {
			c.buf.Write(p[:min(int64(n), room)])
		}
		c.n += int64(n)
		c.progress()
	}
	switch {
	case err == io.EOF:
		c.eof = true
	case err != nil && !errors.Is(err, context.Canceled):
		c.err = err
	}
	return n, err
}

func (c *capture) Close() error { return c.rc.Close() }

// timedTransport notes when the request leaves for the upstream.
type timedTransport struct{ base http.RoundTripper }

func (t timedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if ex, ok := r.Context().Value(ctxKey{}).(*exchange); ok {
		ex.call.Timing.UpstreamSentAt = time.Now().UTC()
	}
	return t.base.RoundTrip(r)
}

func makeBody(b []byte, total int64, sum string, max int64) record.Body {
	body := record.Body{SHA256: sum, Bytes: total, Truncated: total > max}
	if len(b) == 0 {
		return body
	}
	if utf8.Valid(b) {
		body.Text = string(b)
	} else {
		body.Base64 = base64.StdEncoding.EncodeToString(b)
	}
	return body
}

// credentialFingerprint identifies which credential was used without storing
// it: the first 8 bytes of the SHA-256 of the secret.
func credentialFingerprint(h http.Header) string {
	v := firstHeader(h, "Authorization", "X-Api-Key", "Api-Key")
	if v == "" {
		return ""
	}
	if s, ok := strings.CutPrefix(v, "Bearer "); ok {
		v = s
	}
	sum := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// trace continues a W3C traceparent if one was sent, or starts a new trace.
func trace(traceparent, span string) record.Trace {
	parts := strings.Split(traceparent, "-")
	if len(parts) == 4 && len(parts[1]) == 32 && len(parts[2]) == 16 && isHex(parts[1]) && isHex(parts[2]) {
		return record.Trace{TraceID: parts[1], SpanID: span, ParentSpanID: parts[2]}
	}
	return record.Trace{TraceID: randomHex(16), SpanID: span}
}

func firstHeader(h http.Header, keys ...string) string {
	for _, k := range keys {
		if v := h.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// clientAddr is the address a request came from, without its port.
func clientAddr(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
