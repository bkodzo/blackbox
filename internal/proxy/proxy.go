// Package proxy forwards agent traffic to the upstream model server and
// captures each exchange byte for byte.
//
// The proxy does not interpret payloads. It records who sent the request,
// the exact bytes in both directions with their SHA-256, timing, and how the
// exchange ended, then hands a Capture to the sink. Interpretation happens
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

// DefaultMaxBody caps how many bytes of each body are stored. Hashes and byte
// counts always cover the full body.
const DefaultMaxBody = 32 << 20

// Capture is one finished exchange. Call has every field the proxy can know
// without parsing payloads; Req and Resp are the stored bodies.
type Capture struct {
	Call      *record.LLMCall
	Req, Resp []byte
	SSE       bool
}

// Config configures a Proxy.
type Config struct {
	Upstream  *url.URL
	Sink      func(Capture) // called once per exchange, from the handler goroutine
	MaxBody   int64         // default DefaultMaxBody
	Transport http.RoundTripper
}

// Proxy is an http.Handler that forwards every request to Config.Upstream.
type Proxy struct {
	cfg Config
	rp  *httputil.ReverseProxy
}

type ctxKey struct{}

// New returns a Proxy for cfg.
func New(cfg Config) *Proxy {
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = DefaultMaxBody
	}
	base := cfg.Transport
	if base == nil {
		// All traffic goes to one host. The default pool keeps only two idle
		// connections per host, which under concurrent load means a new
		// connection per request and, eventually, exhausted local ports.
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConns = 256
		t.MaxIdleConnsPerHost = 256
		base = t
	}
	p := &Proxy{cfg: cfg}
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

// exchange is the per-request state. All access happens on the handler
// goroutine (ReverseProxy calls hooks and reads the body there).
type exchange struct {
	call *record.LLMCall
	req  []byte
	resp *capture
	sse  bool
	span string
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	received := time.Now().UTC()
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "blackbox: reading request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	ex := &exchange{call: newCall(r, p.cfg.Upstream, received), span: randomHex(8)}
	ex.call.Trace = trace(r.Header.Get("Traceparent"), ex.span)
	ex.req = reqBody[:min(int64(len(reqBody)), p.cfg.MaxBody)]
	ex.call.Request.Body = makeBody(ex.req, int64(len(reqBody)), sha256Hex(reqBody), p.cfg.MaxBody)

	out := r.WithContext(context.WithValue(r.Context(), ctxKey{}, ex))
	out.Body = io.NopCloser(bytes.NewReader(reqBody))
	out.ContentLength = int64(len(reqBody))

	defer func() {
		// ReverseProxy panics with http.ErrAbortHandler when a copy fails
		// mid-response. Record the exchange before letting it propagate.
		v := recover()
		p.finish(ex, r.Context().Err() != nil)
		if v != nil {
			panic(v)
		}
	}()
	p.rp.ServeHTTP(w, out)
}

func newCall(r *http.Request, upstream *url.URL, received time.Time) *record.LLMCall {
	h := r.Header
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
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
	ex.sse = strings.HasPrefix(c.Response.ContentType, "text/event-stream")
	ex.resp = &capture{rc: resp.Body, h: sha256.New(), max: p.cfg.MaxBody}
	resp.Body = ex.resp
	return nil
}

func (p *Proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	ex := r.Context().Value(ctxKey{}).(*exchange)
	class := "upstream_unreachable"
	if r.Context().Err() != nil {
		class = "client_aborted"
	}
	ex.call.Error = &record.Error{Class: class, Message: err.Error()}
	ex.call.Response.Status = http.StatusBadGateway
	w.WriteHeader(http.StatusBadGateway)
}

func (p *Proxy) finish(ex *exchange, clientGone bool) {
	c := ex.call
	c.Timing.CompletedAt = time.Now().UTC()
	if r := ex.resp; r != nil {
		c.Timing.FirstByteAt = r.first
		c.Response.Body = makeBody(r.buf.Bytes(), r.n, hex.EncodeToString(r.h.Sum(nil)), p.cfg.MaxBody)
		outcome := record.StreamCompleted
		switch {
		case r.err != nil:
			outcome = record.StreamUpstreamError
			if c.Error == nil {
				c.Error = &record.Error{Class: "upstream_read", Message: r.err.Error()}
			}
		case !r.eof && clientGone:
			outcome = record.StreamClientAborted
			if c.Error == nil {
				c.Error = &record.Error{Class: "client_aborted", Message: "client disconnected before the response finished"}
			}
		}
		if ex.sse {
			c.Response.Stream = &record.Stream{Outcome: outcome}
		}
		if c.Error == nil && c.Response.Status >= 400 {
			c.Error = &record.Error{Class: "upstream_status", Message: http.StatusText(c.Response.Status)}
		}
	}
	if p.cfg.Sink != nil {
		var resp []byte
		if ex.resp != nil {
			resp = ex.resp.buf.Bytes()
		}
		p.cfg.Sink(Capture{Call: c, Req: ex.req, Resp: resp, SSE: ex.sse})
	}
}

// capture is the response body seen by ReverseProxy. It hashes and counts
// every byte, and keeps up to max bytes.
type capture struct {
	rc    io.ReadCloser
	h     hash.Hash
	buf   bytes.Buffer
	n     int64
	max   int64
	first time.Time
	eof   bool
	err   error
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
