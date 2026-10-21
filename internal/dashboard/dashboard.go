// Package dashboard serves a read-only web view of a log for auditors,
// managers, and security officers. It never writes to the log, and it
// reaches its integrity verdict with the same code as `blackbox verify`.
package dashboard

import (
	"context"
	"crypto/ed25519"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bkodzo/blackbox/internal/audit"
	"github.com/bkodzo/blackbox/internal/index"
)

//go:embed templates static
var files embed.FS

// Config describes what the dashboard shows and who may reach it.
type Config struct {
	Log         string
	Checkpoints string // "" to check without a checkpoint file
	Pub         ed25519.PublicKey
	// AllowedHosts are host names, besides localhost and loopback addresses,
	// that requests may name in their Host header. Requests naming any other
	// host are refused, so a web page on another site cannot reach the
	// dashboard by pointing its own domain at this machine.
	AllowedHosts []string
	// Refresh is how often the log is checked for new entries.
	Refresh time.Duration
}

// Server is the dashboard's HTTP handler.
type Server struct {
	cfg   Config
	idx   *index.Index
	pages map[string]*template.Template
	mux   *http.ServeMux
	hosts map[string]bool

	mu        sync.Mutex
	report    *audit.Report // the latest completed check, or nil
	reportErr error         // why the latest check reached no verdict
	checkedAt int           // entries indexed when the latest check started
	running   chan struct{} // closed when the check in progress ends; nil when idle
}

// New indexes the log and prepares the pages.
func New(cfg Config) (*Server, error) {
	if cfg.Refresh <= 0 {
		cfg.Refresh = time.Second
	}
	idx, err := index.Open(cfg.Log)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, idx: idx, mux: http.NewServeMux(), hosts: map[string]bool{"localhost": true}}
	for _, h := range cfg.AllowedHosts {
		s.hosts[normalHost(h)] = true
	}
	if s.pages, err = parsePages(); err != nil {
		return nil, err
	}
	static, _ := fs.Sub(files, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	s.routes()
	return s, nil
}

// Run follows the log until ctx is done, and checks it once at the start.
func (s *Server) Run(ctx context.Context) {
	s.startCheck()
	t := time.NewTicker(s.cfg.Refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.idx.Refresh(); err != nil {
				log.Printf("reading %s: %v", s.cfg.Log, err)
			}
		}
	}
}

// startCheck starts verifying the log unless a check is already running,
// and returns a channel closed when the running check ends.
func (s *Server) startCheck() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running != nil {
		return s.running
	}
	done := make(chan struct{})
	s.running = done
	entries := s.idx.Len()
	go func() {
		rep, err := audit.Check(s.cfg.Log, s.cfg.Checkpoints, s.cfg.Pub)
		s.mu.Lock()
		if err != nil {
			s.report, s.reportErr = nil, err
		} else {
			s.report, s.reportErr = &rep, nil
		}
		s.checkedAt = entries
		s.running = nil
		s.mu.Unlock()
		close(done)
	}()
	return done
}

// integrity is what pages show about the latest check.
type integrity struct {
	Report   *audit.Report
	Err      error
	Checking bool
	NewSince int // entries added since the latest check started
}

func (s *Server) integrity() integrity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return integrity{Report: s.report, Err: s.reportErr, Checking: s.running != nil, NewSince: max(0, s.idx.Len()-s.checkedAt)}
}

// ServeHTTP applies the security rules shared by every page.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	if !s.allowedHost(r.Host) {
		http.Error(w, "this dashboard is not served under that host name", http.StatusMisdirectedRequest)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
		http.Error(w, "request not sent from the dashboard", http.StatusForbidden)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) allowedHost(hostport string) bool {
	host := normalHost(hostport)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return s.hosts[host]
}

// normalHost reduces a host, with or without a port, to the form compared:
// lower case, without brackets or a trailing dot.
func normalHost(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
}

// sameOrigin reports whether a request that acts came from a dashboard page.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

// Serve serves the dashboard on ln until ctx is done.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute, // a large call body can take a while on a slow link
		IdleTimeout:       2 * time.Minute,
	}
	go s.Run(ctx)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
}
