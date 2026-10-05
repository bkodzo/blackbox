package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/proxy"
	"github.com/bkodzo/blackbox/internal/record"
	"github.com/bkodzo/blackbox/internal/recorder"
	"github.com/bkodzo/blackbox/internal/risk"
	"github.com/bkodzo/blackbox/internal/session"
)

func runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", keyDir(), "directory for the key pair")
	fs.Parse(args)

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return fail("%v", err)
	}
	priv, pub := filepath.Join(*dir, "key.ed25519"), filepath.Join(*dir, "key.pub")
	k, err := ledger.GenerateKey(priv, pub)
	if errors.Is(err, os.ErrExist) {
		return fail("a key already exists in %s; refusing to overwrite it", *dir)
	}
	if err != nil {
		return fail("%v", err)
	}
	fmt.Printf("Created signing key %s\n  private: %s (keep this secret)\n  public:  %s (give this to auditors)\n",
		ledger.Fingerprint(k), priv, pub)
	return 0
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var f config
	cfgPath := serveFlags(fs, &f)
	fs.Parse(args)

	cfg, err := loadConfig(*cfgPath, fs, &f)
	if err != nil {
		return fail("%v", err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fail("%v", err)
	}
	// A closed stdout must not kill the gateway: checkpoint lines written
	// there then fail with an error, which the ledger counts as dropped.
	signal.Ignore(syscall.SIGPIPE)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, cfg, ln, os.Stdout)
}

// serve runs the gateway on ln until ctx is done or the audit log fails.
// Checkpoint lines are mirrored to stdout if enabled.
func serve(ctx context.Context, cfg config, ln net.Listener, stdout io.Writer) int {
	defer ln.Close()
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		return fail("upstream %q is not an absolute URL", cfg.Upstream)
	}
	key, err := ledger.LoadPrivateKey(cfg.Key)
	if errors.Is(err, os.ErrNotExist) {
		return fail("no signing key at %s; run `blackbox init` first", cfg.Key)
	}
	if err != nil {
		return fail("%v", err)
	}
	// Read the risk map once, so the recorded fingerprint matches the rules in use.
	var riskBytes []byte
	riskMap := risk.Map{}
	if cfg.Risk != "" {
		if riskBytes, err = os.ReadFile(cfg.Risk); err != nil {
			return fail("%v", err)
		}
		if riskMap, err = risk.Parse(riskBytes, cfg.Risk); err != nil {
			return fail("%v", err)
		}
	}

	failed := make(chan error, 2)
	onFailure := func(err error) {
		select {
		case failed <- err:
		default:
		}
	}
	opt := ledger.Options{
		Sync:               cfg.Sync == "always",
		CheckpointPath:     cfg.Checkpoints,
		CheckpointRecords:  cfg.CheckpointEvery,
		CheckpointInterval: time.Duration(cfg.CheckpointAfter),
		OnFailure:          onFailure,
	}
	if cfg.MirrorCPs {
		opt.CheckpointMirror = stdout
	}
	l, err := ledger.Open(cfg.Log, key, opt)
	if err != nil {
		return fail("%v", err)
	}

	instance := randomID()
	recovery := l.Recovery()
	start := record.GatewayStart{
		Type:             record.TypeGatewayStart,
		Time:             time.Now().UTC(),
		InstanceID:       instance,
		Version:          version,
		ConfigSHA256:     cfg.fingerprint(riskBytes),
		KeyFingerprint:   ledger.Fingerprint(key.Public().(ed25519.PublicKey)),
		Upstream:         upstream.String(),
		PreviousShutdown: previousShutdown(l),
		RepairedSeq:      recovery.RepairedSeq,
		QuarantinedBytes: recovery.QuarantinedBytes,
		QuarantineFile:   recovery.QuarantineFile,
		QuarantineSHA256: recovery.QuarantineSHA256,

		CheckpointTornBytes: recovery.CheckpointTornBytes,
	}
	// gateway_start, with any recovery it describes, is on disk before the
	// first request is served.
	if err := appendJSON(l, start); err != nil {
		l.Close()
		return fail("writing gateway_start: %v", err)
	}
	if err := l.Sync(); err != nil {
		l.Close()
		return fail("writing gateway_start: %v", err)
	}
	if start.PreviousShutdown == "unclean" {
		log.Printf("warning: the previous gateway run did not shut down cleanly")
	}
	if start.QuarantinedBytes > 0 {
		log.Printf("warning: moved %d bytes of an incomplete final log line to %s", start.QuarantinedBytes, start.QuarantineFile)
	}
	if start.RepairedSeq > 0 {
		log.Printf("warning: entry %d was missing its final newline; added it", start.RepairedSeq)
	}

	sessions, replayed, err := recorder.Rebuild(cfg.Log, session.DefaultIdle)
	if err != nil {
		log.Printf("warning: could not restore recent conversations from the log (%v); checks start fresh", err)
	} else if replayed > 0 {
		log.Printf("restored %d recent calls for conversation checks", replayed)
	}

	rec := recorder.New(l, instance, recorder.Options{
		Risk:      riskMap,
		Sessions:  sessions,
		OnFailure: onFailure,
	})
	auditErr := func() error { return errors.Join(l.Err(), rec.Err()) }
	gate := func() error {
		if cfg.FailOpen {
			return nil
		}
		return auditErr()
	}
	px := proxy.New(proxy.Config{
		Upstream:        upstream,
		Sink:            rec.Submit,
		Gate:            gate,
		MaxBody:         cfg.MaxBody,
		MaxRequest:      cfg.MaxRequest,
		MaxInFlight:     cfg.MaxInFlight,
		StreamIdle:      time.Duration(cfg.StreamIdle),
		AllowUpgrades:   cfg.AllowUpgrades,
		BodyReadTimeout: time.Duration(cfg.BodyReadTimeout),
		UpstreamTimeout: time.Duration(cfg.UpstreamTimeout),
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /_blackbox/health", func(w http.ResponseWriter, r *http.Request) {
		last, _ := l.Last()
		body := map[string]any{"ok": true, "instance_id": instance, "seq": last.Seq, "head": last.Hash}
		w.Header().Set("Content-Type", "application/json")
		if auditErr() != nil {
			body["ok"], body["error"] = false, "audit log unavailable"
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(body)
	})
	mux.Handle("/", px)

	// Requests run under baseCtx, so calls still in flight when the grace
	// period ends can be cancelled and recorded as aborted.
	baseCtx, cancelBase := context.WithCancelCause(context.Background())
	defer cancelBase(nil)
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Printf("blackbox %s listening on http://%s, forwarding to %s", version, ln.Addr(), upstream)
	log.Printf("log %s, key %s", cfg.Log, start.KeyFingerprint)

	code := 0
	select {
	case <-ctx.Done():
		log.Printf("shutting down")
	case err := <-errc:
		log.Printf("server error: %v", err)
		code = 1
	case err := <-failed:
		code = 1
		if cfg.FailOpen {
			log.Printf("AUDIT LOG FAILED (%v); still forwarding because --fail-open is set", err)
			select {
			case <-ctx.Done():
			case err := <-errc:
				log.Printf("server error: %v", err)
			}
		} else {
			// Nothing more can be recorded, so calls in flight must not keep
			// streaming: cancel them now instead of waiting out the grace period.
			log.Printf("AUDIT LOG FAILED (%v); cancelling calls in flight and shutting down", err)
			cancelBase(proxy.ErrShutdown)
		}
	}

	// Stop accepting, give in-flight calls the grace period, then cancel the
	// rest. Every call, finished or cancelled, is recorded before the log closes.
	sctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ShutdownTimeout))
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		log.Printf("grace period ended with calls still in flight; cancelling them")
	}
	cancelBase(proxy.ErrShutdown)
	srv.Close() // closes connections Shutdown left open, so no request arrives late
	px.Close()  // refuses anything that still does, and waits for calls in flight
	rec.Close()

	stopRec := record.GatewayStop{
		Type: record.TypeGatewayStop, Time: time.Now().UTC(), InstanceID: instance,
		Calls: rec.Calls(), Unrecorded: rec.Unrecorded(), AbortedAtShutdown: px.Aborted(),
	}
	if auditErr() == nil {
		if err := appendJSON(l, stopRec); err != nil {
			log.Printf("writing gateway_stop: %v", err)
			code = 1
		}
	}
	if err := l.Close(); err != nil {
		log.Printf("closing log: %v", err)
		code = 1
	}
	if n := l.MirrorDropped(); n > 0 {
		log.Printf("warning: %d checkpoint lines could not be written to stdout", n)
	}
	log.Printf("recorded %d calls (%d unrecorded, %d cancelled at shutdown)", stopRec.Calls, stopRec.Unrecorded, stopRec.AbortedAtShutdown)
	return code
}

// previousShutdown reports whether the last run ended with a gateway_stop.
func previousShutdown(l *ledger.Ledger) string {
	last, ok := l.Last()
	if !ok {
		return "none"
	}
	var h struct {
		Type string `json:"type"`
	}
	json.Unmarshal(last.Rec, &h)
	if h.Type == record.TypeGatewayStop {
		return "clean"
	}
	return "unclean"
}

func appendJSON(l *ledger.Ledger, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, _, err = l.Append(b)
	return err
}

func randomID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
