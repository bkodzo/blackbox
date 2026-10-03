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
	"log"
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
	cfgPath := fs.String("config", "", "JSON config file (flags override it)")
	fs.StringVar(&f.Listen, "listen", "", "address to listen on (default 127.0.0.1:8080)")
	fs.StringVar(&f.Upstream, "upstream", "", "base URL of the model server (required)")
	fs.StringVar(&f.Log, "log", "", "audit log file (default blackbox.jsonl)")
	fs.StringVar(&f.Checkpoints, "checkpoints", "", "checkpoint file (default blackbox.checkpoints.jsonl)")
	fs.StringVar(&f.Key, "key", "", "private signing key (default ~/.blackbox/key.ed25519)")
	fs.StringVar(&f.Risk, "risk", "", "risk map JSON file")
	fs.StringVar(&f.Sync, "sync", "", `"group" (batched fsync, default) or "always" (fsync every record)`)
	fs.Int64Var(&f.MaxBody, "max-body", 0, "bytes of each body to store (default 32 MiB); hashes always cover all bytes")
	fs.BoolVar(&f.MirrorCPs, "checkpoint-stdout", true, "also print each checkpoint to stdout")
	fs.Parse(args)

	cfg, err := loadConfig(*cfgPath, fs, &f)
	if err != nil {
		return fail("%v", err)
	}
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
	var riskBytes []byte
	if cfg.Risk != "" {
		if riskBytes, err = os.ReadFile(cfg.Risk); err != nil {
			return fail("%v", err)
		}
	}
	riskMap, err := risk.Load(cfg.Risk)
	if err != nil {
		return fail("%v", err)
	}

	opt := ledger.Options{Sync: cfg.Sync == "always", CheckpointPath: cfg.Checkpoints}
	if cfg.MirrorCPs {
		opt.CheckpointMirror = os.Stdout
	}
	l, err := ledger.Open(cfg.Log, key, opt)
	if err != nil {
		return fail("%v", err)
	}

	instance := randomID()
	start := record.GatewayStart{
		Type:             record.TypeGatewayStart,
		Time:             time.Now().UTC(),
		InstanceID:       instance,
		Version:          version,
		ConfigSHA256:     cfg.fingerprint(riskBytes),
		KeyFingerprint:   ledger.Fingerprint(key.Public().(ed25519.PublicKey)),
		Upstream:         upstream.String(),
		PreviousShutdown: previousShutdown(l),
		RecoveredBytes:   l.TornBytes(),
	}
	if err := appendJSON(l, start); err != nil {
		l.Close()
		return fail("writing gateway_start: %v", err)
	}
	if start.PreviousShutdown == "unclean" {
		log.Printf("warning: the previous gateway run did not shut down cleanly")
	}
	if start.RecoveredBytes > 0 {
		log.Printf("warning: removed %d bytes of an incomplete final log line", start.RecoveredBytes)
	}

	rec := recorder.New(l, instance, riskMap)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_blackbox/health", func(w http.ResponseWriter, r *http.Request) {
		last, _ := l.Last()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "instance_id": instance, "seq": last.Seq, "head": last.Hash})
	})
	mux.Handle("/", proxy.New(proxy.Config{Upstream: upstream, Sink: rec.Submit, MaxBody: cfg.MaxBody}))
	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Printf("blackbox %s listening on http://%s, forwarding to %s", version, cfg.Listen, upstream)
	log.Printf("log %s, key %s", cfg.Log, start.KeyFingerprint)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	code := 0
	select {
	case sig := <-stop:
		log.Printf("received %s, shutting down", sig)
	case err := <-errc:
		log.Printf("server error: %v", err)
		code = 1
	}

	// Let in-flight calls finish so they are recorded, then close the log.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	rec.Close()
	stopRec := record.GatewayStop{Type: record.TypeGatewayStop, Time: time.Now().UTC(), InstanceID: instance, Calls: rec.Calls()}
	if err := appendJSON(l, stopRec); err != nil {
		log.Printf("writing gateway_stop: %v", err)
		code = 1
	}
	if err := l.Close(); err != nil {
		log.Printf("closing log: %v", err)
		code = 1
	}
	log.Printf("recorded %d calls", rec.Calls())
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
