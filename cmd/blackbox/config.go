package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// duration is a time.Duration written as a string such as "30s" in JSON and
// on the command line.
type duration time.Duration

func (d duration) String() string { return time.Duration(d).String() }

func (d *duration) Set(s string) error {
	v, err := time.ParseDuration(s)
	*d = duration(v)
	return err
}

func (d duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`durations are strings such as "30s"`)
	}
	return d.Set(s)
}

// config holds every setting `blackbox serve` uses. It can come from a JSON
// file, flags, or both; flags win.
type config struct {
	Listen          string   `json:"listen"`
	Upstream        string   `json:"upstream"`
	Log             string   `json:"log"`
	Checkpoints     string   `json:"checkpoints"`
	Key             string   `json:"key"`
	Risk            string   `json:"risk_map"`
	Sync            string   `json:"sync"` // "group" or "always"
	MaxBody         int64    `json:"max_body_bytes"`
	MaxRequest      int64    `json:"max_request_bytes"`
	MirrorCPs       bool     `json:"checkpoint_stdout"`
	FailOpen        bool     `json:"fail_open"`
	BodyReadTimeout duration `json:"body_read_timeout"`
	UpstreamTimeout duration `json:"upstream_timeout"`
	ShutdownTimeout duration `json:"shutdown_timeout"`
}

func defaultConfig() config {
	return config{
		Listen:          "127.0.0.1:8080",
		Log:             "blackbox.jsonl",
		Checkpoints:     "blackbox.checkpoints.jsonl",
		Key:             filepath.Join(keyDir(), "key.ed25519"),
		Sync:            "group",
		MaxBody:         32 << 20,
		MaxRequest:      64 << 20,
		MirrorCPs:       true,
		BodyReadTimeout: duration(time.Minute),
		UpstreamTimeout: duration(10 * time.Minute),
		ShutdownTimeout: duration(30 * time.Second),
	}
}

func keyDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".blackbox"
	}
	return filepath.Join(home, ".blackbox")
}

// serveFlags registers the serve flags on fs, writing into f.
func serveFlags(fs *flag.FlagSet, f *config) *string {
	cfgPath := fs.String("config", "", "JSON config file (flags override it)")
	fs.StringVar(&f.Listen, "listen", "", "address to listen on (default 127.0.0.1:8080)")
	fs.StringVar(&f.Upstream, "upstream", "", "base URL of the model server (required)")
	fs.StringVar(&f.Log, "log", "", "audit log file (default blackbox.jsonl)")
	fs.StringVar(&f.Checkpoints, "checkpoints", "", "checkpoint file (default blackbox.checkpoints.jsonl)")
	fs.StringVar(&f.Key, "key", "", "private signing key (default ~/.blackbox/key.ed25519)")
	fs.StringVar(&f.Risk, "risk", "", "risk map JSON file")
	fs.StringVar(&f.Sync, "sync", "", `"group" (batched fsync, default) or "always" (fsync every record)`)
	fs.Int64Var(&f.MaxBody, "max-body", 0, "bytes of each body to store (default 32 MiB); hashes always cover all bytes")
	fs.Int64Var(&f.MaxRequest, "max-request", 0, "largest request accepted (default 64 MiB); larger ones get 413")
	fs.BoolVar(&f.MirrorCPs, "checkpoint-stdout", true, "also print each checkpoint to stdout")
	fs.BoolVar(&f.FailOpen, "fail-open", false, "keep forwarding traffic if the audit log fails (default: refuse with 503 and exit)")
	fs.Var(&f.BodyReadTimeout, "body-read-timeout", "limit for reading a request body (default 1m)")
	fs.Var(&f.UpstreamTimeout, "upstream-timeout", "limit for the model server to start responding (default 10m)")
	fs.Var(&f.ShutdownTimeout, "shutdown-timeout", "grace period for in-flight calls at shutdown (default 30s)")
	return cfgPath
}

// loadConfig applies defaults, then the JSON file at path (if any), then the
// flags that were set explicitly on fs.
func loadConfig(path string, fs *flag.FlagSet, flags *config) (config, error) {
	c := defaultConfig()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return c, err
		}
		if err := checkKeys(b); err != nil {
			return c, fmt.Errorf("%s: %w", path, err)
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields() // a misspelled setting must not be silently ignored
		if err := dec.Decode(&c); err != nil {
			return c, fmt.Errorf("%s: %w", path, err)
		}
		if dec.More() {
			return c, fmt.Errorf("%s: unexpected data after the configuration object", path)
		}
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "listen":
			c.Listen = flags.Listen
		case "upstream":
			c.Upstream = flags.Upstream
		case "log":
			c.Log = flags.Log
		case "checkpoints":
			c.Checkpoints = flags.Checkpoints
		case "key":
			c.Key = flags.Key
		case "risk":
			c.Risk = flags.Risk
		case "sync":
			c.Sync = flags.Sync
		case "max-body":
			c.MaxBody = flags.MaxBody
		case "max-request":
			c.MaxRequest = flags.MaxRequest
		case "checkpoint-stdout":
			c.MirrorCPs = flags.MirrorCPs
		case "fail-open":
			c.FailOpen = flags.FailOpen
		case "body-read-timeout":
			c.BodyReadTimeout = flags.BodyReadTimeout
		case "upstream-timeout":
			c.UpstreamTimeout = flags.UpstreamTimeout
		case "shutdown-timeout":
			c.ShutdownTimeout = flags.ShutdownTimeout
		}
	})
	switch {
	case c.Upstream == "":
		return c, errors.New("an upstream is required, e.g. --upstream http://127.0.0.1:9000")
	case c.Checkpoints == "":
		return c, errors.New("a checkpoint file is required: without one, entries removed from the end of the log cannot be detected")
	case c.Sync != "group" && c.Sync != "always":
		return c, errors.New(`sync must be "group" or "always"`)
	case c.MaxBody <= 0 || c.MaxRequest <= 0:
		return c, errors.New("body and request limits must be positive")
	case c.BodyReadTimeout <= 0 || c.UpstreamTimeout <= 0 || c.ShutdownTimeout <= 0:
		return c, errors.New("timeouts must be positive")
	}
	return c, nil
}

// checkKeys rejects configuration keys that are not spelled exactly as
// documented, or that appear twice. encoding/json alone would accept
// "FAIL_OPEN" for "fail_open" and keep only the last of duplicate keys.
func checkKeys(b []byte) error {
	known := map[string]bool{}
	t := reflect.TypeFor[config]()
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		known[name] = true
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("the configuration must be a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key := tok.(string)
		switch {
		case !known[key]:
			return fmt.Errorf("unknown setting %q", key)
		case seen[key]:
			return fmt.Errorf("setting %q appears more than once", key)
		}
		seen[key] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}

// fingerprint hashes the effective configuration together with the risk map
// contents, so the log records exactly which settings were in force.
func (c config) fingerprint(riskBytes []byte) string {
	h := sha256.New()
	json.NewEncoder(h).Encode(c)
	h.Write(riskBytes)
	return hex.EncodeToString(h.Sum(nil))
}
