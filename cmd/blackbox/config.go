package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// config holds every setting `blackbox serve` uses. It can come from a JSON
// file, flags, or both; flags win.
type config struct {
	Listen      string `json:"listen"`
	Upstream    string `json:"upstream"`
	Log         string `json:"log"`
	Checkpoints string `json:"checkpoints"`
	Key         string `json:"key"`
	Risk        string `json:"risk_map"`
	Sync        string `json:"sync"` // "group" or "always"
	MaxBody     int64  `json:"max_body_bytes"`
	MirrorCPs   bool   `json:"checkpoint_stdout"`
}

func defaultConfig() config {
	return config{
		Listen:      "127.0.0.1:8080",
		Log:         "blackbox.jsonl",
		Checkpoints: "blackbox.checkpoints.jsonl",
		Key:         filepath.Join(keyDir(), "key.ed25519"),
		Sync:        "group",
		MaxBody:     32 << 20,
		MirrorCPs:   true,
	}
}

func keyDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".blackbox"
	}
	return filepath.Join(home, ".blackbox")
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
		if err := json.Unmarshal(b, &c); err != nil {
			return c, fmt.Errorf("%s: %w", path, err)
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
		case "checkpoint-stdout":
			c.MirrorCPs = flags.MirrorCPs
		}
	})
	switch {
	case c.Upstream == "":
		return c, errors.New("an upstream is required, e.g. --upstream http://127.0.0.1:9000")
	case c.Sync != "group" && c.Sync != "always":
		return c, errors.New(`sync must be "group" or "always"`)
	case c.MaxBody <= 0:
		return c, errors.New("max body bytes must be positive")
	}
	return c, nil
}

// fingerprint hashes the effective configuration together with the risk map
// contents, so the log records exactly which settings were in force.
func (c config) fingerprint(riskBytes []byte) string {
	h := sha256.New()
	json.NewEncoder(h).Encode(c)
	h.Write(riskBytes)
	return hex.EncodeToString(h.Sum(nil))
}
