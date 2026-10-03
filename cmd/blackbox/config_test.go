package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func parse(t *testing.T, file string, args ...string) (config, error) {
	t.Helper()
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var f config
	fs.StringVar(&f.Listen, "listen", "", "")
	fs.StringVar(&f.Upstream, "upstream", "", "")
	fs.StringVar(&f.Sync, "sync", "", "")
	fs.BoolVar(&f.MirrorCPs, "checkpoint-stdout", true, "")
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return loadConfig(file, fs, &f)
}

func TestFlagsOverrideFileOverrideDefaults(t *testing.T) {
	file := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(file, []byte(`{"upstream":"http://file:1","listen":"127.0.0.1:7000","sync":"always"}`), 0o600)

	c, err := parse(t, file, "--listen", "127.0.0.1:9000", "--checkpoint-stdout=false")
	if err != nil {
		t.Fatal(err)
	}
	if c.Upstream != "http://file:1" || c.Listen != "127.0.0.1:9000" || c.Sync != "always" || c.MirrorCPs {
		t.Fatalf("config %+v", c)
	}
	if c.Log != "blackbox.jsonl" {
		t.Fatalf("default log not applied: %q", c.Log)
	}
}

func TestUpstreamRequired(t *testing.T) {
	if _, err := parse(t, ""); err == nil {
		t.Fatal("accepted a config with no upstream")
	}
}

func TestRejectsBadSync(t *testing.T) {
	if _, err := parse(t, "", "--upstream", "http://x:1", "--sync", "sometimes"); err == nil {
		t.Fatal("accepted an invalid sync mode")
	}
}

func TestFingerprintCoversRiskMap(t *testing.T) {
	c := defaultConfig()
	if c.fingerprint([]byte(`{"a":{"risk":"low"}}`)) == c.fingerprint([]byte(`{"a":{"risk":"high"}}`)) {
		t.Fatal("changing the risk map did not change the config fingerprint")
	}
}

func TestRejectsUnknownConfigField(t *testing.T) {
	file := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(file, []byte(`{"upstream":"http://x:1","risk":"risk.json"}`), 0o600)
	if _, err := parse(t, file); err == nil || !strings.Contains(err.Error(), "risk") {
		t.Fatalf("a misspelled field was accepted: %v", err)
	}
}

func TestDurationsParseFromJSON(t *testing.T) {
	file := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(file, []byte(`{"upstream":"http://x:1","shutdown_timeout":"5s"}`), 0o600)
	c, err := parse(t, file)
	if err != nil || time.Duration(c.ShutdownTimeout) != 5*time.Second {
		t.Fatalf("config %+v err %v", c, err)
	}
}
