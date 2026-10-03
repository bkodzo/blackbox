package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
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
