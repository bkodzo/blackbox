// Command agent is a small tool-using agent for trying blackbox.
//
// It talks to any server that accepts chat-shaped requests (a messages array
// in, a choices array out) and gives the model three read-only tools that
// cannot see outside one directory. Point it at a blackbox gateway to watch
// its calls get recorded.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
)

func main() {
	var cfg config
	flag.StringVar(&cfg.URL, "url", "http://127.0.0.1:8080/v1/chat/completions", "chat completions endpoint (normally the blackbox gateway)")
	flag.StringVar(&cfg.Model, "model", "", "model name to request (required)")
	flag.StringVar(&cfg.Dir, "dir", ".", "directory the tools may read")
	flag.StringVar(&cfg.Session, "session", "", "session ID sent to blackbox (default: random)")
	flag.StringVar(&cfg.Agent, "agent", "demo-agent", "agent name sent to blackbox")
	flag.IntVar(&cfg.MaxTurns, "max-turns", 8, "stop after this many model calls")
	flag.BoolVar(&cfg.Forge, "forge", false, "after the first tool call, add a tool result the model never asked for (to see blackbox flag it)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: agent -model NAME [flags] TASK\n\nAPI key, if the server needs one, is read from AGENT_API_KEY.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	cfg.Task = strings.Join(flag.Args(), " ")
	cfg.APIKey = os.Getenv("AGENT_API_KEY")
	if cfg.Model == "" || cfg.Task == "" {
		flag.Usage()
		os.Exit(2)
	}
	if cfg.Session == "" {
		b := make([]byte, 4)
		rand.Read(b)
		cfg.Session = "demo-" + hex.EncodeToString(b)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, cfg, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}
