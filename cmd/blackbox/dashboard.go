package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/bkodzo/blackbox/internal/dashboard"
	"github.com/bkodzo/blackbox/internal/ledger"
)

// hostList collects repeated --allow-host flags.
type hostList []string

func (h *hostList) String() string { return strings.Join(*h, ",") }

func (h *hostList) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*h = append(*h, s)
		}
	}
	return nil
}

func runDashboard(args []string) int {
	fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
	logPath := fs.String("log", "blackbox.jsonl", "audit log file")
	cpPath := fs.String("checkpoints", "blackbox.checkpoints.jsonl", "checkpoint file")
	pubPath := fs.String("pub", filepath.Join(keyDir(), "key.pub"), "gateway public key")
	noCPs := fs.Bool("no-checkpoints", false, "check without a checkpoint file (removals from the end cannot be detected)")
	listen := fs.String("listen", "127.0.0.1:8090", "address to serve the dashboard on")
	export := fs.String("export", "", "write every page to this directory as static files, then exit")
	var hosts hostList
	fs.Var(&hosts, "allow-host", "host name or address the dashboard may be reached under, besides localhost (repeatable)")
	fs.Parse(args)
	if fs.NArg() > 0 {
		return fail("unexpected argument %q", fs.Arg(0))
	}

	pub, err := ledger.LoadPublicKey(*pubPath)
	if err != nil {
		return fail("%v", err)
	}
	if *noCPs {
		*cpPath = ""
	} else if _, err := os.Stat(*cpPath); errors.Is(err, os.ErrNotExist) {
		return fail("no checkpoint file at %s; pass --checkpoints with its location, or --no-checkpoints to check without one", *cpPath)
	}
	s, err := dashboard.New(dashboard.Config{Log: *logPath, Checkpoints: *cpPath, Pub: pub, AllowedHosts: hosts})
	if err != nil {
		return fail("%v", err)
	}
	if *export != "" {
		n, err := s.Export(*export)
		if err != nil {
			return fail("%v", err)
		}
		log.Printf("wrote %d files to %s", n, *export)
		return 0
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fail("%v", err)
	}
	log.Printf("dashboard for %s on http://%s", *logPath, ln.Addr())
	if host, _, _ := net.SplitHostPort(*listen); !isLoopback(host) {
		log.Printf("warning: the dashboard has no login, and the log holds every prompt and response; " +
			"anyone who can reach this address can read them. Put it behind your own access control")
		if len(hosts) == 0 {
			log.Printf("note: only requests addressed to localhost are answered; pass --allow-host with the name or address people will use")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := s.Serve(ctx, ln); err != nil {
		return fail("%v", err)
	}
	return 0
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
