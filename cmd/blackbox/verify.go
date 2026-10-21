package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bkodzo/blackbox/internal/audit"
	"github.com/bkodzo/blackbox/internal/ledger"
)

// Exit codes for verify. Each outcome has its own code so scripts and CI
// never mistake a typo or a missing file for a verdict about the log.
const (
	exitIntact   = 0
	exitTampered = 1
	exitWarnings = 2
	exitError    = 3 // usage or I/O error: no verdict was reached
)

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	logPath := fs.String("log", "blackbox.jsonl", "audit log file")
	cpPath := fs.String("checkpoints", "blackbox.checkpoints.jsonl", "checkpoint file")
	pubPath := fs.String("pub", filepath.Join(keyDir(), "key.pub"), "gateway public key")
	noCPs := fs.Bool("no-checkpoints", false, "verify without a checkpoint file (removals from the end cannot be detected)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "usage: blackbox verify [flags]\n\nExit codes: 0 intact, 1 tampered, 2 intact with warnings, 3 usage or I/O error.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitIntact
		}
		return exitError
	}
	if fs.NArg() > 0 {
		return failCode(exitError, "unexpected argument %q", fs.Arg(0))
	}

	pub, err := ledger.LoadPublicKey(*pubPath)
	if err != nil {
		return failCode(exitError, "%v", err)
	}
	if _, err := os.Stat(*cpPath); errors.Is(err, os.ErrNotExist) && !*noCPs {
		return failCode(exitError, "no checkpoint file at %s; pass --checkpoints with its location, or --no-checkpoints to verify without one", *cpPath)
	}
	if *noCPs {
		*cpPath = ""
	}
	rep, err := audit.Check(*logPath, *cpPath, pub)
	if err != nil && !rep.Opened {
		return failCode(exitError, "%v", err)
	}
	if rep.CheckpointsBad {
		// The checkpoint file was altered, so the log was not read.
		fmt.Printf("Checkpoints:  %s\n\nResult: TAMPERED\n  %s\n", *cpPath, rep.Problem)
		return exitTampered
	}

	res := rep.Result
	fmt.Printf("Log:          %s\n", *logPath)
	fmt.Printf("Signing key:  %s\n", rep.Key)
	fmt.Printf("Entries:      %d checked (%d model calls)\n", res.Entries, rep.Calls)
	fmt.Printf("Checkpoints:  %d of %d matched\n", res.Checkpoints, res.CheckpointsTotal)
	if err != nil {
		return failCode(exitError, "%v", err)
	}

	if rep.Verdict == audit.Tampered {
		fmt.Printf("\nResult: TAMPERED\n  %s\n", rep.Problem)
		if res.Entries > 0 {
			fmt.Printf("  Entries 1 to %d were checked and are intact.\n", res.Entries)
		}
		return exitTampered
	}
	fmt.Printf("\nResult: INTACT\n  Every entry is unchanged, in order, and signed by this key.\n  Head: %s\n", res.Head)
	if rep.Running {
		fmt.Println("  The last gateway run has not shut down (it may still be running).")
	}
	if rep.Verdict == audit.Intact {
		return exitIntact
	}
	fmt.Println("\nWarnings:")
	for _, w := range rep.Warnings {
		fmt.Printf("  - %s\n", w)
	}
	return exitWarnings
}
