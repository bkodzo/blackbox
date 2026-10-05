package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
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
		*cpPath = os.DevNull
	}
	cps, cpTorn, err := ledger.ReadCheckpoints(*cpPath)
	var cpErr *ledger.VerifyError
	if errors.As(err, &cpErr) {
		// A checkpoint line that does not parse was altered: that is a verdict,
		// not an I/O problem.
		fmt.Printf("Checkpoints:  %s\n\nResult: TAMPERED\n  %s\n", *cpPath, cpErr.Error())
		return exitTampered
	}
	if err != nil {
		return failCode(exitError, "%v", err)
	}
	f, err := os.Open(*logPath)
	if err != nil {
		return failCode(exitError, "%v", err)
	}
	defer f.Close()

	var (
		warnings []string
		calls    int
		running  bool   // a gateway_start has no matching gateway_stop yet
		lastType string // type of the last entry
	)
	res, err := ledger.Verify(f, pub, cps, func(e ledger.Entry) {
		var h struct {
			Type string `json:"type"`
		}
		json.Unmarshal(e.Rec, &h)
		lastType = h.Type
		switch h.Type {
		case record.TypeGatewayStart:
			if running {
				warnings = append(warnings, fmt.Sprintf(
					"seq %d: gateway started again without a clean shutdown before it; calls in flight at the time may be missing", e.Seq))
			}
			running = true
			var s record.GatewayStart
			json.Unmarshal(e.Rec, &s)
			if s.QuarantinedBytes > 0 {
				warnings = append(warnings, fmt.Sprintf(
					"seq %d: at startup the gateway moved %d bytes of an incomplete line to %s (sha256 %s)",
					e.Seq, s.QuarantinedBytes, s.QuarantineFile, s.QuarantineSHA256))
			}
			if s.CheckpointTornBytes > 0 {
				warnings = append(warnings, fmt.Sprintf(
					"seq %d: at startup the gateway removed %d bytes of an incomplete checkpoint line", e.Seq, s.CheckpointTornBytes))
			}
			if s.CheckpointsMissing {
				warnings = append(warnings, fmt.Sprintf(
					"seq %d: at startup the checkpoint file was missing and was created empty", e.Seq))
			}
			if s.RepairedSeq > 0 {
				warnings = append(warnings, fmt.Sprintf(
					"seq %d: at startup entry %d was missing its final newline; the gateway added it", e.Seq, s.RepairedSeq))
			}
		case record.TypeGatewayStop:
			running = false
		case record.TypeLLMCall:
			calls++
		}
	})

	fmt.Printf("Log:          %s\n", *logPath)
	fmt.Printf("Signing key:  %s\n", ledger.Fingerprint(pub))
	fmt.Printf("Entries:      %d checked (%d model calls)\n", res.Entries, calls)
	fmt.Printf("Checkpoints:  %d of %d matched\n", res.Checkpoints, res.CheckpointsTotal)

	var ve *ledger.VerifyError
	if errors.As(err, &ve) {
		fmt.Printf("\nResult: TAMPERED\n  %s\n", ve.Error())
		if res.Entries > 0 {
			fmt.Printf("  Entries 1 to %d were checked and are intact.\n", res.Entries)
		}
		return exitTampered
	}
	if err != nil {
		return failCode(exitError, "%v", err)
	}
	// A clean shutdown always writes a final checkpoint. A log that ends in
	// one with no checkpoint covering it has lost entries, and its checkpoint
	// file has been edited to match.
	if lastType == record.TypeGatewayStop && !*noCPs {
		var covered uint64
		for _, c := range cps {
			covered = max(covered, c.Seq)
		}
		if covered < res.Entries {
			fmt.Printf("\nResult: TAMPERED\n  the log ends with a clean shutdown (entry %d) that no checkpoint covers;\n"+
				"  entries were removed or the checkpoint file was edited\n", res.Entries)
			return exitTampered
		}
	}

	if res.TornBytes > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"the log ends in an incomplete line of %d bytes (an interrupted write); the gateway moves it to a quarantine file on next start",
			res.TornBytes))
	}
	if res.Unterminated {
		warnings = append(warnings, fmt.Sprintf(
			"entry %d is valid but missing its final newline; the gateway adds it on next start", res.Entries))
	}
	if cpTorn > 0 {
		warnings = append(warnings, "the checkpoint file ends in an incomplete line (an interrupted write); it was ignored")
	}
	if len(cps) == 0 {
		warnings = append(warnings, "no checkpoints found, so entries removed from the end of the log cannot be detected")
	}
	fmt.Printf("\nResult: INTACT\n  Every entry is unchanged, in order, and signed by this key.\n  Head: %s\n", res.Head)
	if running {
		fmt.Println("  The last gateway run has not shut down (it may still be running).")
	}
	if len(warnings) == 0 {
		return exitIntact
	}
	fmt.Println("\nWarnings:")
	for _, w := range warnings {
		fmt.Printf("  - %s\n", w)
	}
	return exitWarnings
}
