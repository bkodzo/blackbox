// Package audit decides whether a log can be trusted. It is shared by
// `blackbox verify` and the dashboard, so the two always reach the same
// verdict.
package audit

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
)

// Verdict is the outcome of a check.
type Verdict int

const (
	Intact   Verdict = iota // every entry is unchanged, in order, and signed
	Warnings                // intact, with something worth a look
	Tampered                // the log or its checkpoints were altered
)

func (v Verdict) String() string {
	switch v {
	case Intact:
		return "intact"
	case Warnings:
		return "intact with warnings"
	}
	return "tampered"
}

// Report is the result of a check.
type Report struct {
	Log         string
	Checkpoints string // "" when checked without a checkpoint file
	Key         string // fingerprint of the public key
	Verdict     Verdict
	// Problem says where and how the log was altered, when Tampered.
	Problem string
	// CheckpointsBad is set when the checkpoint file itself was altered, so
	// the log was not read.
	CheckpointsBad bool
	Result         ledger.Result
	Calls          int
	Running        bool // the last gateway run has not shut down
	// Opened is set once the log was opened, so Result and Calls describe
	// what was read even when reading it then failed.
	Opened    bool
	Warnings  []string
	CheckedAt time.Time
}

// Check verifies the log at logPath against pub and the checkpoints at
// cpPath. Pass cpPath "" to check without checkpoints, in which case entries
// removed from the end cannot be detected. An error means no verdict was
// reached, for example because a file could not be read.
func Check(logPath, cpPath string, pub ed25519.PublicKey) (Report, error) {
	rep := Report{Log: logPath, Checkpoints: cpPath, Key: ledger.Fingerprint(pub), CheckedAt: time.Now()}
	var cps []ledger.Checkpoint
	var cpTorn int64
	if cpPath != "" {
		if _, err := os.Stat(cpPath); err != nil {
			return rep, err
		}
		var err error
		cps, cpTorn, err = ledger.ReadCheckpoints(cpPath)
		var cpErr *ledger.VerifyError
		if errors.As(err, &cpErr) {
			// A checkpoint line that does not parse was altered: that is a
			// verdict, not an I/O problem.
			rep.Verdict, rep.Problem, rep.CheckpointsBad = Tampered, cpErr.Error(), true
			return rep, nil
		}
		if err != nil {
			return rep, err
		}
	}
	f, err := os.Open(logPath)
	if err != nil {
		return rep, err
	}
	defer f.Close()
	rep.Opened = true

	var lastType string
	res, err := ledger.Verify(f, pub, cps, func(e ledger.Entry) {
		var h struct {
			Type string `json:"type"`
		}
		json.Unmarshal(e.Rec, &h)
		lastType = h.Type
		switch h.Type {
		case record.TypeGatewayStart:
			if rep.Running {
				rep.warn("seq %d: gateway started again without a clean shutdown before it; calls in flight at the time may be missing", e.Seq)
			}
			rep.Running = true
			var s record.GatewayStart
			json.Unmarshal(e.Rec, &s)
			startWarnings(&rep, e.Seq, s)
		case record.TypeGatewayStop:
			rep.Running = false
		case record.TypeLLMCall:
			rep.Calls++
		}
	})
	rep.Result = res
	var ve *ledger.VerifyError
	if errors.As(err, &ve) {
		rep.Verdict, rep.Problem = Tampered, ve.Error()
		return rep, nil
	}
	if err != nil {
		return rep, err
	}

	// A clean shutdown writes a final checkpoint after gateway_stop, so a log
	// that ends in one with no checkpoint covering it is worth a look. It is
	// not proof of tampering: a crash between the two writes, or a checkpoint
	// copy that is behind (such as one collected from stdout), looks the same.
	// An attacker who cut the log back to an earlier run's end would keep
	// that run's checkpoint, and only a copy kept elsewhere reveals that.
	if lastType == record.TypeGatewayStop && len(cps) > 0 {
		var covered uint64
		for _, c := range cps {
			covered = max(covered, c.Seq)
		}
		if covered < res.Entries {
			rep.warn("the log ends with a clean shutdown (entry %d), but the newest checkpoint here covers entry %d; "+
				"the gateway stopped while writing its final checkpoint, this copy of the checkpoints is behind, "+
				"or checkpoints were removed. Compare with the copy kept elsewhere", res.Entries, covered)
		}
	}
	if res.TornBytes > 0 {
		rep.warn("the log ends in an incomplete line of %d bytes (an interrupted write); the gateway moves it to a quarantine file on next start",
			res.TornBytes)
	}
	if res.Unterminated {
		rep.warn("entry %d is valid but missing its final newline; the gateway adds it on next start", res.Entries)
	}
	if cpTorn > 0 {
		rep.warn("the checkpoint file ends in an incomplete line (an interrupted write); it was ignored")
	}
	if len(cps) == 0 {
		rep.warn("no checkpoints found, so entries removed from the end of the log cannot be detected")
	}
	if len(rep.Warnings) > 0 {
		rep.Verdict = Warnings
	}
	return rep, nil
}

func startWarnings(rep *Report, seq uint64, s record.GatewayStart) {
	if s.QuarantinedBytes > 0 {
		rep.warn("seq %d: at startup the gateway moved %d bytes of an incomplete line to %s (sha256 %s)",
			seq, s.QuarantinedBytes, s.QuarantineFile, s.QuarantineSHA256)
	}
	if s.CheckpointTornBytes > 0 {
		rep.warn("seq %d: at startup the gateway removed %d bytes of an incomplete checkpoint line", seq, s.CheckpointTornBytes)
	}
	if s.CheckpointsMissing {
		rep.warn("seq %d: at startup the checkpoint file was missing and was created empty", seq)
	}
	if s.CheckpointsEmpty {
		rep.warn("seq %d: at startup the checkpoint file had no checkpoints although the log had entries "+
			"(it was emptied, or the run before stopped before writing its first one)", seq)
	}
	if s.RepairedSeq > 0 {
		rep.warn("seq %d: at startup entry %d was missing its final newline; the gateway added it", seq, s.RepairedSeq)
	}
}

func (r *Report) warn(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}
