package recorder

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/bkodzo/blackbox/internal/format"
	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
	"github.com/bkodzo/blackbox/internal/session"
)

// Rebuild replays calls from the last idle period of the log at path into a
// new session tracker, so conversation checks continue across a restart
// instead of starting blind. It returns the tracker and the number of calls
// replayed.
func Rebuild(path string, idle time.Duration) (*session.Tracker, int, error) {
	t := session.New(idle)
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return t, 0, nil
	}
	if err != nil {
		return t, 0, err
	}
	defer f.Close()

	cutoff := time.Now().Add(-idle)
	n := 0
	err = ledger.Scan(f, func(e ledger.Entry) error {
		var h struct {
			Type   string `json:"type"`
			Timing struct {
				CompletedAt time.Time `json:"completed_at"`
			} `json:"timing"`
		}
		if json.Unmarshal(e.Rec, &h) != nil || h.Type != record.TypeLLMCall || h.Timing.CompletedAt.Before(cutoff) {
			return nil
		}
		var c record.LLMCall
		if err := json.Unmarshal(e.Rec, &c); err != nil {
			return nil
		}
		p := format.Parse(bodyBytes(c.Request.Body), bodyBytes(c.Response.Body), c.Response.Stream != nil)
		scratch := record.LLMCall{Session: record.Session{ID: c.Session.ID}}
		t.CommitAt(t.Observe(&scratch, p), e.Seq, c.Timing.CompletedAt)
		n++
		return nil
	})
	return t, n, err
}

func bodyBytes(b record.Body) []byte {
	if b.Base64 != "" {
		raw, _ := base64.StdEncoding.DecodeString(b.Base64)
		return raw
	}
	return []byte(b.Text)
}
