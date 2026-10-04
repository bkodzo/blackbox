package recorder

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/bkodzo/blackbox/internal/format"
	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
	"github.com/bkodzo/blackbox/internal/session"
)

// rebuildMargin widens the replay window: entries are written in completion
// order, so times are only roughly increasing through the file.
const rebuildMargin = 5 * time.Minute

// Rebuild replays calls from the last idle period of the log at path into a
// new session tracker, so conversation checks continue across a restart
// instead of starting blind. It finds where that period starts by searching
// the file, so the cost depends on recent traffic rather than the size of the
// log. It returns the tracker and the number of calls replayed.
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
	start, err := recentStart(f, cutoff.Add(-rebuildMargin))
	if err != nil {
		return t, 0, err
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return t, 0, err
	}

	n := 0
	err = ledger.Scan(f, func(e ledger.Entry) error {
		var c record.LLMCall
		if json.Unmarshal(e.Rec, &c) != nil || c.Type != record.TypeLLMCall || c.Timing.CompletedAt.Before(cutoff) {
			return nil
		}
		if c.Request.Body.Truncated || c.Response.Body.Truncated {
			// The stored history is incomplete; checking later turns against it
			// would raise false alarms. Treat the conversation as unseen.
			t.Forget(c.Session.ID)
			return nil
		}
		p := format.Parse(bodyBytes(c.Request.Body), bodyBytes(c.Response.Body), c.Response.Stream != nil)
		// Carry the error over, so failed calls are replayed as failed.
		scratch := record.LLMCall{Session: record.Session{ID: c.Session.ID}, Error: c.Error}
		t.CommitAt(t.Observe(&scratch, p), e.Seq, c.Timing.CompletedAt)
		n++
		return nil
	})
	return t, n, err
}

// recentStart returns the offset of a line at or before the first entry
// completed after cutoff, found by binary search over the file.
func recentStart(f *os.File, cutoff time.Time) (int64, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	lo, hi := int64(0), st.Size() // the answer is in [lo, hi]
	for hi-lo > 64<<10 {
		mid := lo + (hi-lo)/2
		start, ts, ok, err := lineAfter(f, mid)
		if err != nil {
			return 0, err
		}
		if !ok || start >= hi {
			hi = mid
			continue
		}
		if ts.Before(cutoff) {
			lo = start
		} else {
			hi = mid
		}
	}
	return lineStart(f, lo)
}

// lineStart returns the offset of the first line that starts at or after off.
func lineStart(f *os.File, off int64) (int64, error) {
	if off == 0 {
		return 0, nil
	}
	br := bufio.NewReader(io.NewSectionReader(f, off-1, 1<<62))
	skipped, err := br.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return 0, err
	}
	return off - 1 + int64(len(skipped)), nil
}

// lineAfter reads the first line starting at or after off and returns where
// it starts and the time it records.
func lineAfter(f *os.File, off int64) (start int64, ts time.Time, ok bool, err error) {
	if start, err = lineStart(f, off); err != nil {
		return 0, time.Time{}, false, err
	}
	line, err := bufio.NewReader(io.NewSectionReader(f, start, 1<<62)).ReadBytes('\n')
	if err != nil && err != io.EOF {
		return 0, time.Time{}, false, err
	}
	ts, ok = entryTime(line)
	return start, ts, ok, nil
}

// entryTime extracts a record's completion time, or its timestamp for
// gateway events, without decoding the whole record. Quotes inside stored
// bodies are escaped, so these patterns only match real fields; the timing
// object is the last field of a call record.
func entryTime(line []byte) (time.Time, bool) {
	for _, key := range [][]byte{[]byte(`"completed_at":"`), []byte(`"ts":"`)} {
		i := bytes.LastIndex(line, key)
		if i < 0 {
			continue
		}
		rest := line[i+len(key):]
		j := bytes.IndexByte(rest, '"')
		if j < 0 {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, string(rest[:j])); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

func bodyBytes(b record.Body) []byte {
	if b.Base64 != "" {
		raw, _ := base64.StdEncoding.DecodeString(b.Base64)
		return raw
	}
	return []byte(b.Text)
}
