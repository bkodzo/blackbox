package index

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
)

type fixture struct {
	path string
	l    *ledger.Ledger
	t0   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	_, key, _ := ed25519.GenerateKey(nil)
	path := filepath.Join(dir, "log.jsonl")
	l, err := ledger.Open(path, key, ledger.Options{CheckpointPath: filepath.Join(dir, "cp.jsonl"), Sync: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return &fixture{path: path, l: l, t0: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)}
}

func (f *fixture) append(t *testing.T, rec any) {
	t.Helper()
	b, _ := json.Marshal(rec)
	if _, _, err := f.l.Append(b); err != nil {
		t.Fatal(err)
	}
}

// call appends a model call in the given session (or conversation, when the
// session starts with "c:") n minutes after the fixture's start.
func (f *fixture) call(t *testing.T, session string, n int, flags ...string) {
	t.Helper()
	c := record.LLMCall{Type: record.TypeLLMCall, InstanceID: "i1", Agent: record.Agent{ID: "agent-1"}, Principal: "alice"}
	if conv, ok := strings.CutPrefix(session, "c:"); ok {
		c.Session.Conversation = conv
	} else {
		c.Session.ID = session
	}
	c.Request.ModelRequested = "m"
	c.Response.Status = 200
	c.Response.Usage = record.Usage{Input: 10, Output: 2}
	c.Response.ToolCalls = []record.ToolCall{{Name: "read_file", Risk: "low"}}
	c.Response.Body.Text = strings.Repeat("x", 1000) // bodies are not kept in the index
	for _, k := range flags {
		c.Anomalies = append(c.Anomalies, record.Anomaly{Kind: k, Detail: "d"})
	}
	c.Timing.ReceivedAt = f.t0.Add(time.Duration(n) * time.Minute)
	c.Timing.CompletedAt = c.Timing.ReceivedAt.Add(time.Second)
	f.append(t, c)
}

func TestSummariesAndSessions(t *testing.T) {
	f := newFixture(t)
	f.append(t, record.GatewayStart{Type: record.TypeGatewayStart, Time: f.t0, InstanceID: "i1"})
	f.call(t, "run-1", 1)
	f.call(t, "run-2", 2, record.AnomalyOrphanToolResult)
	f.call(t, "run-1", 3)
	f.call(t, "c:abcd", 4)
	f.call(t, "", 5)

	x, err := Open(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if x.Len() != 6 {
		t.Fatalf("indexed %d entries, want 6", x.Len())
	}
	ss := x.Sessions()
	var names []string
	for _, s := range ss {
		names = append(names, s.Name())
	}
	if got := strings.Join(names, ","); got != "(no session),conversation abcd,run-1,run-2" {
		t.Fatalf("sessions, most recent first: %s", got)
	}
	s, calls, ok := x.Session("s:run-1")
	if !ok || s.Calls != 2 || s.Tools != 2 || s.In != 20 || s.Agent != "agent-1" || len(calls) != 2 || calls[0].Seq != 2 || calls[1].Seq != 4 {
		t.Fatalf("run-1: %+v, calls %+v", s, calls)
	}
	if !s.First.Equal(f.t0.Add(time.Minute)) || !s.Last.Equal(f.t0.Add(3*time.Minute+time.Second)) {
		t.Fatalf("run-1 spans %v to %v", s.First, s.Last)
	}
	flagged := x.Entries(func(e *Entry) bool { return len(e.Anomalies) > 0 }, 0)
	if len(flagged) != 1 || flagged[0].Seq != 3 || flagged[0].Anomalies[0].Kind != record.AnomalyOrphanToolResult {
		t.Fatalf("flagged: %+v", flagged)
	}
	if start, _ := x.Entry(1); start.Type != record.TypeGatewayStart || start.Instance != "i1" {
		t.Fatalf("first entry %+v", start)
	}
	full, err := x.Read(3)
	if err != nil || full.Seq != 3 || !strings.Contains(string(full.Rec), strings.Repeat("x", 1000)) {
		t.Fatalf("read seq 3: %v", err)
	}
}

func TestFollowsTheLog(t *testing.T) {
	f := newFixture(t)
	f.call(t, "run-1", 1)
	x, err := Open(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.call(t, "run-1", 2)
	f.call(t, "run-2", 3)
	if err := x.Refresh(); err != nil {
		t.Fatal(err)
	}
	if x.Len() != 3 || len(x.Sessions()) != 2 {
		t.Fatalf("after refresh: %d entries, %d sessions", x.Len(), len(x.Sessions()))
	}
	// A line still being written is left for later.
	f.l.Close()
	line, _ := os.ReadFile(f.path)
	last := strings.SplitAfter(string(line), "\n")[2]
	os.WriteFile(f.path, []byte(strings.Join(strings.SplitAfter(string(line), "\n")[:2], "")), 0o600)
	x, _ = Open(f.path)
	fh, _ := os.OpenFile(f.path, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString(last[:len(last)/2])
	x.Refresh()
	if x.Len() != 2 || x.Err() != nil {
		t.Fatalf("a partial line was indexed (%d entries, err %v)", x.Len(), x.Err())
	}
	fh.WriteString(last[len(last)/2:])
	fh.Close()
	x.Refresh()
	if x.Len() != 3 || x.Err() != nil {
		t.Fatalf("the completed line was not indexed (%d entries, err %v)", x.Len(), x.Err())
	}
}

func TestShrinkingLogIsRebuiltAndReported(t *testing.T) {
	f := newFixture(t)
	for i := range 3 {
		f.call(t, "run-1", i)
	}
	f.l.Close()
	x, _ := Open(f.path)
	b, _ := os.ReadFile(f.path)
	lines := strings.SplitAfter(string(b), "\n")
	os.WriteFile(f.path, []byte(lines[0]), 0o600)
	x.Refresh()
	if !x.Shrunk() || x.Len() != 1 {
		t.Fatalf("shrunk %v, %d entries", x.Shrunk(), x.Len())
	}
	if s, _, _ := x.Session("s:run-1"); s.Calls != 1 {
		t.Fatalf("session kept %d calls from before the rebuild", s.Calls)
	}
}

func TestMalformedEntryStopsIndexing(t *testing.T) {
	f := newFixture(t)
	f.call(t, "run-1", 1)
	f.l.Close()
	fh, _ := os.OpenFile(f.path, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString("not json\n")
	fh.Close()
	x, err := Open(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if x.Len() != 1 || x.Err() == nil {
		t.Fatalf("%d entries, err %v", x.Len(), x.Err())
	}
}

func TestReadersDuringRefresh(t *testing.T) {
	f := newFixture(t)
	f.call(t, "run-0", 0)
	x, _ := Open(f.path)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, s := range x.Sessions() {
					x.Session(s.Key)
				}
				x.Entries(nil, 10)
			}
		}()
	}
	for i := range 50 {
		f.call(t, fmt.Sprint("run-", i%5), i)
		x.Refresh()
	}
	close(stop)
	wg.Wait()
	if x.Len() != 51 {
		t.Fatalf("indexed %d entries, want 51", x.Len())
	}
}
