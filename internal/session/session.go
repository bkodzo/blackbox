// Package session follows each agent session across calls and flags behaviour
// an auditor should look at: tool results the model never asked for, history
// the agent changed between turns, and tools, system prompts, or models that
// changed mid-session.
//
// Only hashes and tool call IDs are kept per session, never message content.
// A Tracker is not safe for concurrent use; the recorder owns it.
package session

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/bkodzo/blackbox/internal/format"
	"github.com/bkodzo/blackbox/internal/record"
	"github.com/bkodzo/blackbox/internal/risk"
)

// DefaultIdle is how long a session is remembered after its last call.
const DefaultIdle = time.Hour

type state struct {
	turn      int
	lastSeen  time.Time
	messages  []string          // message hashes of the previous request
	lastCalls []string          // tool call IDs the model returned last turn
	issued    map[string]uint64 // tool call ID -> seq of the call that issued it
	tools     string
	system    string
}

// Tracker holds per-session state.
type Tracker struct {
	idle      time.Duration
	sessions  map[string]*state
	lastSweep time.Time
	now       func() time.Time
}

// New returns a Tracker that forgets sessions idle for longer than idle.
func New(idle time.Duration) *Tracker {
	if idle <= 0 {
		idle = DefaultIdle
	}
	return &Tracker{idle: idle, sessions: map[string]*state{}, now: time.Now}
}

// Observation is the outcome of Observe, passed to Commit once the call has
// a sequence number.
type Observation struct {
	key      string
	messages []string
	calls    []string
	tools    string
	system   string
}

// Observe checks call against what the session has done so far and fills in
// call.Turn, call.ToolResultsIn, and call.Anomalies. It does not change the
// session; Commit does, after the call is written.
func (t *Tracker) Observe(call *record.LLMCall, p format.Parsed) *Observation {
	t.sweep()
	callChecks(call)

	key := call.Session.ID
	if key == "" {
		return nil // nothing to correlate with
	}
	obs := &Observation{key: key, tools: p.Request.ToolsSHA256, system: p.Request.SystemSHA256}
	for _, m := range p.Request.Messages {
		obs.messages = append(obs.messages, m.SHA256)
	}
	for _, tc := range p.Response.ToolCalls {
		obs.calls = append(obs.calls, tc.ID)
	}

	s, ok := t.sessions[key]
	if !ok {
		call.Turn = 1
		return obs
	}
	call.Turn = s.turn + 1
	msgs := p.Request.Messages
	prev := len(s.messages)

	// History: every message sent last turn must be sent again unchanged.
	if len(msgs) < prev {
		flag(call, record.AnomalyHistoryTruncated,
			"request has %d messages; the previous turn had %d", len(msgs), prev)
	} else if i := firstDiff(obs.messages[:prev], s.messages); i >= 0 {
		flag(call, record.AnomalyHistoryRewritten,
			"message %d (%s) differs from what was sent in turn %d", i+1, roleOf(msgs[i]), s.turn)
	}

	// Only messages added since last turn are new: the echoed model reply and
	// any tool results.
	if len(msgs) > prev {
		added := msgs[prev:]
		if a := added[0]; a.Role == "assistant" && len(s.lastCalls) > 0 && !sameSet(a.ToolCallIDs, s.lastCalls) {
			flag(call, record.AnomalyHistoryRewritten,
				"tool calls in the echoed reply (%s) differ from what the model returned (%s)",
				list(a.ToolCallIDs), list(s.lastCalls))
		}
		for _, m := range added {
			for _, id := range m.ToolResultFor {
				if id == "" {
					continue
				}
				seq, ok := s.issued[id]
				call.ToolResultsIn = append(call.ToolResultsIn, record.ToolResultLink{ToolCallID: id, MatchedSeq: seq})
				if !ok {
					flag(call, record.AnomalyOrphanToolResult,
						"result for tool call %q, which the model never requested in this session", id)
				}
			}
		}
	}

	if obs.tools != s.tools {
		flag(call, record.AnomalyToolsetChanged, "tools offered differ from turn %d", s.turn)
	}
	if obs.system != s.system {
		flag(call, record.AnomalySystemPromptChanged, "system prompt differs from turn %d", s.turn)
	}
	return obs
}

// Commit records an observed call, written at seq, into its session.
func (t *Tracker) Commit(obs *Observation, seq uint64) {
	if obs == nil {
		return
	}
	s, ok := t.sessions[obs.key]
	if !ok {
		s = &state{issued: map[string]uint64{}}
		t.sessions[obs.key] = s
	}
	s.turn++
	s.lastSeen = t.now()
	s.messages, s.lastCalls, s.tools, s.system = obs.messages, obs.calls, obs.tools, obs.system
	for _, id := range obs.calls {
		if id != "" {
			s.issued[id] = seq
		}
	}
}

// Sessions reports how many sessions are being tracked.
func (t *Tracker) Sessions() int { return len(t.sessions) }

func (t *Tracker) sweep() {
	now := t.now()
	if now.Sub(t.lastSweep) < time.Minute {
		return
	}
	t.lastSweep = now
	for k, s := range t.sessions {
		if now.Sub(s.lastSeen) > t.idle {
			delete(t.sessions, k)
		}
	}
}

// callChecks flags anomalies visible in a single call.
func callChecks(call *record.LLMCall) {
	req, served := call.Request.ModelRequested, call.Upstream.ModelServed
	if req != "" && served != "" && !sameModel(req, served) {
		flag(call, record.AnomalyModelSubstituted, "requested %q, served by %q", req, served)
	}
	if s := call.Response.Stream; s != nil && s.Outcome == record.StreamClientAborted {
		flag(call, record.AnomalyStreamAborted, "client disconnected after %d chunks", s.Chunks)
	}
	for _, tc := range call.Response.ToolCalls {
		if tc.InText {
			flag(call, record.AnomalyToolCallInText,
				"model wrote a call to %q in its reply text instead of making a tool call", tc.Name)
		}
		if tc.Risk == risk.High {
			flag(call, record.AnomalyHighRiskTool, "model requested high-risk tool %q", tc.Name)
		}
	}
}

// sameModel treats a served name that extends the requested one (a pinned
// version of an alias, for example) as the same model.
func sameModel(requested, served string) bool {
	r, s := strings.ToLower(requested), strings.ToLower(served)
	return strings.HasPrefix(s, r) || strings.HasPrefix(r, s)
}

func flag(call *record.LLMCall, kind, f string, args ...any) {
	call.Anomalies = append(call.Anomalies, record.Anomaly{Kind: kind, Detail: fmt.Sprintf(f, args...)})
}

func firstDiff(a, b []string) int {
	for i := range a {
		if a[i] != b[i] {
			return i
		}
	}
	return -1
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func roleOf(m format.Message) string {
	if m.Role == "" {
		return "no role"
	}
	return m.Role
}

func list(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}
