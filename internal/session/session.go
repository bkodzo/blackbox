// Package session follows each conversation across calls and flags behaviour
// an auditor should look at: tool results the model never asked for, history
// or tool calls the agent changed between turns, and tools, system prompts,
// or models that changed mid-conversation.
//
// Calls are grouped by the session ID the agent sends. Calls without one are
// grouped by conversation: requests that start with the same opening messages
// and extend a previous request's history. Only hashes and tool call
// identities are kept, never message content.
//
// A Tracker is not safe for concurrent use; the recorder owns it.
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/bkodzo/blackbox/internal/format"
	"github.com/bkodzo/blackbox/internal/record"
	"github.com/bkodzo/blackbox/internal/risk"
)

// DefaultIdle is how long a conversation is remembered after its last call.
const DefaultIdle = time.Hour

// toolCall identifies a tool call by ID, name, and canonical arguments.
type toolCall struct{ id, name, args string }

type state struct {
	turn      int
	lastSeen  time.Time
	lastSeq   uint64
	messages  []string          // message hashes of the previous request
	calls     []toolCall        // structured tool calls the model returned last turn
	textCalls []toolCall        // tool calls the model wrote as text last turn
	text      string            // hash of the model's reply text last turn
	issued    map[string]uint64 // tool call ID -> seq of the call that issued it
	tools     string
	system    string
}

// Tracker holds per-conversation state.
type Tracker struct {
	idle      time.Duration
	sessions  map[string]*state   // by session ID
	convs     map[string][]*state // by conversation root, for calls without a session ID
	lastSweep time.Time
	now       func() time.Time
}

// New returns a Tracker that forgets conversations idle for longer than idle.
func New(idle time.Duration) *Tracker {
	if idle <= 0 {
		idle = DefaultIdle
	}
	return &Tracker{idle: idle, sessions: map[string]*state{}, convs: map[string][]*state{}, now: time.Now}
}

// Observation is the outcome of Observe, passed to Commit once the call has
// a sequence number.
type Observation struct {
	sessionID string
	root      string
	state     *state // nil for a new conversation
	messages  []string
	calls     []toolCall
	textCalls []toolCall
	text      string
	tools     string
	system    string
	adopted   map[string]uint64 // tool call IDs the agent assigned to ID-less model calls
}

// Observe checks call against its conversation so far and fills in
// call.Turn, call.ToolResultsIn, call.Anomalies, and, for calls without a
// session ID, call.Session.Conversation. It does not change any state;
// Commit does, after the call is written.
func (t *Tracker) Observe(c *record.LLMCall, p format.Parsed) *Observation {
	t.sweep()
	callChecks(c)

	msgs := p.Request.Messages
	obs := &Observation{
		tools:  p.Request.ToolsSHA256,
		system: p.Request.SystemSHA256,
		text:   format.TextHash(p.Response.Text),
	}
	for _, m := range msgs {
		obs.messages = append(obs.messages, m.SHA256)
	}
	for _, tc := range p.Response.ToolCalls {
		obs.calls = append(obs.calls, toolCall{tc.ID, tc.Name, format.CanonicalArgs(tc.Arguments)})
	}
	for _, tc := range p.Response.TextToolCalls {
		obs.textCalls = append(obs.textCalls, toolCall{tc.ID, tc.Name, format.CanonicalArgs(tc.Arguments)})
	}

	var s *state
	start := -1 // index of the first message added since the last turn, or -1
	if id := c.Session.ID; id != "" {
		obs.sessionID = id
		if s = t.sessions[id]; s != nil {
			start = historyCheck(c, s, obs.messages, msgs)
		}
	} else {
		if len(msgs) == 0 {
			return nil // nothing to correlate with
		}
		obs.root = conversationRoot(msgs)
		c.Session.Conversation = obs.root[:16]
		if s = t.match(obs.root, obs.messages, msgs); s != nil {
			start = len(s.messages)
		}
	}
	obs.state = s

	if s == nil {
		c.Turn = 1
		if n := toolResults(msgs); n > 0 {
			flag(c, record.AnomalyUnverifiableResult,
				"%d tool result(s) arrived with no earlier turn to check them against "+
					"(the conversation began before the gateway saw it, or under another session ID)", n)
		}
		return obs
	}
	c.Turn = s.turn + 1

	if start >= 0 && start < len(msgs) {
		added := msgs[start:]
		if added[0].Role == "assistant" {
			obs.adopted = checkEcho(c, s, added[0])
		}
		for _, m := range added {
			for _, id := range m.ToolResultFor {
				if id == "" {
					continue
				}
				seq, ok := s.issued[id]
				if !ok {
					seq, ok = obs.adopted[id]
				}
				c.ToolResultsIn = append(c.ToolResultsIn, record.ToolResultLink{ToolCallID: id, MatchedSeq: seq})
				if !ok {
					flag(c, record.AnomalyOrphanToolResult,
						"result for tool call %q, which the model never requested in this conversation", id)
				}
			}
		}
	}

	if obs.tools != s.tools {
		flag(c, record.AnomalyToolsetChanged, "tools offered differ from turn %d", s.turn)
	}
	if obs.system != s.system {
		flag(c, record.AnomalySystemPromptChanged, "system prompt differs from turn %d", s.turn)
	}
	return obs
}

// historyCheck compares the request's history with the previous turn's and
// returns where the newly added messages start, or -1 if the history was
// rewritten. Dropping the oldest turns (context trimming) is reported as
// history_truncated; any other change as history_rewritten.
func historyCheck(c *record.LLMCall, s *state, cur []string, msgs []format.Message) int {
	prev := s.messages
	if len(cur) >= len(prev) && slices.Equal(cur[:len(prev)], prev) {
		return len(prev)
	}

	// Trimming keeps a common prefix (typically the system prompt) and the
	// most recent messages, dropping a block in between.
	a := 0
	for a < len(cur) && a < len(prev) && cur[a] == prev[a] {
		a++
	}
	for b := min(len(cur)-a, len(prev)-a-1); b >= 0; b-- {
		if !slices.Equal(cur[a:a+b], prev[len(prev)-b:]) {
			continue
		}
		if i := a + b; i == len(cur) || msgs[i].Role == "assistant" {
			flag(c, record.AnomalyHistoryTruncated,
				"%d earlier messages were dropped since turn %d", len(prev)-a-b, s.turn)
			return i
		}
	}
	role := "no role"
	if a < len(msgs) && msgs[a].Role != "" {
		role = msgs[a].Role
	}
	flag(c, record.AnomalyHistoryRewritten,
		"message %d (%s) is not what was sent in turn %d", a+1, role, s.turn)
	return -1
}

// checkEcho compares the reply the agent sent back with what the model
// returned last turn. It returns IDs the agent gave to tool calls the model
// returned without IDs, which then count as issued.
func checkEcho(c *record.LLMCall, s *state, echo format.Message) map[string]uint64 {
	var adopted map[string]uint64
	used := make([]bool, len(s.calls))
	usedText := make([]bool, len(s.textCalls))

	for _, ec := range echo.ToolCalls {
		if i := slices.IndexFunc(s.calls, func(mc toolCall) bool { return mc.id != "" && mc.id == ec.ID }); i >= 0 {
			used[i] = true
			if mc := s.calls[i]; mc.name != ec.Name || mc.args != ec.Arguments {
				flag(c, record.AnomalyHistoryRewritten,
					"tool call %q was echoed as %s %s but the model returned %s %s",
					ec.ID, ec.Name, clip(ec.Arguments), mc.name, clip(mc.args))
			}
			continue
		}
		// Calls returned without IDs, or written as text, match by name and arguments.
		same := func(mc toolCall) bool { return mc.name == ec.Name && mc.args == ec.Arguments }
		if i := indexUnused(s.calls, used, func(mc toolCall) bool { return mc.id == "" && same(mc) }); i >= 0 {
			used[i] = true
		} else if i := indexUnused(s.textCalls, usedText, same); i >= 0 {
			usedText[i] = true
		} else {
			flag(c, record.AnomalyHistoryRewritten,
				"the echoed reply contains tool call %q (%s %s), which the model never returned",
				ec.ID, ec.Name, clip(ec.Arguments))
			continue
		}
		if ec.ID != "" {
			if adopted == nil {
				adopted = map[string]uint64{}
			}
			adopted[ec.ID] = s.lastSeq
		}
	}
	for i, mc := range s.calls {
		if !used[i] {
			flag(c, record.AnomalyHistoryRewritten,
				"tool call %s %s returned by the model is missing from the echoed reply", mc.name, clip(mc.args))
		}
	}
	if s.text != "" && echo.TextSHA256 != "" && echo.TextSHA256 != s.text {
		flag(c, record.AnomalyHistoryRewritten, "the text of the echoed reply differs from what the model returned")
	}
	return adopted
}

func indexUnused(calls []toolCall, used []bool, f func(toolCall) bool) int {
	for i, mc := range calls {
		if !used[i] && f(mc) {
			return i
		}
	}
	return -1
}

// match finds the conversation a request without a session ID continues: one
// with the same opening whose last request is a prefix of this one. A request
// that adds nothing to a conversation that already has a reply starts a new
// branch (a retry or a second run of the same task).
func (t *Tracker) match(root string, cur []string, msgs []format.Message) *state {
	var best *state
	for _, s := range t.convs[root] {
		n := len(s.messages)
		if n > len(cur) || !slices.Equal(cur[:n], s.messages) || n == len(cur) {
			continue
		}
		if best == nil || n > len(best.messages) || (n == len(best.messages) && echoes(s, msgs[n]) && !echoes(best, msgs[n])) {
			best = s
		}
	}
	return best
}

// echoes reports whether m looks like the reply s's model gave.
func echoes(s *state, m format.Message) bool {
	if m.Role != "assistant" {
		return false
	}
	for _, ec := range m.ToolCalls {
		if !slices.ContainsFunc(s.calls, func(mc toolCall) bool { return mc.id == ec.ID }) {
			return false
		}
	}
	return len(m.ToolCalls) > 0 || (s.text != "" && s.text == m.TextSHA256)
}

// Commit records an observed call, written at seq, into its conversation.
func (t *Tracker) Commit(obs *Observation, seq uint64) { t.CommitAt(obs, seq, t.now()) }

// CommitAt is Commit with an explicit time, for rebuilding state from a log.
func (t *Tracker) CommitAt(obs *Observation, seq uint64, at time.Time) {
	if obs == nil {
		return
	}
	s := obs.state
	if s == nil {
		s = &state{issued: map[string]uint64{}}
		if obs.sessionID != "" {
			t.sessions[obs.sessionID] = s
		} else {
			t.convs[obs.root] = append(t.convs[obs.root], s)
		}
	}
	s.turn++
	s.lastSeen, s.lastSeq = at, seq
	s.messages, s.calls, s.textCalls = obs.messages, obs.calls, obs.textCalls
	s.text, s.tools, s.system = obs.text, obs.tools, obs.system
	for _, tc := range obs.calls {
		if tc.id != "" {
			s.issued[tc.id] = seq
		}
	}
	for id, at := range obs.adopted {
		s.issued[id] = at
	}
}

// Sessions reports how many conversations are being tracked.
func (t *Tracker) Sessions() int {
	n := len(t.sessions)
	for _, ss := range t.convs {
		n += len(ss)
	}
	return n
}

func (t *Tracker) sweep() {
	now := t.now()
	if now.Sub(t.lastSweep) < time.Minute {
		return
	}
	t.lastSweep = now
	stale := func(s *state) bool { return now.Sub(s.lastSeen) > t.idle }
	for k, s := range t.sessions {
		if stale(s) {
			delete(t.sessions, k)
		}
	}
	for root, ss := range t.convs {
		if ss = slices.DeleteFunc(ss, stale); len(ss) == 0 {
			delete(t.convs, root)
		} else {
			t.convs[root] = ss
		}
	}
}

// conversationRoot hashes the messages up to and including the first user
// message: what every request in one conversation starts with.
func conversationRoot(msgs []format.Message) string {
	h := sha256.New()
	for _, m := range msgs {
		h.Write([]byte(m.SHA256))
		if m.Role == "user" {
			break
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func toolResults(msgs []format.Message) int {
	n := 0
	for _, m := range msgs {
		n += len(m.ToolResultFor)
	}
	return n
}

// callChecks flags anomalies visible in a single call.
func callChecks(c *record.LLMCall) {
	req, served := c.Request.ModelRequested, c.Upstream.ModelServed
	if req != "" && served != "" && !sameModel(req, served) {
		flag(c, record.AnomalyModelSubstituted, "requested %q, served by %q", req, served)
	}
	if s := c.Response.Stream; s != nil && s.Outcome == record.StreamClientAborted {
		flag(c, record.AnomalyStreamAborted, "client disconnected after %d chunks", s.Chunks)
	}
	for _, tc := range c.Response.ToolCalls {
		if tc.InText {
			flag(c, record.AnomalyToolCallInText,
				"model wrote a call to %q in its reply text instead of making a tool call", tc.Name)
		}
		if tc.Risk == risk.High {
			flag(c, record.AnomalyHighRiskTool, "model requested high-risk tool %q", tc.Name)
		}
	}
}

// versionSuffix matches what servers append to a model name when resolving
// an alias to a pinned version: a date, a version number, or "latest".
var versionSuffix = regexp.MustCompile(`^[-:@.](v?[0-9][0-9a-z.\-]*|latest)$`)

// sameModel treats a served name equal to the requested one, or the requested
// one plus a version suffix, as the same model.
func sameModel(requested, served string) bool {
	norm := func(s string) string { return strings.TrimSuffix(strings.ToLower(s), ":latest") }
	r, s := norm(requested), norm(served)
	if r == s {
		return true
	}
	rest, ok := strings.CutPrefix(s, r)
	return ok && versionSuffix.MatchString(rest)
}

func flag(c *record.LLMCall, kind, f string, args ...any) {
	c.Anomalies = append(c.Anomalies, record.Anomaly{Kind: kind, Detail: fmt.Sprintf(f, args...)})
}

func clip(s string) string {
	if len(s) <= 80 {
		return s
	}
	return s[:77] + "..."
}
