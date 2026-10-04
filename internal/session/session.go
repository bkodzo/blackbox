// Package session follows each conversation across calls and flags behaviour
// an auditor should look at: tool results the model never asked for or that
// were already answered, history the agent changed between turns, replies it
// attributed to the model that the model never sent, and tools, system
// prompts, or models that changed mid-conversation.
//
// Calls are grouped by the session ID the agent sends. Calls without one are
// grouped by conversation: requests that start with the same opening messages
// and extend a previous request's history. Only hashes and tool call
// identities are kept, never message content, and the number of tracked
// conversations is bounded.
//
// A Tracker is not safe for concurrent use; the recorder owns it.
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/bkodzo/blackbox/internal/format"
	"github.com/bkodzo/blackbox/internal/record"
	"github.com/bkodzo/blackbox/internal/risk"
)

// Limits on tracked state.
const (
	DefaultIdle = time.Hour // how long a conversation is remembered after its last call
	MaxBranches = 32        // branches kept per conversation opening, oldest evicted first
	MaxStates   = 10000     // conversations kept in total, least recently used evicted first
)

// toolCall identifies a tool call by ID, name, and canonical arguments.
type toolCall struct{ id, name, args string }

type state struct {
	key       string // session ID, or "" for a conversation tracked by content
	root      string // conversation opening, for conversations tracked by content
	turn      int
	lastSeen  time.Time
	lastSeq   uint64
	messages  []string          // message hashes of the previous request
	calls     []toolCall        // structured tool calls the model returned last turn
	textCalls []toolCall        // tool calls the model wrote as text last turn
	text      string            // hash of the model's reply text last turn
	replied   bool              // the model returned text or calls last turn
	issued    map[string]uint64 // tool call ID -> seq of the call that issued it
	answered  map[string]bool   // tool call IDs that already have a result
	tools     string
	system    string
}

// Tracker holds per-conversation state.
type Tracker struct {
	idle      time.Duration
	sessions  map[string]*state   // by session ID
	convs     map[string][]*state // by conversation opening, for calls without a session ID
	count     int
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
	state     *state // state the call continues, or nil for a new conversation
	branch    bool   // commit as a new branch of state instead of updating it
	messages  []string
	calls     []toolCall
	textCalls []toolCall
	text      string
	tools     string
	system    string
	adopted   map[string]uint64 // IDs the agent assigned to calls the model returned without IDs
	answered  []string          // tool call IDs answered by this request
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
		} else if s = t.closest(obs.root, obs.messages); s != nil {
			// The history diverges from every branch seen so far: check it
			// against the closest one, and record it as a new branch.
			start = historyCheck(c, s, obs.messages, msgs)
			obs.branch = true
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
		checkAdded(c, s, msgs[start:], obs)
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
// rewritten. Dropping a block of older turns while keeping the opening
// (context trimming), or rolling back to an earlier point, is reported as
// history_truncated; any other change as history_rewritten.
func historyCheck(c *record.LLMCall, s *state, cur []string, msgs []format.Message) int {
	prev := s.messages
	if len(cur) >= len(prev) && slices.Equal(cur[:len(prev)], prev) {
		return len(prev)
	}

	a := 0 // length of the common prefix
	for a < len(cur) && a < len(prev) && cur[a] == prev[a] {
		a++
	}
	if a == len(cur) {
		flag(c, record.AnomalyHistoryTruncated,
			"the conversation was rolled back to message %d of the %d sent in turn %d", a, len(prev), s.turn)
		return len(cur)
	}
	// Trimming keeps the opening and a (possibly empty) suffix of the previous
	// history. What follows must be new messages starting with the model's
	// reply, which checkAdded then checks like any other turn, so a trim
	// cannot be used to slip in messages the model never sent.
	for b := min(len(cur)-a, len(prev)-a-1); b >= 0 && a > 0; b-- {
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
	if msgs[a].Role != "" {
		role = msgs[a].Role
	}
	flag(c, record.AnomalyHistoryRewritten,
		"message %d (%s) is not what was sent in turn %d", a+1, role, s.turn)
	return -1
}

// checkAdded checks the messages added since the last turn. A turn adds at
// most one model message, the echo of the model's last reply, which must come
// first and match what the model returned. Tool results must answer calls the
// model issued, each only once.
func checkAdded(c *record.LLMCall, s *state, added []format.Message, obs *Observation) {
	echoAt := slices.IndexFunc(added, func(m format.Message) bool { return m.Role == "assistant" })
	switch {
	case echoAt < 0 && s.replied && toolResults(added) > 0:
		flag(c, record.AnomalyHistoryRewritten,
			"tool results were sent without the model's reply from turn %d", s.turn)
	case echoAt < 0 && s.replied:
		flag(c, record.AnomalyHistoryTruncated, "the model's reply from turn %d was left out", s.turn)
	case echoAt >= 0:
		if echoAt > 0 {
			flag(c, record.AnomalyHistoryRewritten,
				"%d message(s) were placed before the model's reply from turn %d", echoAt, s.turn)
		}
		if !s.replied {
			flag(c, record.AnomalyHistoryRewritten,
				"a reply is attributed to the model, but the model returned nothing in turn %d", s.turn)
		} else {
			obs.adopted = checkEcho(c, s, added[echoAt])
		}
		extra := 0
		for _, m := range added[echoAt+1:] {
			if m.Role == "assistant" {
				extra++
			}
		}
		if extra > 0 {
			flag(c, record.AnomalyHistoryRewritten,
				"%d message(s) are attributed to the model that it never sent", extra)
		}
	}

	seen := map[string]bool{}
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
			switch {
			case !ok:
				flag(c, record.AnomalyOrphanToolResult,
					"result for tool call %q, which the model never requested in this conversation", id)
			case s.answered[id] || seen[id]:
				flag(c, record.AnomalyDuplicateToolResult,
					"another result for tool call %q, which was already answered", id)
			}
			seen[id] = true
			obs.answered = append(obs.answered, id)
		}
	}
}

// checkEcho compares the reply the agent sent back with what the model
// returned last turn. It returns IDs the agent gave to tool calls the model
// returned without IDs, which then count as issued.
func checkEcho(c *record.LLMCall, s *state, echo format.Message) map[string]uint64 {
	var adopted map[string]uint64
	adopt := func(id string) {
		if id == "" {
			return
		}
		if adopted == nil {
			adopted = map[string]uint64{}
		}
		adopted[id] = s.lastSeq
	}
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
		same := func(mc toolCall) bool { return mc.name == ec.Name && mc.args == ec.Arguments }
		// Calls the model returned without IDs match by name and arguments.
		if i := indexUnused(s.calls, used, func(mc toolCall) bool { return mc.id == "" && same(mc) }); i >= 0 {
			used[i] = true
			adopt(ec.ID)
			continue
		}
		// A call the model only wrote as text can be run by an agent that
		// parses replies, but only when the model made no real calls; it is
		// always flagged, since the text may have been quoted, not meant.
		if len(s.calls) == 0 {
			if i := indexUnused(s.textCalls, usedText, same); i >= 0 {
				usedText[i] = true
				adopt(ec.ID)
				flag(c, record.AnomalyTextCallExecuted,
					"the agent ran %s %s, which the model wrote as text rather than calling it", ec.Name, clip(ec.Arguments))
				continue
			}
		}
		flag(c, record.AnomalyHistoryRewritten,
			"the echoed reply contains tool call %q (%s %s), which the model never returned",
			ec.ID, ec.Name, clip(ec.Arguments))
	}
	for i, mc := range s.calls {
		if !used[i] {
			flag(c, record.AnomalyHistoryRewritten,
				"tool call %s %s returned by the model is missing from the echoed reply", mc.name, clip(mc.args))
		}
	}
	switch {
	case s.text == "" || echo.TextSHA256 == s.text:
	case echo.TextSHA256 == "":
		flag(c, record.AnomalyHistoryRewritten, "the model's reply text was left out of the echoed reply")
	default:
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

// match finds the branch a request without a session ID continues: one with
// the same opening whose last request is a strict prefix of this one. When
// several qualify, the longest wins, then one whose model reply this request
// echoes.
func (t *Tracker) match(root string, cur []string, msgs []format.Message) *state {
	var best *state
	for _, s := range t.convs[root] {
		n := len(s.messages)
		if n >= len(cur) || !slices.Equal(cur[:n], s.messages) {
			continue
		}
		if best == nil || n > len(best.messages) || (n == len(best.messages) && echoes(s, msgs[n]) && !echoes(best, msgs[n])) {
			best = s
		}
	}
	return best
}

// closest finds the branch with the same opening that shares the longest
// common prefix with cur, preferring the most recent.
func (t *Tracker) closest(root string, cur []string) *state {
	var best *state
	bestN := -1
	for _, s := range t.convs[root] {
		n := 0
		for n < len(cur) && n < len(s.messages) && cur[n] == s.messages[n] {
			n++
		}
		if n > bestN || (n == bestN && s.lastSeen.After(best.lastSeen)) {
			best, bestN = s, n
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
		if !slices.ContainsFunc(s.calls, func(mc toolCall) bool {
			return mc.id == ec.ID || (mc.id == "" && mc.name == ec.Name && mc.args == ec.Arguments)
		}) {
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
	if s == nil || obs.branch {
		n := &state{key: obs.sessionID, root: obs.root, issued: map[string]uint64{}, answered: map[string]bool{}}
		if s != nil { // a new branch inherits what the conversation has issued and answered
			n.turn, n.issued, n.answered = s.turn, maps.Clone(s.issued), maps.Clone(s.answered)
		}
		s = n
		t.insert(s)
	}
	s.turn++
	s.lastSeen, s.lastSeq = at, seq
	s.messages, s.calls, s.textCalls = obs.messages, obs.calls, obs.textCalls
	s.text, s.tools, s.system = obs.text, obs.tools, obs.system
	s.replied = len(obs.calls) > 0 || obs.text != ""
	for _, tc := range obs.calls {
		if tc.id != "" {
			s.issued[tc.id] = seq
		}
	}
	for id, at := range obs.adopted {
		s.issued[id] = at
	}
	for _, id := range obs.answered {
		s.answered[id] = true
	}
}

// insert adds a new state, evicting the oldest branch of the same opening
// and the least recently used conversation when limits are reached.
func (t *Tracker) insert(s *state) {
	if s.key != "" {
		if _, ok := t.sessions[s.key]; !ok {
			t.count++
		}
		t.sessions[s.key] = s
	} else {
		branches := t.convs[s.root]
		if len(branches) >= MaxBranches {
			oldest := slices.MinFunc(branches, func(a, b *state) int { return a.lastSeen.Compare(b.lastSeen) })
			t.remove(oldest)
			branches = t.convs[s.root]
		}
		t.convs[s.root] = append(branches, s)
		t.count++
	}
	for t.count > MaxStates {
		t.remove(t.leastRecent())
	}
}

func (t *Tracker) leastRecent() *state {
	var lru *state
	consider := func(s *state) {
		if lru == nil || s.lastSeen.Before(lru.lastSeen) {
			lru = s
		}
	}
	for _, s := range t.sessions {
		consider(s)
	}
	for _, ss := range t.convs {
		for _, s := range ss {
			consider(s)
		}
	}
	return lru
}

func (t *Tracker) remove(s *state) {
	if s == nil {
		return
	}
	if s.key != "" {
		if t.sessions[s.key] == s {
			delete(t.sessions, s.key)
			t.count--
		}
		return
	}
	ss := t.convs[s.root]
	if i := slices.Index(ss, s); i >= 0 {
		ss = slices.Delete(ss, i, i+1)
		t.count--
	}
	if len(ss) == 0 {
		delete(t.convs, s.root)
	} else {
		t.convs[s.root] = ss
	}
}

// Forget drops what is known about a session, so its next call is treated
// as the start of a conversation.
func (t *Tracker) Forget(sessionID string) {
	if s, ok := t.sessions[sessionID]; ok && sessionID != "" {
		t.remove(s)
	}
}

// Sessions reports how many conversations are being tracked.
func (t *Tracker) Sessions() int { return t.count }

func (t *Tracker) sweep() {
	now := t.now()
	if now.Sub(t.lastSweep) < time.Minute {
		return
	}
	t.lastSweep = now
	var stale []*state
	for _, s := range t.sessions {
		if now.Sub(s.lastSeen) > t.idle {
			stale = append(stale, s)
		}
	}
	for _, ss := range t.convs {
		for _, s := range ss {
			if now.Sub(s.lastSeen) > t.idle {
				stale = append(stale, s)
			}
		}
	}
	for _, s := range stale {
		t.remove(s)
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

// pinnedVersion matches what servers append to a model name when resolving
// an alias to a pinned release: a date or a plain version number.
var pinnedVersion = regexp.MustCompile(`^[-:](\d{8}|\d{4}-\d{2}-\d{2}|v?\d+(\.\d+)*)$`)

// sameModel reports whether served is the requested model or a pinned
// release of it. "latest" aliases and "@" version separators are normalized.
func sameModel(requested, served string) bool {
	norm := func(s string) string { return strings.ReplaceAll(strings.ToLower(s), "@", "-") }
	r, s := norm(requested), norm(served)
	for _, alias := range []string{":latest", "-latest"} {
		r = strings.TrimSuffix(r, alias)
		s = strings.TrimSuffix(s, alias)
	}
	if r == s {
		return true
	}
	rest, ok := strings.CutPrefix(s, r)
	return ok && pinnedVersion.MatchString(rest)
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
