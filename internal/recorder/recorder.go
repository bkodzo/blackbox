// Package recorder turns captured exchanges into audit records and appends
// them to the ledger. It runs on its own goroutine so parsing, hashing, and
// signing never delay the agent.
package recorder

import (
	"encoding/json"
	"log"
	"sync/atomic"

	"github.com/bkodzo/blackbox/internal/format"
	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/proxy"
	"github.com/bkodzo/blackbox/internal/record"
	"github.com/bkodzo/blackbox/internal/risk"
	"github.com/bkodzo/blackbox/internal/session"
)

// queueSize bounds captures waiting to be written. When full, Submit blocks:
// the gateway slows down rather than dropping audit records.
const queueSize = 1024

// Recorder consumes captures in arrival order.
type Recorder struct {
	l          *ledger.Ledger
	instanceID string
	risk       risk.Map
	sessions   *session.Tracker
	ch         chan proxy.Capture
	done       chan struct{}
	calls      atomic.Uint64
}

// New starts a recorder writing to l. Records carry instanceID so they can be
// tied to the gateway_start entry of the process that wrote them. Tool calls
// are classified with rm.
func New(l *ledger.Ledger, instanceID string, rm risk.Map) *Recorder {
	r := &Recorder{
		l: l, instanceID: instanceID, risk: rm, sessions: session.New(session.DefaultIdle),
		ch: make(chan proxy.Capture, queueSize), done: make(chan struct{}),
	}
	go r.run()
	return r
}

// Submit queues a capture. It is the proxy's Sink.
func (r *Recorder) Submit(c proxy.Capture) { r.ch <- c }

// Close drains the queue. No Submit calls may happen after Close.
func (r *Recorder) Close() {
	close(r.ch)
	<-r.done
}

// Calls returns how many calls have been written.
func (r *Recorder) Calls() uint64 { return r.calls.Load() }

func (r *Recorder) run() {
	defer close(r.done)
	for c := range r.ch {
		call, parsed := Enrich(c, r.instanceID, r.risk)
		obs := r.sessions.Observe(call, parsed)
		b, err := json.Marshal(call)
		if err != nil {
			log.Printf("blackbox: encoding record: %v", err)
			continue
		}
		e, _, err := r.l.Append(b)
		if err != nil {
			log.Printf("blackbox: AUDIT RECORD NOT WRITTEN: %v", err)
			continue
		}
		r.sessions.Commit(obs, e.Seq)
		r.calls.Add(1)
	}
}

// Enrich fills the fields that require reading the payloads.
func Enrich(c proxy.Capture, instanceID string, rm risk.Map) (*record.LLMCall, format.Parsed) {
	call := c.Call
	call.InstanceID = instanceID
	p := format.Parse(c.Req, c.Resp, c.SSE)
	call.Format = p.Format

	rq := &call.Request
	rq.ModelRequested = p.Request.Model
	rq.Stream = p.Request.Stream
	rq.MessageCount = len(p.Request.Messages)
	rq.SystemSHA256 = p.Request.SystemSHA256
	rq.ToolsOffered = p.Request.Tools
	rq.ToolsSHA256 = p.Request.ToolsSHA256

	call.Upstream.ModelServed = p.Response.Model
	call.Upstream.SystemFingerprint = p.Response.SystemFingerprint

	rs := &call.Response
	rs.FinishReason = p.Response.FinishReason
	rs.Usage = record.Usage{Input: p.Response.Input, Output: p.Response.Output, Total: p.Response.Total}
	for _, tc := range p.Response.ToolCalls {
		rule := rm.Lookup(tc.Name)
		rs.ToolCalls = append(rs.ToolCalls, record.ToolCall{
			ID:        tc.ID,
			Name:      tc.Name,
			Arguments: tc.Arguments,
			ValidJSON: tc.Arguments == "" || json.Valid([]byte(tc.Arguments)),
			Risk:      rule.Risk,
			Category:  rule.Category,
		})
	}
	if rs.Stream != nil {
		rs.Stream.Chunks = p.Response.Chunks
	}
	return call, p
}
