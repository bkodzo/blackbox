// Package recorder turns captured exchanges into audit records and appends
// them to the ledger. It runs on its own goroutine so parsing, hashing, and
// signing never delay the agent.
package recorder

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/bkodzo/blackbox/internal/format"
	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
	"github.com/bkodzo/blackbox/internal/risk"
	"github.com/bkodzo/blackbox/internal/session"
)

// DefaultMaxQueueBytes bounds the bodies waiting to be recorded.
const DefaultMaxQueueBytes = 256 << 20

// Options configure a Recorder.
type Options struct {
	Risk risk.Map
	// MaxQueueBytes bounds memory held by queued exchanges. When it is
	// reached, Submit blocks: the gateway slows down rather than dropping
	// audit records or growing without limit.
	MaxQueueBytes int64
	// OnFailure is called once, from the recorder goroutine, when a record
	// cannot be written. The gateway uses it to stop forwarding traffic.
	OnFailure func(error)
	// Sessions, if set, is used instead of a new tracker (for example one
	// rebuilt from the log at startup).
	Sessions *session.Tracker
}

// Recorder consumes exchanges in arrival order.
type Recorder struct {
	l          *ledger.Ledger
	instanceID string
	opt        Options
	sessions   *session.Tracker

	mu     sync.Mutex
	cond   *sync.Cond
	queue  []record.Exchange
	bytes  int64
	closed bool

	done       chan struct{}
	calls      atomic.Uint64
	unrecorded atomic.Uint64
	failed     atomic.Pointer[error]
}

// New starts a recorder writing to l. Records carry instanceID so they can be
// tied to the gateway_start entry of the process that wrote them.
func New(l *ledger.Ledger, instanceID string, opt Options) *Recorder {
	if opt.MaxQueueBytes <= 0 {
		opt.MaxQueueBytes = DefaultMaxQueueBytes
	}
	if opt.Sessions == nil {
		opt.Sessions = session.New(session.DefaultIdle)
	}
	r := &Recorder{l: l, instanceID: instanceID, opt: opt, sessions: opt.Sessions, done: make(chan struct{})}
	r.cond = sync.NewCond(&r.mu)
	go r.run()
	return r
}

// Submit queues an exchange; it is the proxy's sink. It blocks while the
// queue is full. After Close, the exchange is counted as unrecorded.
func (r *Recorder) Submit(x record.Exchange) {
	size := x.Size()
	r.mu.Lock()
	defer r.mu.Unlock()
	// A single exchange larger than the budget is admitted once the queue is
	// empty, so it cannot block forever.
	for !r.closed && r.bytes > 0 && r.bytes+size > r.opt.MaxQueueBytes {
		r.cond.Wait()
	}
	if r.closed {
		r.unrecorded.Add(1)
		return
	}
	r.queue = append(r.queue, x)
	r.bytes += size
	r.cond.Broadcast()
}

// Close records everything already queued, then stops. Later Submit calls
// are counted as unrecorded.
func (r *Recorder) Close() { r.CloseWithin(-1) }

// CloseWithin is Close that gives up after d (d < 0 waits indefinitely),
// for example when the disk has stopped responding. It reports whether
// everything queued was handled.
func (r *Recorder) CloseWithin(d time.Duration) bool {
	r.mu.Lock()
	r.closed = true
	r.cond.Broadcast()
	r.mu.Unlock()
	if d < 0 {
		<-r.done
	} else {
		select {
		case <-r.done:
		case <-time.After(d):
			log.Printf("blackbox: the audit log did not finish writing; queued records may be missing")
			return false
		}
	}
	if n := r.unrecorded.Load(); n > 0 {
		log.Printf("blackbox: %d audit records were not written", n)
	}
	return true
}

// Calls returns how many calls have been written.
func (r *Recorder) Calls() uint64 { return r.calls.Load() }

// Unrecorded returns how many exchanges could not be written.
func (r *Recorder) Unrecorded() uint64 { return r.unrecorded.Load() }

// Err returns the error that stopped recording, if any.
func (r *Recorder) Err() error {
	if p := r.failed.Load(); p != nil {
		return *p
	}
	return nil
}

func (r *Recorder) next() (record.Exchange, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.queue) == 0 && !r.closed {
		r.cond.Wait()
	}
	if len(r.queue) == 0 {
		return record.Exchange{}, false
	}
	x := r.queue[0]
	r.queue[0] = record.Exchange{}
	r.queue = r.queue[1:]
	r.bytes -= x.Size()
	r.cond.Broadcast()
	return x, true
}

func (r *Recorder) run() {
	defer close(r.done)
	for {
		x, ok := r.next()
		if !ok {
			return
		}
		if err := r.write(x); err != nil {
			r.unrecorded.Add(1)
			if r.failed.CompareAndSwap(nil, &err) {
				log.Printf("blackbox: AUDIT RECORD NOT WRITTEN: %v", err)
				if r.opt.OnFailure != nil {
					r.opt.OnFailure(err)
				}
			}
		}
	}
}

func (r *Recorder) write(x record.Exchange) error {
	if err := r.Err(); err != nil {
		return err
	}
	call, parsed := Enrich(x, r.instanceID, r.opt.Risk)
	obs := r.sessions.Observe(call, parsed)
	b, err := json.Marshal(call)
	if err != nil {
		return errors.Join(errors.New("encoding record"), err)
	}
	e, _, err := r.l.Append(b)
	if err != nil {
		return err
	}
	r.sessions.Commit(obs, e.Seq)
	if call.Request.Body.Truncated || call.Response.Body.Truncated {
		// Later turns cannot be checked against an incompletely stored turn;
		// let the conversation start fresh instead of raising false alarms.
		r.sessions.Drop(obs)
	}
	r.calls.Add(1)
	return nil
}

// Enrich fills the fields that require reading the payloads.
func Enrich(x record.Exchange, instanceID string, rm risk.Map) (*record.LLMCall, format.Parsed) {
	call := x.Call
	call.InstanceID = instanceID
	p := format.Parse(x.Req, x.Resp, x.SSE)
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
	add := func(tc format.ToolCall, inText bool) {
		rule := rm.Lookup(tc.Name)
		rs.ToolCalls = append(rs.ToolCalls, record.ToolCall{
			ID:        tc.ID,
			Name:      tc.Name,
			Arguments: tc.Arguments,
			ValidJSON: tc.Arguments == "" || json.Valid([]byte(tc.Arguments)),
			InText:    inText,
			Risk:      rule.Risk,
			Category:  rule.Category,
		})
	}
	for _, tc := range p.Response.ToolCalls {
		add(tc, false)
	}
	// A tool call written as text counts when no tools were offered (the
	// agent parses replies itself), or when it names an offered tool or one
	// in the risk map. This keeps JSON the model merely quotes, such as a
	// config file, from being reported as a call.
	offered := map[string]bool{}
	for _, name := range p.Request.Tools {
		offered[name] = true
	}
	kept := p.Response.TextToolCalls[:0:0]
	for _, tc := range p.Response.TextToolCalls {
		if len(offered) == 0 || offered[tc.Name] || rm.Lookup(tc.Name).Risk != risk.Unknown {
			kept = append(kept, tc)
			add(tc, true)
		} else {
			rs.IgnoredTextCalls++
		}
	}
	p.Response.TextToolCalls = kept
	rs.TextScanPartial = p.Response.TextScanPartial
	if rs.Stream != nil {
		rs.Stream.Chunks = p.Response.Chunks
	}
	if text := strings.TrimSpace(p.Response.Reasoning); text != "" || p.Response.ReasoningRedacted > 0 {
		r := &record.Reasoning{Chars: utf8.RuneCountInString(text), RedactedBlocks: p.Response.ReasoningRedacted}
		if text != "" {
			sum := sha256.Sum256([]byte(text))
			r.SHA256 = hex.EncodeToString(sum[:])
			r.Preview = string([]rune(text)[:min(r.Chars, record.ReasoningPreview)])
		}
		rs.Reasoning = r
	}
	return call, p
}
