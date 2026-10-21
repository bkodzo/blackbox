// Package index keeps a small summary of every entry in a log, so the
// dashboard can list and filter calls without holding their bodies in
// memory. It follows the log as the gateway appends to it.
//
// The index reads entries without checking hashes or signatures; whether
// the log can be trusted is decided by ledger.Verify.
package index

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
)

// Tool is a tool call the model made.
type Tool struct {
	Name   string
	Risk   string
	InText bool // written in the reply text rather than made as a call
}

// Entry summarizes one log entry.
type Entry struct {
	Seq        uint64
	Off        int64 // where the entry's line starts in the file
	Len        int   // length of the line, without its newline
	Type       string
	Time       time.Time
	Instance   string
	Session    string // key of the session the call belongs to
	Agent      string
	Principal  string
	Model      string
	Status     int
	ErrorClass string
	Turn       int
	In, Out    int
	Tools      []Tool
	Anomalies  []record.Anomaly
}

// Session groups the calls of one agent run: those with the same session ID,
// or, for calls without one, the same conversation.
type Session struct {
	Key          string // stable identifier, used in links
	ID           string // session ID sent by the agent, if any
	Conversation string // conversation ID, for calls without a session ID
	Agent        string
	Principal    string
	First, Last  time.Time
	Calls        int
	Tools        int
	Flags        int
	In, Out      int
	seqs         []uint64
}

// Name is how the session is shown.
func (s Session) Name() string {
	switch {
	case s.ID != "":
		return s.ID
	case s.Conversation != "":
		return "conversation " + s.Conversation
	}
	return "(no session)"
}

// Index is a summary of a log, safe for concurrent use.
type Index struct {
	path string

	mu       sync.RWMutex
	entries  []Entry // in log order
	sessions map[string]*Session
	off      int64 // bytes of complete lines read so far
	err      error // set when an entry could not be read; indexing stops there

	file     os.FileInfo // the file read so far, to notice it being replaced
	lastHead []byte      // the start of the last line read, to notice it changing
	// lost is the last entry read before the file became shorter. Shrunk
	// reports it until the file holds that entry again, as it does once a
	// copy being rewritten in place is complete.
	lost     []byte
	lostSeq  uint64
	replaced bool // the file was replaced or rewritten with other content
}

// headLen is how much of a line is kept to recognize it: enough to include
// its seq and hash, which no other entry shares.
const headLen = 256

func lineHead(line []byte) []byte { return bytes.Clone(line[:min(len(line), headLen)]) }

// Open reads the log at path into a new index.
func Open(path string) (*Index, error) {
	x := &Index{path: path, sessions: map[string]*Session{}}
	if err := x.Refresh(); err != nil {
		return nil, err
	}
	return x, nil
}

// Refresh reads entries appended since the last call. A final line without
// its newline is still being written and is left for a later call. If the
// file has become shorter than what was read, entries were removed: the
// index is rebuilt from the start and Shrunk reports it. If the file was
// replaced, or its last entry read so far has changed, it is rebuilt too and
// Replaced reports it.
func (x *Index) Refresh() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	f, err := os.Open(x.path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	switch {
	case fi.Size() < x.off:
		if n := len(x.entries); n > 0 && x.lost == nil {
			x.lost, x.lostSeq = x.lastHead, x.entries[n-1].Seq
		}
		x.reset()
	case x.file != nil && (!os.SameFile(x.file, fi) || !x.sameLastLine(f)):
		x.replaced = true
		x.reset()
	}
	x.file = fi
	if x.err != nil || fi.Size() == x.off {
		return nil
	}
	if _, err := f.Seek(x.off, io.SeekStart); err != nil {
		return err
	}
	br := bufio.NewReaderSize(f, 1<<20)
	off := x.off
	for {
		line, err := br.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			break // nothing more, or a line still being written
		}
		if err != nil {
			x.off = off // keep what was read, so it is not added twice
			return err
		}
		body := bytes.TrimSuffix(line, []byte{'\n'})
		e, perr := ledger.ParseEntry(body)
		if perr != nil {
			x.err = fmt.Errorf("the entry at byte %d could not be read: %v", off, perr)
			break
		}
		x.add(e, off, len(body))
		x.lastHead = lineHead(body)
		if x.lost != nil && e.Seq == x.lostSeq && bytes.Equal(x.lastHead, x.lost) {
			x.lost, x.lostSeq = nil, 0 // the removed entries are back
		}
		off += int64(len(line))
	}
	x.off = off
	return nil
}

func (x *Index) reset() {
	x.entries, x.sessions, x.off, x.err, x.lastHead = nil, map[string]*Session{}, 0, nil, nil
}

// sameLastLine reports whether the last line read still starts as it did.
func (x *Index) sameLastLine(f *os.File) bool {
	n := len(x.entries)
	if n == 0 {
		return true
	}
	b := make([]byte, len(x.lastHead))
	_, err := f.ReadAt(b, x.entries[n-1].Off)
	return err == nil && bytes.Equal(b, x.lastHead)
}

// callHead is the part of a record the index keeps. Bodies are not decoded.
type callHead struct {
	Type       string           `json:"type"`
	Time       time.Time        `json:"ts"`
	InstanceID string           `json:"instance_id"`
	Agent      record.Agent     `json:"agent"`
	Session    record.Session   `json:"session"`
	Principal  string           `json:"principal"`
	Turn       int              `json:"turn"`
	Anomalies  []record.Anomaly `json:"anomalies"`
	Request    struct {
		ModelRequested string `json:"model_requested"`
	} `json:"request"`
	Upstream struct {
		ModelServed string `json:"model_served"`
	} `json:"upstream"`
	Response struct {
		Status    int `json:"status"`
		ToolCalls []struct {
			Name   string `json:"name"`
			Risk   string `json:"risk"`
			InText bool   `json:"in_text"`
		} `json:"tool_calls"`
		Usage record.Usage `json:"usage"`
	} `json:"response"`
	Error  *record.Error `json:"error"`
	Timing record.Timing `json:"timing"`
}

func (x *Index) add(le ledger.Entry, off int64, n int) {
	var h callHead
	json.Unmarshal(le.Rec, &h) // a record that does not decode is listed by its seq alone
	e := Entry{Seq: le.Seq, Off: off, Len: n, Type: h.Type, Time: h.Time, Instance: h.InstanceID}
	if h.Type == record.TypeLLMCall {
		e.Time = h.Timing.ReceivedAt
		e.Agent, e.Principal, e.Turn = h.Agent.ID, h.Principal, h.Turn
		e.Model = h.Upstream.ModelServed
		if e.Model == "" {
			e.Model = h.Request.ModelRequested
		}
		e.Status = h.Response.Status
		if h.Error != nil {
			e.ErrorClass = h.Error.Class
		}
		e.In, e.Out = h.Response.Usage.Input, h.Response.Usage.Output
		for _, tc := range h.Response.ToolCalls {
			e.Tools = append(e.Tools, Tool{Name: tc.Name, Risk: tc.Risk, InText: tc.InText})
		}
		e.Anomalies = h.Anomalies
		e.Session = x.addToSession(&e, h.Session, h.Timing.CompletedAt)
	}
	x.entries = append(x.entries, e)
}

func (x *Index) addToSession(e *Entry, rs record.Session, done time.Time) string {
	key := "-"
	switch {
	case rs.ID != "":
		key = "s:" + rs.ID
	case rs.Conversation != "":
		key = "c:" + rs.Conversation
	}
	s := x.sessions[key]
	if s == nil {
		s = &Session{Key: key, ID: rs.ID, Conversation: rs.Conversation, First: e.Time}
		x.sessions[key] = s
	}
	if s.Agent == "" {
		s.Agent = e.Agent
	}
	if s.Principal == "" {
		s.Principal = e.Principal
	}
	if e.Time.Before(s.First) {
		s.First = e.Time
	}
	for _, t := range []time.Time{e.Time, done} {
		if t.After(s.Last) {
			s.Last = t
		}
	}
	s.Calls++
	s.Tools += len(e.Tools)
	s.Flags += len(e.Anomalies)
	s.In += e.In
	s.Out += e.Out
	s.seqs = append(s.seqs, e.Seq)
	return key
}

// Err reports why indexing stopped early, or nil.
func (x *Index) Err() error {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.err
}

// Shrunk reports whether entries read earlier are missing from the end of
// the file.
func (x *Index) Shrunk() bool {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.lost != nil
}

// Replaced reports whether the file was ever replaced, or its entries
// rewritten, while it was being read.
func (x *Index) Replaced() bool {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.replaced
}

// Len returns the number of entries indexed.
func (x *Index) Len() int {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return len(x.entries)
}

// Stats are totals over the log.
type Stats struct {
	Entries      int
	Calls        int
	Sessions     int
	Flagged      int // calls with at least one anomaly
	CallsSince   int // calls received at or after the time given to Stats
	FlaggedSince int
	Last         time.Time // when the newest call was received
}

// Stats counts calls in the whole log and since the given time.
func (x *Index) Stats(since time.Time) Stats {
	x.mu.RLock()
	defer x.mu.RUnlock()
	st := Stats{Entries: len(x.entries), Sessions: len(x.sessions)}
	for i := range x.entries {
		e := &x.entries[i]
		if e.Type != record.TypeLLMCall {
			continue
		}
		flagged := len(e.Anomalies) > 0
		st.Calls++
		if flagged {
			st.Flagged++
		}
		if !e.Time.Before(since) {
			st.CallsSince++
			if flagged {
				st.FlaggedSince++
			}
		}
		if e.Time.After(st.Last) {
			st.Last = e.Time
		}
	}
	return st
}

// Day is activity on one calendar day.
type Day struct {
	Start   time.Time // midnight, local time
	Calls   int
	Flagged int
	In, Out int // tokens
}

// Activity returns one Day for each of the n days ending with the day of
// now, oldest first, counting calls by when they were received.
func (x *Index) Activity(n int, now time.Time) []Day {
	now = now.Local()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	days := make([]Day, n)
	for i := range days {
		days[i].Start = today.AddDate(0, 0, i-n+1)
	}
	first := days[0].Start
	x.mu.RLock()
	defer x.mu.RUnlock()
	for i := range x.entries {
		e := &x.entries[i]
		if e.Type != record.TypeLLMCall || e.Time.Before(first) || !e.Time.Before(today.AddDate(0, 0, 1)) {
			continue
		}
		t := e.Time.Local()
		d := &days[sort.Search(n, func(j int) bool { return days[j].Start.After(t) })-1]
		d.Calls++
		if len(e.Anomalies) > 0 {
			d.Flagged++
		}
		d.In += e.In
		d.Out += e.Out
	}
	return days
}

// ToolCount is how often the model asked to use a tool.
type ToolCount struct {
	Name  string
	Risk  string // as recorded on the most recent call
	Calls int
}

// TopTools returns the n tools the model asked to use most, most used first.
func (x *Index) TopTools(n int) []ToolCount {
	x.mu.RLock()
	byName := map[string]*ToolCount{}
	for i := range x.entries {
		for _, t := range x.entries[i].Tools {
			c := byName[t.Name]
			if c == nil {
				c = &ToolCount{Name: t.Name}
				byName[t.Name] = c
			}
			c.Calls++
			c.Risk = t.Risk
		}
	}
	x.mu.RUnlock()
	out := make([]ToolCount, 0, len(byName))
	for _, c := range byName {
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b ToolCount) int {
		if a.Calls != b.Calls {
			return b.Calls - a.Calls
		}
		return cmpString(a.Name, b.Name)
	})
	return out[:min(n, len(out))]
}

// Entries returns the newest entries for which keep returns true, at most
// limit of them (0 for no limit), and how many entries match in all.
func (x *Index) Entries(keep func(*Entry) bool, limit int) ([]Entry, int) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	var out []Entry
	total := 0
	for i := len(x.entries) - 1; i >= 0; i-- {
		if e := &x.entries[i]; keep == nil || keep(e) {
			total++
			if limit == 0 || len(out) < limit {
				out = append(out, *e)
			}
		}
	}
	return out, total
}

// Entry returns the summary of the entry with the given seq.
func (x *Index) Entry(seq uint64) (Entry, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	i, ok := x.find(seq)
	if !ok {
		return Entry{}, false
	}
	return x.entries[i], true
}

func (x *Index) find(seq uint64) (int, bool) {
	i := sort.Search(len(x.entries), func(i int) bool { return x.entries[i].Seq >= seq })
	return i, i < len(x.entries) && x.entries[i].Seq == seq
}

// Sessions returns every session, most recently active first.
func (x *Index) Sessions() []Session {
	x.mu.RLock()
	defer x.mu.RUnlock()
	out := make([]Session, 0, len(x.sessions))
	for _, s := range x.sessions {
		c := *s
		c.seqs = nil
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b Session) int {
		if c := b.Last.Compare(a.Last); c != 0 {
			return c
		}
		return cmpString(a.Key, b.Key)
	})
	return out
}

// Session returns the session with the given key and, in log order, its
// last limit calls (0 for all) before the entry numbered before (0 for the
// newest).
func (x *Index) Session(key string, before uint64, limit int) (Session, []Entry, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	s, ok := x.sessions[key]
	if !ok {
		return Session{}, nil, false
	}
	seqs := s.seqs
	if before > 0 {
		seqs = seqs[:sort.Search(len(seqs), func(i int) bool { return seqs[i] >= before })]
	}
	if limit > 0 && len(seqs) > limit {
		seqs = seqs[len(seqs)-limit:]
	}
	calls := make([]Entry, 0, len(seqs))
	for _, seq := range seqs {
		if i, ok := x.find(seq); ok {
			calls = append(calls, x.entries[i])
		}
	}
	c := *s
	c.seqs = nil
	return c, calls, true
}

// ReadLine returns the line of e exactly as stored, without its newline.
func (x *Index) ReadLine(e Entry) ([]byte, error) {
	f, err := os.Open(x.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, e.Len)
	if _, err := f.ReadAt(b, e.Off); err != nil {
		return nil, err
	}
	return b, nil
}

// Read returns the full entry with the given seq, read from the file.
func (x *Index) Read(seq uint64) (ledger.Entry, error) {
	e, ok := x.Entry(seq)
	if !ok {
		return ledger.Entry{}, fmt.Errorf("no entry %d", seq)
	}
	b, err := x.ReadLine(e)
	if err != nil {
		return ledger.Entry{}, err
	}
	le, err := ledger.ParseEntry(b)
	if err != nil {
		return ledger.Entry{}, err
	}
	if le.Seq != seq {
		return ledger.Entry{}, fmt.Errorf("entry %d has moved in the file; reload the page", seq)
	}
	return le, nil
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
