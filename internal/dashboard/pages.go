package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bkodzo/blackbox/internal/audit"
	"github.com/bkodzo/blackbox/internal/index"
	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
)

// listLimit caps the rows a list page shows.
const listLimit = 500

// bodyShown is how much of a body the call page shows; the rest is in the
// raw entry, which can be downloaded.
const bodyShown = 256 << 10

func (s *Server) routes() {
	s.mux.HandleFunc("GET /{$}", s.overview)
	s.mux.HandleFunc("GET /sessions", s.sessions)
	s.mux.HandleFunc("GET /session", s.session)
	s.mux.HandleFunc("GET /flags", s.flags)
	s.mux.HandleFunc("GET /call/{seq}", s.call)
	s.mux.HandleFunc("GET /call/{seq}/raw", s.raw)
	s.mux.HandleFunc("GET /integrity", s.integrityPage)
	s.mux.HandleFunc("GET /report", s.reportPage)
	s.mux.HandleFunc("POST /verify", s.verify)
	s.mux.HandleFunc("GET /status.json", s.status)
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { s.notFound(w, "There is no page at that address.") })
}

var funcs = template.FuncMap{
	"ts": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Local().Format("2006-01-02 15:04:05")
	},
	"stamp": func(s string) string { // an RFC 3339 time as stored in a checkpoint
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return s
		}
		return t.Local().Format("2006-01-02 15:04:05")
	},
	"clock": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Local().Format("15:04:05")
	},
	"span": func(a, b time.Time) string {
		if a.IsZero() || b.Before(a) {
			return "-"
		}
		return b.Sub(a).Round(time.Millisecond).String()
	},
	"verdictClass": func(v audit.Verdict) string {
		return map[audit.Verdict]string{audit.Intact: "ok", audit.Warnings: "warn", audit.Tampered: "bad"}[v]
	},
	"sessionName": sessionName,
	"prev":        func(n uint64) uint64 { return n - 1 },
	"next":        func(n uint64) uint64 { return n + 1 },
	"flag":        flag,
	"short":       short,
	"day":         func(t time.Time) string { return t.Format("Mon Jan 2") },
	"errorTitle":  errorTitle,
	"plural": func(n int, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %s", n, many)
	},
	"orDash": func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	},
	"clip": func(s string, n int) string {
		r := []rune(strings.Join(strings.Fields(s), " "))
		if len(r) <= n {
			return string(r)
		}
		return string(r[:n-3]) + "..."
	},
	"kinds": func(as []record.Anomaly) []string {
		var ks []string
		for _, a := range as {
			if !slices.Contains(ks, a.Kind) {
				ks = append(ks, a.Kind)
			}
		}
		return ks
	},
}

// sessionName turns a session key from the index into its display name.
func sessionName(key string) string {
	switch {
	case strings.HasPrefix(key, "s:"):
		return key[2:]
	case strings.HasPrefix(key, "c:"):
		return "conversation " + key[2:]
	}
	return "(no session)"
}

func parsePages() (map[string]*template.Template, error) {
	pages := map[string]*template.Template{}
	for _, name := range []string{"overview", "sessions", "session", "flags", "call", "integrity", "report", "error"} {
		t, err := template.New(name).Funcs(funcs).ParseFS(files, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		pages[name] = t
	}
	return pages, nil
}

// page is what every template receives.
type page struct {
	Title     string
	Nav       string
	Log       string
	Entries   int
	Integrity integrity
	IndexErr  error
	Shrunk    bool
	Replaced  bool
	Data      any
}

func (s *Server) render(w http.ResponseWriter, status int, name, title string, data any) {
	p := page{
		Title: title, Nav: name, Log: s.cfg.Log, Entries: s.idx.Len(),
		Integrity: s.integrity(), IndexErr: s.idx.Err(), Shrunk: s.idx.Shrunk(), Replaced: s.idx.Replaced(), Data: data,
	}
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		log.Printf("rendering %s: %v", name, err)
		http.Error(w, "the page could not be shown", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func (s *Server) notFound(w http.ResponseWriter, what string) {
	s.render(w, http.StatusNotFound, "error", "Not found", what)
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	day := time.Now().Add(-24 * time.Hour)
	isCall := func(e *index.Entry) bool { return e.Type == record.TypeLLMCall }
	attention, _ := s.idx.Entries(func(e *index.Entry) bool { return len(e.Anomalies) > 0 }, 8)
	recent, _ := s.idx.Entries(isCall, 10)
	s.render(w, http.StatusOK, "overview", "Overview", struct {
		Stats     index.Stats
		Attention []index.Entry
		Recent    []index.Entry
		Activity  activity
	}{s.idx.Stats(day), attention, recent, buildActivity(s.idx, time.Now())})
}

func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	flagged := r.URL.Query().Get("flagged") != ""
	var rows []index.Session
	total := 0
	for _, ss := range s.idx.Sessions() {
		if flagged && ss.Flags == 0 {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(ss.Name()+" "+ss.Agent+" "+ss.Principal), q) {
			continue
		}
		total++
		if len(rows) < listLimit {
			rows = append(rows, ss)
		}
	}
	s.render(w, http.StatusOK, "sessions", "Sessions", struct {
		Q       string
		Flagged bool
		Rows    []index.Session
		Total   int
		Limit   int
	}{q, flagged, rows, total, listLimit})
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	before, _ := strconv.ParseUint(r.URL.Query().Get("before"), 10, 64)
	ss, calls, ok := s.idx.Session(key, before, listLimit)
	if !ok {
		s.notFound(w, "No session with that key is in the log.")
		return
	}
	// Earlier is the entry to page back from, when older calls exist.
	var earlier uint64
	if len(calls) > 0 {
		if _, older, _ := s.idx.Session(key, calls[0].Seq, 1); len(older) > 0 {
			earlier = calls[0].Seq
		}
	}
	s.render(w, http.StatusOK, "session", "Session "+ss.Name(), struct {
		Session index.Session
		Calls   []index.Entry
		Earlier uint64
		Paged   bool
		Limit   int
	}{ss, calls, earlier, before > 0, listLimit})
}

func (s *Server) flags(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind, agent := q.Get("kind"), strings.TrimSpace(q.Get("agent"))
	from, _ := time.ParseInLocation("2006-01-02", q.Get("from"), time.Local)
	to, _ := time.ParseInLocation("2006-01-02", q.Get("to"), time.Local)
	rows, total := s.idx.Entries(func(e *index.Entry) bool {
		switch {
		case len(e.Anomalies) == 0,
			kind != "" && !slices.ContainsFunc(e.Anomalies, func(a record.Anomaly) bool { return a.Kind == kind }),
			agent != "" && e.Agent != agent,
			!from.IsZero() && e.Time.Before(from),
			!to.IsZero() && !e.Time.Before(to.AddDate(0, 0, 1)):
			return false
		}
		return true
	}, listLimit)
	kinds := make([]string, 0, len(flagInfos))
	for k := range flagInfos {
		kinds = append(kinds, k)
	}
	slices.SortFunc(kinds, func(a, b string) int { return strings.Compare(flag(a).Title, flag(b).Title) })
	s.render(w, http.StatusOK, "flags", "Flags", struct {
		Kind, Agent, From, To string
		Kinds                 []string
		Rows                  []index.Entry
		Total, Limit          int
	}{kind, agent, q.Get("from"), q.Get("to"), kinds, rows, total, listLimit})
}

// shownBody is a body prepared for display.
type shownBody struct {
	Text      string
	Encoding  string
	Bytes     int64
	SHA256    string
	Clipped   bool // only the start is shown
	Truncated bool // the gateway stored only the start
}

func showBody(b record.Body) shownBody {
	text := b.Text
	if b.Base64 != "" {
		text = b.Base64
	}
	sb := shownBody{Encoding: "text", Bytes: b.Bytes, SHA256: b.SHA256, Truncated: b.Truncated}
	if b.Base64 != "" {
		sb.Encoding = "base64"
	} else if len(text) <= bodyShown && json.Valid([]byte(text)) {
		var out bytes.Buffer
		if json.Indent(&out, []byte(text), "", "  ") == nil {
			text = out.String()
		}
	}
	if len(text) > bodyShown {
		text, sb.Clipped = strings.ToValidUTF8(text[:bodyShown], ""), true
	}
	sb.Text = text
	return sb
}

func (s *Server) entry(w http.ResponseWriter, r *http.Request) (ledger.Entry, bool) {
	seq, err := strconv.ParseUint(r.PathValue("seq"), 10, 64)
	if err != nil {
		s.notFound(w, "That is not an entry number.")
		return ledger.Entry{}, false
	}
	le, err := s.idx.Read(seq)
	if err != nil {
		s.notFound(w, fmt.Sprintf("Entry %d could not be read: %v", seq, err))
		return ledger.Entry{}, false
	}
	return le, true
}

func (s *Server) call(w http.ResponseWriter, r *http.Request) {
	le, ok := s.entry(w, r)
	if !ok {
		return
	}
	sum, _ := s.idx.Entry(le.Seq)
	data := struct {
		Entry   ledger.Entry
		Summary index.Entry
		Call    *record.LLMCall
		Req     shownBody
		Resp    shownBody
		Record  string // other entries, shown as indented JSON
	}{Entry: le, Summary: sum}
	if sum.Type == record.TypeLLMCall {
		var c record.LLMCall
		if err := json.Unmarshal(le.Rec, &c); err == nil {
			data.Call = &c
			data.Req, data.Resp = showBody(c.Request.Body), showBody(c.Response.Body)
		}
	}
	if data.Call == nil {
		var out bytes.Buffer
		json.Indent(&out, le.Rec, "", "  ")
		data.Record = out.String()
	}
	s.render(w, http.StatusOK, "call", fmt.Sprintf("Entry %d", le.Seq), data)
}

// raw serves the entry exactly as stored, as a download, so it is never
// rendered by the browser.
func (s *Server) raw(w http.ResponseWriter, r *http.Request) {
	le, ok := s.entry(w, r)
	if !ok {
		return
	}
	sum, _ := s.idx.Entry(le.Seq)
	b, err := s.idx.ReadLine(sum)
	if err != nil {
		s.notFound(w, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="entry-%d.json"`, le.Seq))
	w.Write(b)
}

func (s *Server) integrityPage(w http.ResponseWriter, r *http.Request) {
	var cps []ledger.Checkpoint
	var cpErr error
	if s.cfg.Checkpoints != "" {
		cps, _, cpErr = ledger.ReadCheckpoints(s.cfg.Checkpoints)
	}
	slices.Reverse(cps)
	shown := cps
	if len(shown) > 50 {
		shown = shown[:50]
	}
	s.render(w, http.StatusOK, "integrity", "Integrity", struct {
		Checkpoints     string
		CheckpointList  []ledger.Checkpoint
		CheckpointCount int
		CheckpointErr   error
	}{s.cfg.Checkpoints, shown, len(cps), cpErr})
}

// verify starts a check, or joins the one running, and waits briefly for it
// so the page that follows usually shows the result.
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	select {
	case <-s.startCheck():
	case <-time.After(30 * time.Second):
	case <-r.Context().Done():
		return
	}
	http.Redirect(w, r, "/integrity", http.StatusSeeOther)
}

// status lets open pages notice new entries without reloading.
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"entries":%d}`, s.idx.Len())
}

// reportLimit caps the calls a report lists; a report that needs more is
// better made from the log itself.
const reportLimit = 2000

// kindCount is how often one kind of anomaly was flagged.
type kindCount struct {
	Kind  string
	Count int
}

// reportData is a summary of a session or a date range, for printing.
type reportData struct {
	Scope     string // what the report covers, in words
	Form      bool   // no scope was chosen yet
	From, To  string
	Generated time.Time
	Calls     int
	In, Out   int
	Sessions  []index.Session
	Session   *index.Session // set for a report on one session
	Kinds     []kindCount
	Flagged   []index.Entry
	Timeline  []index.Entry // the session's calls, for a report on one session
	Clipped   bool          // more calls matched than reportLimit
}

func (s *Server) reportPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := reportData{Generated: time.Now(), From: q.Get("from"), To: q.Get("to")}
	var calls []index.Entry
	switch key := q.Get("key"); {
	case key != "":
		ss, cs, ok := s.idx.Session(key, 0, reportLimit)
		if !ok {
			s.notFound(w, "No session with that key is in the log.")
			return
		}
		d.Session, d.Timeline, calls, d.Clipped = &ss, cs, cs, ss.Calls > len(cs)
		d.Scope = "Session " + ss.Name()
	case d.From != "" || d.To != "":
		from, ferr := time.ParseInLocation("2006-01-02", d.From, time.Local)
		to, terr := time.ParseInLocation("2006-01-02", d.To, time.Local)
		if (d.From != "" && ferr != nil) || (d.To != "" && terr != nil) || (d.From != "" && d.To != "" && to.Before(from)) {
			s.render(w, http.StatusBadRequest, "error", "Bad dates", "Give the dates as year-month-day, with the start no later than the end.")
			return
		}
		var total int
		calls, total = s.idx.Entries(func(e *index.Entry) bool {
			return e.Type == record.TypeLLMCall && (from.IsZero() || !e.Time.Before(from)) && (to.IsZero() || e.Time.Before(to.AddDate(0, 0, 1)))
		}, reportLimit)
		d.Clipped = total > len(calls)
		slices.Reverse(calls)
		d.Scope = "Calls " + describeRange(d.From, d.To)
	default:
		d.Form = true
		s.render(w, http.StatusOK, "report", "Report", d)
		return
	}

	kinds := map[string]int{}
	bySession := map[string]*index.Session{}
	var order []string
	for _, c := range calls {
		d.Calls++
		d.In += c.In
		d.Out += c.Out
		if len(c.Anomalies) > 0 {
			d.Flagged = append(d.Flagged, c)
		}
		for _, a := range c.Anomalies {
			kinds[a.Kind]++
		}
		ss := bySession[c.Session]
		if ss == nil {
			ss = &index.Session{Key: c.Session, Agent: c.Agent, Principal: c.Principal, First: c.Time}
			bySession[c.Session] = ss
			order = append(order, c.Session)
		}
		ss.Calls++
		ss.Tools += len(c.Tools)
		ss.Flags += len(c.Anomalies)
		ss.Last = c.Time
	}
	for _, k := range order {
		d.Sessions = append(d.Sessions, *bySession[k])
	}
	for k, n := range kinds {
		d.Kinds = append(d.Kinds, kindCount{k, n})
	}
	slices.SortFunc(d.Kinds, func(a, b kindCount) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.Kind, b.Kind)
	})
	s.render(w, http.StatusOK, "report", "Report: "+d.Scope, d)
}

func describeRange(from, to string) string {
	switch {
	case from != "" && to != "":
		return "from " + from + " to " + to
	case from != "":
		return "from " + from
	}
	return "up to " + to
}
