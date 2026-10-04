package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bkodzo/blackbox/internal/ledger"
	"github.com/bkodzo/blackbox/internal/record"
)

const noSession = "(no session)"

// eachCall reads the log and calls fn for every model call, with its seq.
func eachCall(path string, fn func(uint64, *record.LLMCall)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return ledger.Scan(f, func(e ledger.Entry) error {
		var h struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(e.Rec, &h); err != nil {
			return fmt.Errorf("seq %d: %w", e.Seq, err)
		}
		if h.Type != record.TypeLLMCall {
			return nil
		}
		var c record.LLMCall
		if err := json.Unmarshal(e.Rec, &c); err != nil {
			return fmt.Errorf("seq %d: %w", e.Seq, err)
		}
		fn(e.Seq, &c)
		return nil
	})
}

type sessionSummary struct {
	id, agent        string
	calls, tools     int
	anomalies        int
	tokensIn, tokOut int
	first, last      time.Time
}

func runSessions(args []string) int {
	fs := flag.NewFlagSet("sessions", flag.ExitOnError)
	logPath := fs.String("log", "blackbox.jsonl", "audit log file")
	fs.Parse(args)

	byID := map[string]*sessionSummary{}
	err := eachCall(*logPath, func(_ uint64, c *record.LLMCall) {
		id := c.Session.ID
		if id == "" {
			id = noSession
		}
		s, ok := byID[id]
		if !ok {
			s = &sessionSummary{id: id, agent: c.Agent.ID, first: c.Timing.ReceivedAt}
			byID[id] = s
		}
		s.calls++
		s.tools += len(c.Response.ToolCalls)
		s.anomalies += len(c.Anomalies)
		s.tokensIn += c.Response.Usage.Input
		s.tokOut += c.Response.Usage.Output
		s.last = c.Timing.CompletedAt
	})
	if err != nil {
		return fail("%v", err)
	}
	if len(byID) == 0 {
		fmt.Println("No model calls recorded yet.")
		return 0
	}

	list := make([]*sessionSummary, 0, len(byID))
	for _, s := range byID {
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].first.Before(list[j].first) })

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SESSION\tAGENT\tCALLS\tTOOL CALLS\tANOMALIES\tTOKENS IN\tTOKENS OUT\tSTARTED\tDURATION")
	for _, s := range list {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n",
			safe(s.id), orDash(s.agent), s.calls, s.tools, s.anomalies, s.tokensIn, s.tokOut,
			s.first.Local().Format("2006-01-02 15:04:05"), s.last.Sub(s.first).Round(time.Millisecond))
	}
	tw.Flush()
	fmt.Println("\nThese views read the log without checking it. Run `blackbox verify` to confirm it is intact.")
	return 0
}

func runShow(args []string) int {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	logPath := fs.String("log", "blackbox.jsonl", "audit log file")
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fail("usage: blackbox show [--log FILE] SESSION")
	}
	want := fs.Arg(0)
	if want == noSession {
		want = ""
	}

	found := 0
	err := eachCall(*logPath, func(seq uint64, c *record.LLMCall) {
		if c.Session.ID != want {
			return
		}
		if found == 0 {
			fmt.Printf("Session %s, agent %s\n\n", orDash(want), orDash(c.Agent.ID))
		}
		found++
		printCall(seq, c)
	})
	if err != nil {
		return fail("%v", err)
	}
	if found == 0 {
		return fail("no calls recorded for session %q", fs.Arg(0))
	}
	fmt.Println("\n" + showLegend)
	return 0
}

func printCall(seq uint64, c *record.LLMCall) {
	model := c.Upstream.ModelServed
	if model == "" {
		model = c.Request.ModelRequested
	}
	latency := c.Timing.CompletedAt.Sub(c.Timing.ReceivedAt).Round(time.Millisecond)
	fmt.Printf("#%d  %s  turn %d  %s  status %d  %s  %d in / %d out tokens\n",
		seq, c.Timing.ReceivedAt.Local().Format("15:04:05"), c.Turn, orDash(model),
		c.Response.Status, latency, c.Response.Usage.Input, c.Response.Usage.Output)
	if r := c.Response.Reasoning; r != nil {
		switch {
		case r.Preview != "":
			fmt.Printf("      reasoning %s\n", clip(r.Preview, 120))
		case r.RedactedBlocks > 0:
			fmt.Printf("      reasoning (returned encrypted, %d blocks)\n", r.RedactedBlocks)
		}
	}
	for _, tc := range c.Response.ToolCalls {
		label := "tool    "
		if tc.InText {
			label = "tool*   "
		}
		fmt.Printf("      %s %s %s  [risk: %s]\n", label, safe(tc.Name), clip(tc.Arguments, 80), orDash(tc.Risk))
	}
	for _, l := range c.ToolResultsIn {
		if l.MatchedSeq > 0 {
			fmt.Printf("      result   for %s, requested in #%d\n", safe(l.ToolCallID), l.MatchedSeq)
		}
	}
	for _, a := range c.Anomalies {
		fmt.Printf("      ANOMALY  %s: %s\n", safe(a.Kind), safe(a.Detail))
	}
	if c.Error != nil {
		fmt.Printf("      ERROR    %s: %s\n", safe(c.Error.Class), safe(c.Error.Message))
	}
	if c.Response.FinishReason == "stop" || c.Response.FinishReason == "end_turn" {
		fmt.Println("      answer   final response returned")
	}
}

// showLegend explains marks used by printCall.
const showLegend = "tool* = written in the reply text instead of made as a tool call; the agent may not have run it"

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return safe(s)
}

// clip collapses whitespace, escapes, and shortens s to at most n runes.
func clip(s string, n int) string {
	r := []rune(safe(strings.Join(strings.Fields(s), " ")))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n-3]) + "..."
}

// safe escapes control characters and Unicode direction controls in text
// that came from agents or models, so it cannot move the cursor, erase
// lines, or visually reorder what an auditor reads.
func safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || isDirectionControl(r) {
			fmt.Fprintf(&b, `\u%04x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isDirectionControl(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}
