package dashboard

import (
	"fmt"
	"math"
	"time"

	"github.com/bkodzo/blackbox/internal/index"
)

// Charts are drawn as SVG on the server, with no script, from bar geometry
// computed here. Each value is split in two stacked parts so one chart can
// show, say, flagged calls within all calls.

const (
	chartW   = 720.0
	chartH   = 150.0
	chartTop = 8.0  // room above the tallest bar
	chartBot = 26.0 // room below the bars for day labels
)

type segment struct{ Y, H float64 }

type bar struct {
	X, W   float64
	Lo, Hi segment // the lower part and the part stacked on it
	Title  string  // shown on hover and read by screen readers
}

type tick struct {
	X      float64
	Text   string
	Anchor string // where the text sits relative to X, so edge labels stay inside
}

type chart struct {
	W, H    float64
	Base    float64 // y of the baseline
	Bars    []bar
	Ticks   []tick
	Max     string // the value of the top of the scale
	Label   string // what the chart shows, for screen readers
	LoClass string
	HiClass string
}

// stacked lays out one bar per day with lo(d) under hi(d).
func stacked(days []index.Day, label, loClass, hiClass string, lo, hi func(index.Day) int, title func(index.Day) string) chart {
	c := chart{W: chartW, H: chartH, Base: chartH - chartBot, Label: label, LoClass: loClass, HiClass: hiClass}
	peak := 0
	for _, d := range days {
		peak = max(peak, lo(d)+hi(d))
	}
	scale := niceCeil(peak)
	c.Max = short(scale)
	plot := c.Base - chartTop
	slot := chartW / float64(len(days))
	for i, d := range days {
		l, h := float64(lo(d)), float64(hi(d))
		lh := round1(plot * l / float64(scale))
		hh := round1(plot * h / float64(scale))
		c.Bars = append(c.Bars, bar{
			X: round1(float64(i)*slot + 1), W: round1(max(slot-2, 1)),
			Lo:    segment{Y: c.Base - lh, H: lh},
			Hi:    segment{Y: c.Base - lh - hh, H: hh},
			Title: d.Start.Format("Mon Jan 2") + ": " + title(d),
		})
		if i%7 == len(days)%7 || i == len(days)-1 {
			t := tick{X: round1(float64(i)*slot + slot/2), Text: d.Start.Format("Jan 2"), Anchor: "middle"}
			switch {
			case i == len(days)-1:
				t.X, t.Anchor = chartW, "end"
			case i == 0:
				t.X, t.Anchor = 0, "start"
			}
			c.Ticks = append(c.Ticks, t)
		}
	}
	return c
}

// round1 rounds to a tenth of a unit, which keeps the SVG short.
func round1(v float64) float64 { return math.Round(v*10) / 10 }

// niceCeil rounds n up to 1, 2, or 5 times a power of ten, so the scale
// reads well; it is at least 1.
func niceCeil(n int) int {
	if n <= 1 {
		return 1
	}
	for p := 1; ; p *= 10 {
		for _, m := range []int{1, 2, 5} {
			if m*p >= n {
				return m * p
			}
		}
	}
}

// short formats a count compactly: 950, 12.3k, 4.5M.
func short(n int) string {
	switch {
	case n >= 1_000_000:
		return trimZero(fmt.Sprintf("%.1fM", float64(n)/1e6))
	case n >= 10_000:
		return trimZero(fmt.Sprintf("%.1fk", float64(n)/1e3))
	}
	return fmt.Sprint(n)
}

func trimZero(s string) string {
	if len(s) > 3 && s[len(s)-3:len(s)-1] == ".0" {
		return s[:len(s)-3] + s[len(s)-1:]
	}
	return s
}

// activity is the Overview's charts and the data they are drawn from.
type activity struct {
	Days   []index.Day
	Calls  chart
	Tokens chart
	Tools  []toolBar
}

type toolBar struct {
	index.ToolCount
	W float64 // bar width, out of toolBarW
}

const toolBarW = 160.0

func buildActivity(idx *index.Index, now time.Time) activity {
	days := idx.Activity(30, now)
	a := activity{Days: days}
	a.Calls = stacked(days, "Model calls per day for the last 30 days, flagged calls shown at the bottom of each bar", "flagged", "calls",
		func(d index.Day) int { return d.Flagged },
		func(d index.Day) int { return d.Calls - d.Flagged },
		func(d index.Day) string { return fmt.Sprintf("%d calls, %d flagged", d.Calls, d.Flagged) })
	a.Tokens = stacked(days, "Tokens per day for the last 30 days, input at the bottom of each bar and output above it", "tokens-in", "tokens-out",
		func(d index.Day) int { return d.In },
		func(d index.Day) int { return d.Out },
		func(d index.Day) string { return fmt.Sprintf("%d tokens in, %d out", d.In, d.Out) })
	top := idx.TopTools(8)
	for _, t := range top {
		a.Tools = append(a.Tools, toolBar{ToolCount: t, W: max(2, toolBarW*float64(t.Calls)/float64(top[0].Calls))})
	}
	return a
}
