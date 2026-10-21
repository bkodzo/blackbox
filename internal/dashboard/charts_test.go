package dashboard

import (
	"math"
	"testing"
	"time"

	"github.com/bkodzo/blackbox/internal/index"
)

func TestScaleAndNumbers(t *testing.T) {
	for n, want := range map[int]int{0: 1, 1: 1, 2: 2, 3: 5, 7: 10, 10: 10, 11: 20, 480: 500, 501: 1000} {
		if got := niceCeil(n); got != want {
			t.Errorf("niceCeil(%d) = %d, want %d", n, got, want)
		}
	}
	for n, want := range map[int]string{950: "950", 9999: "9999", 12300: "12.3k", 20000: "20k", 4_500_000: "4.5M", 2_000_000: "2M"} {
		if got := short(n); got != want {
			t.Errorf("short(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestBarsStackWithinThePlot(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.Local)
	var days []index.Day
	for i := range 30 {
		days = append(days, index.Day{Start: start.AddDate(0, 0, i), Calls: i, Flagged: i / 3})
	}
	c := stacked(days, "", "lo", "hi",
		func(d index.Day) int { return d.Flagged },
		func(d index.Day) int { return d.Calls - d.Flagged },
		func(d index.Day) string { return "" })
	if len(c.Bars) != 30 || c.Max != "50" {
		t.Fatalf("%d bars, scale %s", len(c.Bars), c.Max)
	}
	for i, b := range c.Bars {
		near := func(a, b float64) bool { return math.Abs(a-b) < 0.01 }
		if !near(b.Lo.Y+b.Lo.H, c.Base) || !near(b.Hi.Y+b.Hi.H, b.Lo.Y) || b.Hi.Y < chartTop-0.01 || b.X+b.W > chartW {
			t.Fatalf("bar %d out of place: %+v", i, b)
		}
	}
	if last := c.Ticks[len(c.Ticks)-1]; last.Text != "Oct 30" {
		t.Fatalf("last label %q", last.Text)
	}
	// An empty month draws flat bars on a scale of 1.
	empty := stacked(make([]index.Day, 30), "", "", "", func(index.Day) int { return 0 }, func(index.Day) int { return 0 }, func(index.Day) string { return "" })
	if empty.Max != "1" || empty.Bars[0].Lo.H != 0 {
		t.Fatalf("empty chart %+v", empty.Bars[0])
	}
}
