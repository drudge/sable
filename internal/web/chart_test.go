package web

import (
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/web/pages"
)

func TestStatsHistoryBuildsRealCounterDeltaSeries(t *testing.T) {
	t.Parallel()

	started := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	history := newStatsHistory()
	history.record(started, dnsserver.Stats{Queries: 10, CacheHits: 2})
	history.record(started.Add(5*time.Second), dnsserver.Stats{
		Queries: 15, Blocked: 1, CacheHits: 5,
	})

	view := history.view("hour", started.Add(5*time.Second), dnsserver.Stats{
		Queries: 15, Blocked: 1, CacheHits: 5,
	}, pages.TimeDisplay{Format: pages.TimeFormat12})
	if !view.HasActivity || view.ActiveRange != "hour" {
		t.Fatalf("chart view = %+v", view)
	}
	if !strings.Contains(view.Total, "58.0,24.0") || view.Blocked == "" || view.CacheHits == "" {
		t.Fatalf("chart coordinates = total %q blocked %q cache %q", view.Total, view.Blocked, view.CacheHits)
	}
	wantCustomStart := started.Add(5 * time.Second).Add(-7 * 24 * time.Hour).Local().Format("2006-01-02T15:04")
	if view.CustomStart != wantCustomStart {
		t.Fatalf("default custom start = %q, want %q", view.CustomStart, wantCustomStart)
	}
}

func TestChartDurationRejectsUnknownRange(t *testing.T) {
	t.Parallel()

	if _, valid := chartDuration("forever"); valid {
		t.Fatal("chartDuration() accepted an unknown range")
	}
}

func TestChartTimeFormatHonorsDisplayPreference(t *testing.T) {
	t.Parallel()

	if got := chartTimeFormat(time.Hour, pages.TimeDisplay{Format: pages.TimeFormat12}); got != "3:04:05 PM" {
		t.Fatalf("12-hour chart format = %q", got)
	}
	if got := chartTimeFormat(time.Hour, pages.TimeDisplay{Format: pages.TimeFormat24}); got != "15:04:05" {
		t.Fatalf("24-hour chart format = %q", got)
	}
}

func TestStatsHistoryBuildsCustomRange(t *testing.T) {
	t.Parallel()

	started := time.Now().Add(-30 * time.Minute).Truncate(time.Minute)
	history := newStatsHistory()
	history.record(started, dnsserver.Stats{Queries: 10, NoError: 8})
	history.record(started.Add(5*time.Minute), dnsserver.Stats{Queries: 14, NoError: 12})

	view := history.customView(started.Add(-time.Minute), started.Add(10*time.Minute), dnsserver.Stats{Queries: 14, NoError: 12}, pages.TimeDisplay{Format: pages.TimeFormat12})
	if !view.HasActivity || view.ActiveRange != "custom" {
		t.Fatalf("custom chart view = %+v", view)
	}
	if view.CustomStart == "" || view.CustomEnd == "" || view.Total == "" {
		t.Fatalf("custom chart fields = %+v", view)
	}
}
