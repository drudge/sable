package blocking

import (
	"context"
	"strings"
	"testing"
	"time"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/querylog"
)

func TestFindingsHonorTheMissedUpdatesLimit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		limits     Limits
		lastUpdate time.Duration
		reported   bool
		method     string
	}{
		{"a day and a half is not two missed updates", Limits{}, 36 * time.Hour, false, ""},
		{"one missed update is enough when asked", Limits{MissedUpdates: 1}, 36 * time.Hour, true, "at least 1 update interval without"},
		{"three days is two missed updates", Limits{}, 72 * time.Hour, true, "at least 2 update intervals without"},
		{"three days is not five missed updates", Limits{MissedUpdates: 5}, 72 * time.Hour, false, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			findings := Findings(FindingsInput{
				Now: now, UpdateInterval: 24 * time.Hour, Limits: test.limits,
				Health: []ListHealth{{Name: "Stale", Health: blockcompiler.SourceHealth{ConsecutiveFailures: 2, LastSuccess: now.Add(-test.lastUpdate)}}},
			})
			if (len(findings) == 1) != test.reported {
				t.Fatalf("findings = %+v, want reported = %t", findings, test.reported)
			}
			if test.reported && !strings.Contains(findings[0].Method, test.method) {
				t.Fatalf("method = %q, want it to say %q", findings[0].Method, test.method)
			}
		})
	}
}

// A kind an operator turned off is never looked for, so it never crowds the
// findings that are on out of the few Insights shows.
func TestFindingsLeaveOutKindsThatAreOff(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	blocks := make([]PastBlock, 0, 3)
	health := make([]ListHealth, 0, 3)
	for _, name := range []string{"a.example", "b.example", "c.example"} {
		blocks = append(blocks, PastBlock{Rule: name, Evidence: querylog.BlockedNameEvidence{Name: name, Blocked: 4}})
		health = append(health, ListHealth{Name: "List " + name, Health: blockcompiler.SourceHealth{ConsecutiveFailures: 3}})
	}
	contribution := Contribution{Analyzed: 3, Lists: []ListContribution{
		{Name: "Big List", Available: true, Domains: 200_000, Unique: 90_000, Covered: 110_000},
		{Name: "Small List", Available: true, Domains: 50_000, Unique: 400, Covered: 49_600, LargestOverlap: Overlap{Name: "Big List", Domains: 49_600}},
		{Name: "Unreadable", Problem: "No cached copy has been downloaded yet"},
	}}
	input := FindingsInput{Now: now, UpdateInterval: time.Hour, PastBlocks: blocks, Health: health, Contribution: &contribution}
	count := func(findings []insights.Finding) map[string]int {
		counts := map[string]int{}
		for _, finding := range findings {
			counts[finding.Kind]++
		}
		return counts
	}
	if counts := count(Findings(input)); counts[KindPastBlock] != 3 || counts[KindUpdateFailing] != 3 || counts[KindLowUnique] != 0 {
		t.Fatalf("with every kind on, findings = %v", counts)
	}
	input.Off = map[string]bool{KindPastBlock: true, KindUniqueCoverage: true}
	counts := count(Findings(input))
	if counts[KindPastBlock] != 0 || counts[KindUniqueCoverage] != 0 {
		t.Fatalf("kinds that are off were reported: %v", counts)
	}
	if counts[KindUpdateFailing] != 3 || counts[KindListUnreadable] != 1 || counts[KindLowUnique] != 1 {
		t.Fatalf("with past blocks and unique coverage off, findings = %v", counts)
	}
}

// countingSources counts how often the analyzer searches for past blocks.
type countingSources struct {
	fakeSources
	pastBlockReads int
}

func (sources *countingSources) PastBlocks(ctx context.Context, window insights.Window) ([]PastBlock, error) {
	sources.pastBlockReads++
	return sources.fakeSources.PastBlocks(ctx, window)
}

func TestAnalyzerSkipsTheSearchForPastBlocksWhenTheyAreOff(t *testing.T) {
	t.Parallel()
	window := insights.Window{Start: time.Unix(0, 0), End: time.Unix(86_400, 0)}
	for _, test := range []struct {
		name  string
		off   map[string]bool
		reads int
	}{
		{"past blocks on", nil, 1},
		{"past blocks off", map[string]bool{KindPastBlock: true}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sources := &countingSources{fakeSources: fakeSources{pastBlocks: []PastBlock{
				{Rule: "a.example", Evidence: querylog.BlockedNameEvidence{Name: "a.example", Blocked: 2, ClientCount: 1}},
			}}}
			findings, err := Analyzer{Sources: sources, Off: test.off}.Analyze(context.Background(), window)
			if err != nil {
				t.Fatal(err)
			}
			if sources.pastBlockReads != test.reads || len(findings) != test.reads {
				t.Fatalf("searches = %d, findings = %+v, want %d of each", sources.pastBlockReads, findings, test.reads)
			}
		})
	}
}
