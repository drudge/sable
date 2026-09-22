package blocking

import (
	"slices"
	"strings"
	"testing"
	"time"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/querylog"
)

func TestAllowRulesMatchLikeTheResolver(t *testing.T) {
	t.Parallel()
	rules := NewAllowRules([]string{"Login.Example.com", "*.cdn.example", "not a domain", "*.Shop.Example."})
	for name, want := range map[string]string{
		"login.example.com.":   "login.example.com",
		"eu.login.example.com": "",
		"cdn.example":          "",
		"img.cdn.example":      "*.cdn.example",
		"a.b.cdn.example.":     "*.cdn.example",
		"www.shop.example":     "*.shop.example",
		"elsewhere.example":    "",
	} {
		if got := rules.Match(name); got != want {
			t.Errorf("Match(%q) = %q, want %q", name, got, want)
		}
	}
	if !slices.Equal(rules.Exact(), []string{"login.example.com"}) || !slices.Equal(rules.Suffixes(), []string{"cdn.example", "shop.example"}) {
		t.Fatalf("rules = %v / %v", rules.Exact(), rules.Suffixes())
	}
	if NewAllowRules(nil).Empty() != true || rules.Empty() {
		t.Fatal("Empty() disagrees with the configured rules")
	}
}

func TestFindingsReportAPastBlockWithItsEvidence(t *testing.T) {
	t.Parallel()
	first := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)
	findings := Findings(FindingsInput{
		Now: first.Add(48 * time.Hour),
		PastBlocks: []PastBlock{
			{Rule: "*.example.com", Evidence: querylog.BlockedNameEvidence{Name: "img.example.com", Blocked: 3, ClientCount: 1, Clients: map[string]uint64{"10.0.0.2": 3}}},
			{Rule: "telemetry.example.com", Evidence: querylog.BlockedNameEvidence{
				Name: "telemetry.example.com", Blocked: 412, ClientCount: 12,
				FirstBlocked: first, LastBlocked: first.Add(time.Hour),
				Clients: map[string]uint64{"10.0.0.5": 400, "10.0.0.9": 12},
			}},
			// A rule with no blocked traffic behind it is not evidence.
			{Rule: "quiet.example", Evidence: querylog.BlockedNameEvidence{Name: "quiet.example"}},
		},
	})
	if len(findings) != 2 {
		t.Fatalf("findings = %+v, want the two names with blocked traffic", findings)
	}
	top := findings[0]
	if top.Kind != KindPastBlock || top.Tone != insights.ToneAttention || top.Subject != "telemetry.example.com" {
		t.Fatalf("top finding = %+v", top)
	}
	if top.Summary != "Blocked 412 times during the selected period and is now explicitly allowed." {
		t.Fatalf("summary = %q", top.Summary)
	}
	if top.Query == nil || top.Query.Name != "telemetry.example.com" || !top.Query.Blocked {
		t.Fatalf("query filter = %+v, want the exact blocked name", top.Query)
	}
	if len(top.Clients) != 2 || top.Clients[0] != (insights.Count{Name: "10.0.0.5", Hits: 400}) {
		t.Fatalf("clients = %+v", top.Clients)
	}
	if fact := findFact(top.Facts, "Clients"); fact.Value != "12" {
		t.Fatalf("client fact = %+v, want the distinct count rather than the listed clients", fact)
	}
	if fact := findFact(top.Facts, "Current policy"); fact.Value != "Allowed by telemetry.example.com" {
		t.Fatalf("policy fact = %+v", fact)
	}
	if got := findings[1].Summary; got != "Blocked 3 times during the selected period and is now allowed by *.example.com." {
		t.Fatalf("wildcard summary = %q", got)
	}
	if !strings.Contains(top.Method, "never treated as evidence") {
		t.Fatalf("method = %q, want it to rule out retries as evidence", top.Method)
	}
}

func TestFindingsDescribeListCoverageWithoutAdvice(t *testing.T) {
	t.Parallel()
	contribution := Contribution{Analyzed: 3, Lists: []ListContribution{
		{Name: "Big List", Available: true, Domains: 200_000, Unique: 90_000, Covered: 110_000, LargestOverlap: Overlap{Name: "Medium List", Domains: 100_000}},
		{Name: "Medium List", Available: true, Domains: 120_000, Unique: 20_000, Covered: 100_000},
		{Name: "Small List", Available: true, Domains: 50_000, Unique: 400, Covered: 49_600, LargestOverlap: Overlap{Name: "Big List", Domains: 49_600}},
		{Name: "Unreadable", Problem: "No cached copy has been downloaded yet"},
		{Name: "Tiny", Available: true, Domains: 10, Unique: 0, Covered: 10},
	}}
	findings := Findings(FindingsInput{Now: time.Now(), Contribution: &contribution})

	low := findingOfKind(t, findings, KindLowUnique)
	if low.Subject != "Small List" || low.Summary != "99.2% of this list's domains are also covered by Big List." {
		t.Fatalf("low unique finding = %+v", low)
	}
	positive := findingOfKind(t, findings, KindUniqueCoverage)
	if positive.Subject != "Big List" || positive.Summary != "90,000 of this list's domains (45.0%) are not covered by any other enabled list." {
		t.Fatalf("unique coverage finding = %+v", positive)
	}
	unreadable := findingOfKind(t, findings, KindListUnreadable)
	if unreadable.Subject != "Unreadable" {
		t.Fatalf("unreadable finding = %+v", unreadable)
	}
	for _, finding := range findings {
		if finding.Subject == "Tiny" {
			t.Fatal("a list below the comparison minimum produced a finding")
		}
		lower := strings.ToLower(finding.Summary + finding.Method)
		for _, advice := range []string{"remove", "delete", "you should", "recommend"} {
			if strings.Contains(lower, advice) {
				t.Fatalf("finding %q gives advice (%q)", finding.Summary, advice)
			}
		}
	}
}

func TestFindingsNameOtherListsWhenNoSingleListCoversTheOverlap(t *testing.T) {
	t.Parallel()
	contribution := Contribution{Analyzed: 3, Lists: []ListContribution{
		{Name: "Overlapped", Available: true, Domains: 1_000, Unique: 5, Covered: 995, LargestOverlap: Overlap{Name: "A", Domains: 700}},
		{Name: "A", Available: true, Domains: 800, Unique: 100, Covered: 700},
	}}
	finding := findingOfKind(t, Findings(FindingsInput{Contribution: &contribution}), KindLowUnique)
	if finding.Summary != "99.5% of this list's domains are also covered by other enabled lists." {
		t.Fatalf("summary = %q", finding.Summary)
	}
}

func TestFindingsNeedTwoListsToCompareCoverage(t *testing.T) {
	t.Parallel()
	contribution := Contribution{Analyzed: 1, Lists: []ListContribution{{Name: "Only", Available: true, Domains: 5_000, Unique: 5_000}}}
	if findings := Findings(FindingsInput{Contribution: &contribution}); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none for a single list", findings)
	}
}

func TestFindingsReportOnlyStaleUpdateFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	findings := Findings(FindingsInput{
		Now:            now,
		UpdateInterval: 24 * time.Hour,
		Health: []ListHealth{
			{Name: "Recent blip", Health: blockcompiler.SourceHealth{ConsecutiveFailures: 1, LastSuccess: now.Add(-6 * time.Hour)}},
			{Name: "Healthy", Health: blockcompiler.SourceHealth{LastSuccess: now.Add(-100 * time.Hour)}},
			{Name: "Stale", Health: blockcompiler.SourceHealth{ConsecutiveFailures: 4, LastSuccess: now.Add(-72 * time.Hour), LastError: "HTTP 503", RetryAfter: now.Add(time.Hour)}},
			{Name: "Never", Health: blockcompiler.SourceHealth{ConsecutiveFailures: 1}},
		},
	})
	if len(findings) != 2 {
		t.Fatalf("findings = %+v, want the stale and never-downloaded lists", findings)
	}
	if findings[0].Subject != "Stale" || findings[0].Summary != "The last 4 updates failed. Its newest cached copy is 3 days old." {
		t.Fatalf("stale finding = %+v", findings[0])
	}
	if fact := findFact(findings[0].Facts, "Next retry"); !fact.Time.Equal(now.Add(time.Hour)) {
		t.Fatalf("retry fact = %+v", fact)
	}
	if findings[1].Summary != "The last update failed. This list has never downloaded successfully." {
		t.Fatalf("never finding = %+v", findings[1])
	}
}

func TestFindingsStaySparse(t *testing.T) {
	t.Parallel()
	blocks := make([]PastBlock, 0, 10)
	for index := range 10 {
		name := strings.Repeat("a", index+1) + ".example"
		blocks = append(blocks, PastBlock{Rule: name, Evidence: querylog.BlockedNameEvidence{Name: name, Blocked: uint64(index + 1)}})
	}
	findings := Findings(FindingsInput{PastBlocks: blocks})
	if len(findings) != maximumPastBlocks || findings[0].Subject != "aaaaaaaaaa.example" {
		t.Fatalf("findings = %d (%+v), want the %d busiest past blocks", len(findings), findings, maximumPastBlocks)
	}
}

func TestFormatShareNeverOverstates(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		part, whole uint64
		want        string
	}{
		{0, 10, "0%"}, {10, 10, "100%"}, {1, 0, "0%"},
		{9_999, 10_000, ">99.9%"}, {1, 10_000, "<0.1%"},
		{992, 1_000, "99.2%"}, {1, 3, "33.3%"},
	} {
		if got := insights.FormatShare(test.part, test.whole); got != test.want {
			t.Errorf("FormatShare(%d, %d) = %q, want %q", test.part, test.whole, got, test.want)
		}
	}
	if got := insights.FormatCount(1_234_567); got != "1,234,567" {
		t.Errorf("FormatCount = %q", got)
	}
}

func findFact(facts []insights.Fact, label string) insights.Fact {
	for _, fact := range facts {
		if fact.Label == label {
			return fact
		}
	}
	return insights.Fact{}
}

func findingOfKind(t *testing.T, findings []insights.Finding, kind string) insights.Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.Kind == kind {
			return finding
		}
	}
	t.Fatalf("no %s finding in %+v", kind, findings)
	return insights.Finding{}
}
