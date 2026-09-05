package pages

import (
	"strings"
	"testing"
)

// A panel narrowed by a dashboard link opens with the filter bar collapsed, so
// the tokens beside the count are the only thing telling an operator that they
// are not looking at every row.
func TestQueryLogPanelShowsAppliedFiltersAsTokens(t *testing.T) {
	t.Parallel()

	view := QueryLogsView{
		PageSize: 50, ClientIP: "10.0.7.112", Source: "cache",
		Start: "2026-08-20T00:00", End: "2026-08-21T23:59",
	}
	panel := renderComponent(t, QueryLogsPanel(view))
	for _, expected := range []string{
		"10.0.7.112",
		"Cached",
		"Aug 20, 00:00 – Aug 21, 23:59",
		"/logs?end=2026-08-21T23%3A59&amp;source=cache&amp;start=2026-08-20T00%3A00&amp;tab=queries",
	} {
		if !strings.Contains(panel, expected) {
			t.Errorf("query log panel does not contain %q", expected)
		}
	}
	if strings.Contains(panel, `type="datetime-local"`) {
		t.Error("query log filter still uses a bare datetime-local input instead of the range picker")
	}
	for _, expected := range []string{
		`<select aria-label="Month" data-calendar-month data-styled-select>`,
		`<select aria-label="Year" data-calendar-year data-styled-select>`,
		`class="styled-select-chevron" aria-hidden="true"`,
	} {
		if !strings.Contains(panel, expected) {
			t.Errorf("query log range picker does not contain themed calendar select %q", expected)
		}
	}
}

func TestQueryLogPanelRendersOneReusableDetailDrawer(t *testing.T) {
	t.Parallel()

	view := QueryLogsView{
		PageSize:    25,
		CanBlocking: true,
		Entries: []QueryLogEntryView{
			{OccurredAt: "Aug 28, 1:00 PM", ClientIP: "10.0.0.2", Name: "one.example", RecordType: "A", Status: "NOERROR", Source: "cache", Protocol: "UDP", Answers: []string{"192.0.2.1"}, Duration: "120µs", Decision: QueryDecisionView{Available: true, Summary: "Sable answered this query from its cache.", Policy: "No blocking rule matched", Cache: "Cache hit", Resolver: "Returned a cached response"}},
			{OccurredAt: "Aug 28, 1:01 PM", ClientIP: "10.0.0.3", Name: "two.example", RecordType: "AAAA", Status: "NXDOMAIN", Source: "upstream", Protocol: "TCP", Duration: "2ms"},
		},
	}
	panel := renderComponent(t, QueryLogsPanel(view))
	for _, expected := range []string{
		`data-query-detail-row`, `data-query-detail-duration="120µs"`, `data-query-detail-answers="192.0.2.1"`,
		`aria-label="View details for one.example"`, `id="query-detail-dialog"`, "Query details",
		`data-query-detail-policy="block"`, `data-query-detail-policy="allow"`,
		`data-query-detail-explain-available="true"`, `data-query-detail-cache-label="Cache hit"`,
		`id="query-detail-explain-title"`, `data-query-decision-step="resolver"`, "Why this answer?",
	} {
		if !strings.Contains(panel, expected) {
			t.Errorf("query log detail markup does not contain %q", expected)
		}
	}
	if dialogs := strings.Count(panel, `id="query-detail-dialog"`); dialogs != 1 {
		t.Errorf("query detail dialog count = %d, want one reusable dialog", dialogs)
	}
}

// The live refresh replaces the whole panel, so its URL has to carry every
// filter or a filtered panel quietly widens to every row once polling starts.
func TestQueryPanelLiveURLKeepsTheWholeFilter(t *testing.T) {
	t.Parallel()

	view := QueryLogsView{
		PageSize: 50, ClientIP: "10.0.7.112", Name: "example.com", RecordType: "A",
		Source: "cache", Protocol: "UDP", ResponseCode: "NOERROR",
		Start: "2026-08-20T00:00", End: "2026-08-21T23:59", Exact: true, Live: true,
	}
	url := queryPanelLiveURL(view)
	for _, expected := range []string{
		"client_ip=10.0.7.112", "name=example.com", "record_type=A", "source=cache",
		"protocol=UDP", "response_code=NOERROR", "start=2026-08-20T00%3A00",
		"end=2026-08-21T23%3A59", "match=exact", "live=1",
	} {
		if !strings.Contains(url, expected) {
			t.Errorf("live URL %q does not carry %q", url, expected)
		}
	}
}

// Exact only qualifies the client and domain filters, so dropping the last of
// them has to drop it too rather than leave a match mode with nothing to match.
func TestQueryFilterRemovalDropsExactWithItsLastFilter(t *testing.T) {
	t.Parallel()

	view := QueryLogsView{ClientIP: "10.0.7.112", Exact: true}
	if url := queryFilterURL(view, "client_ip"); strings.Contains(url, "match=exact") {
		t.Errorf("removing the last exact filter left %q", url)
	}
	view.Name = "example.com"
	if url := queryFilterURL(view, "client_ip"); !strings.Contains(url, "match=exact") {
		t.Errorf("removing one exact filter dropped the match mode from %q", url)
	}
}

// The runtime log is a tail, so it follows on arrival. Paging into the stored
// history stops it: the refresh always reads the newest page, and a panel left
// following would drag the operator straight back off the page they asked for.
func TestRuntimeLogFollowsUntilPaged(t *testing.T) {
	t.Parallel()

	view := RuntimeLogsView{Level: "all", PageSize: 100, Live: true, Persisted: true}
	if url := runtimePanelURL(view); !strings.Contains(url, "live=1") {
		t.Errorf("following panel URL %q does not ask to keep following", url)
	}
	if url := runtimePanelURL(RuntimeLogsView{Level: "all", PageSize: 100}); !strings.Contains(url, "live=0") {
		t.Errorf("paused panel URL %q does not spell the pause out", url)
	}
	if url := runtimeExportURL(view); strings.Contains(url, "live=") {
		t.Errorf("export URL %q carries the follow flag", url)
	}
}
