package pages

import (
	"strings"
	"testing"
)

func TestAppShellProvidesKeyboardLandmarks(t *testing.T) {
	t.Parallel()

	page := renderComponent(t, AppDocument(DashboardView{}, "Dashboard", "dashboard", Empty()))
	for _, expected := range []string{
		`class="skip-links"`, `href="#primary-navigation"`, `href="#main-content"`,
		`id="primary-navigation"`, `aria-label="Primary navigation"`,
		`id="main-content"`, `tabindex="-1"`, `aria-current="page"`,
		`data-a11y-announcer`, `aria-live="polite"`,
		`aria-controls="app-sidebar"`, `aria-expanded="false"`,
	} {
		if !strings.Contains(page, expected) {
			t.Errorf("application shell does not contain %q", expected)
		}
	}
	if strings.Index(page, `href="#main-content"`) > strings.Index(page, `href="#primary-navigation"`) {
		t.Error("main-content skip link must be the first keyboard stop")
	}
}

func TestLogsExposeKeyboardReadableRegionsAndActions(t *testing.T) {
	t.Parallel()

	view := LogsPageView{
		ActiveTab: "queries",
		Runtime:   RuntimeLogsView{Entries: []RuntimeLogEntryView{{OccurredAt: "now", Level: "info", Message: "ready"}}},
		Queries:   QueryLogsView{PageSize: 25, Entries: []QueryLogEntryView{{Name: "example.test", Source: "cache", Status: "NOERROR"}}},
	}
	page := renderComponent(t, LogsContent(view))
	for _, expected := range []string{
		`role="tabpanel"`, `aria-labelledby="runtime-log-title"`,
		`role="log"`, `aria-label="Runtime log entries"`,
		`role="region" aria-label="DNS query results" tabindex="0"`,
		`<caption class="sr-only">DNS query results.`,
		`aria-label="View details for example.test"`,
		`aria-controls="query-log-filters"`,
		`id="runtime-log-copy" readonly tabindex="-1" aria-hidden="true"`,
		`id="query-log-copy" readonly tabindex="-1" aria-hidden="true"`,
	} {
		if !strings.Contains(page, expected) {
			t.Errorf("logs accessibility markup does not contain %q", expected)
		}
	}
}

func TestDashboardChartsHaveKeyboardEquivalents(t *testing.T) {
	t.Parallel()

	chart := renderComponent(t, QueryChart(QueryChartView{HasActivity: true, HoverData: `{}`}))
	for _, expected := range []string{`role="img" tabindex="0"`, `Use Left and Right Arrow keys`, `data-chart-keyboard-status`, `aria-live="polite"`} {
		if !strings.Contains(chart, expected) {
			t.Errorf("query chart does not contain %q", expected)
		}
	}

	distribution := renderComponent(t, DistributionPanel("Responses", []DistributionItemView{{Name: "Cached", Value: 12, Percent: 75}}))
	for _, expected := range []string{`role="list"`, `role="listitem" tabindex="0"`, `Cached: 12, 75.0% of total`} {
		if !strings.Contains(distribution, expected) {
			t.Errorf("distribution chart does not contain %q", expected)
		}
	}
}

func TestRenderedDialogsHaveAccessibleNames(t *testing.T) {
	t.Parallel()

	pages := map[string]string{
		"administration": renderComponent(t, AdministrationContent(AdministrationPageView{ActiveTab: "users"})),
		"blocking":       renderComponent(t, BlockingContent(BlockingPageView{ActiveTab: "lists"})),
	}
	for name, page := range pages {
		for _, dialog := range openingTags(page, "<dialog ", "") {
			if !strings.Contains(dialog, "aria-label=") && !strings.Contains(dialog, "aria-labelledby=") {
				t.Errorf("%s contains an unnamed dialog: %s", name, dialog)
			}
		}
	}
}

func TestBlockingTabsExposeRovingTabState(t *testing.T) {
	t.Parallel()

	page := renderComponent(t, BlockingContent(BlockingPageView{ActiveTab: "domains"}))
	for _, expected := range []string{
		`id="blocking-tab-domains"`, `aria-controls="blocking-panel-domains"`,
		`aria-label="Blocked"`, `aria-selected="true"`, `tabindex="0"`, `role="tabpanel" aria-labelledby="blocking-tab-domains"`,
		`aria-label="Block list categories"`, `id="catalog-tab-popular"`,
	} {
		if !strings.Contains(page, expected) {
			t.Errorf("blocking tab markup does not contain %q", expected)
		}
	}
}

func TestResponsiveZoneActionsKeepAccessibleNames(t *testing.T) {
	t.Parallel()

	list := renderComponent(t, ZonesContent(ZonesPageView{CanCreate: true}))
	for _, expected := range []string{`aria-label="Import zone"`, `aria-label="Add zone"`} {
		if !strings.Contains(list, expected) {
			t.Errorf("zone list does not contain %q", expected)
		}
	}

	primary := renderComponent(t, ZonesContent(ZonesPageView{
		Selected: "example.test",
		Zones:    []ZoneView{{Name: "example.test", Type: "primary", CanRecords: true}},
	}))
	if !strings.Contains(primary, `aria-label="Add DNS record"`) {
		t.Error("primary zone detail action loses its accessible name when its visible label is hidden")
	}

	secondary := renderComponent(t, ZonesContent(ZonesPageView{
		Selected: "example.test",
		Zones:    []ZoneView{{Name: "example.test", Type: "secondary", CanTransfer: true}},
	}))
	if !strings.Contains(secondary, `aria-label="Resynchronize zone"`) {
		t.Error("secondary zone detail action loses its accessible name when its visible label is hidden")
	}
}
