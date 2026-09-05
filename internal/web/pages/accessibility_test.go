package pages

import (
	"strings"
	"testing"

	"github.com/drudge/sable/internal/auth"
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

func TestAdministrationMobileUserShowsSSOStatusAndGroupPills(t *testing.T) {
	t.Parallel()

	page := renderComponent(t, UsersPanel(AdministrationPageView{
		Users: []auth.ManagedUser{{
			ID:          1,
			Username:    "art.vandelay",
			DisplayName: "Art Vandelay",
			Roles:       []string{"Administrator"},
			Identities:  []auth.LinkedIdentity{{Provider: "oidc", Subject: "art"}},
		}},
	}))
	for _, expected := range []string{
		`class="admin-mobile-user-statuses"`,
		`class="status-badge sso-badge"`,
		`>SSO</span>`,
		`class="mobile-role-list"><span>Administrator</span>`,
	} {
		if !strings.Contains(page, expected) {
			t.Errorf("mobile administration user does not include %q", expected)
		}
	}
	if strings.Index(page, `class="status-badge sso-badge"`) > strings.Index(page, `class="status-badge active"`) {
		t.Error("mobile SSO badge should appear before the account status")
	}
}

func TestAdministrationMobileRowsOnlyShowAvailableActions(t *testing.T) {
	t.Parallel()

	builtInGroup := renderComponent(t, GroupsPanel(AdministrationPageView{
		Roles: []auth.Role{{ID: 1, Name: "Administrator", BuiltIn: true}},
	}))
	for _, expected := range []string{
		`<article class="admin-mobile-row admin-mobile-group-row static">`,
		`class="built-in-badge">Built in</span>`,
	} {
		if !strings.Contains(builtInGroup, expected) {
			t.Errorf("built-in mobile group row does not include %q", expected)
		}
	}
	if strings.Contains(builtInGroup, `data-dialog-open="edit-group-1-dialog"`) || strings.Contains(builtInGroup, `icon-chevron-right`) {
		t.Error("built-in mobile group row advertises an unavailable edit action")
	}

	customGroup := renderComponent(t, GroupsPanel(AdministrationPageView{
		Roles: []auth.Role{{ID: 2, Name: "DNS Operators"}},
	}))
	for _, expected := range []string{
		`<button type="button" class="admin-mobile-row admin-mobile-group-row" data-dialog-open="edit-group-2-dialog">`,
		`icon-chevron-right`,
	} {
		if !strings.Contains(customGroup, expected) {
			t.Errorf("editable mobile group row does not include %q", expected)
		}
	}

	permissions := renderComponent(t, PermissionsPanel(AdministrationPageView{
		Permissions: []string{"dns.read"},
	}))
	if strings.Contains(permissions, `icon-chevron-right`) {
		t.Error("informational mobile permission row advertises a disclosure action")
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
