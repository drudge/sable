package pages

import (
	"strings"
	"testing"
)

// The browser tab has to name the thing on screen, so an operator with several
// consoles open can tell them apart. Empty segments drop out rather than
// leaving a dangling separator.
func TestDocumentTitleJoinsSegmentsMostSpecificFirst(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name     string
		segments []string
		want     string
	}{
		{name: "detail and section", segments: []string{"example.com", "Zones"}, want: "example.com · Zones"},
		{name: "section only", segments: []string{"", "Zones"}, want: "Zones"},
		{name: "blank detail", segments: []string{"   ", "Settings"}, want: "Settings"},
		{name: "nothing", segments: nil, want: ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := documentTitle(testCase.segments...); got != testCase.want {
				t.Fatalf("documentTitle(%q) = %q, want %q", testCase.segments, got, testCase.want)
			}
		})
	}
}

// A missing or bogus tab parameter renders the first panel, so the title has to
// name that panel rather than nothing at all.
func TestTabLabelFallsBackToFirstTab(t *testing.T) {
	t.Parallel()

	if got := tabLabel(settingsTabs, "blocking"); got != "Blocking" {
		t.Fatalf("tabLabel(settingsTabs, %q) = %q, want %q", "blocking", got, "Blocking")
	}
	if got := tabLabel(settingsTabs, "nope"); got != "General" {
		t.Fatalf("tabLabel(settingsTabs, %q) = %q, want %q", "nope", got, "General")
	}
	if got := tabLabel(nil, "users"); got != "" {
		t.Fatalf("tabLabel(nil, %q) = %q, want empty", "users", got)
	}
}

// The zone title comes from the resolved zone. A bookmark pointing at a deleted
// zone falls back to the list, and the title has to fall back with it.
func TestZonesTitleNamesOnlyAResolvedZone(t *testing.T) {
	t.Parallel()

	view := ZonesPageView{Zones: []ZoneView{{Name: "example.com"}}, Selected: "example.com"}
	if got := zonesTitle(view); got != "example.com · Zones" {
		t.Fatalf("zonesTitle(selected) = %q, want %q", got, "example.com · Zones")
	}

	view.Selected = "gone.test"
	if got := zonesTitle(view); got != "Zones" {
		t.Fatalf("zonesTitle(missing) = %q, want %q", got, "Zones")
	}
}

// Profile tabs are links because each one is its own request. They still come
// from the same table the title reads, so the two can never disagree.
func TestProfileTabStripComesFromTheTitleTable(t *testing.T) {
	t.Parallel()

	markup := renderComponent(t, ProfileContent(ProfilePageView{ActiveTab: "tokens"}))
	for _, want := range []string{`href="/profile?tab=profile"`, `href="/profile?tab=tokens"`, "Account", "API Tokens"} {
		if !strings.Contains(markup, want) {
			t.Fatalf("profile markup missing %s", want)
		}
	}
}

// Tab strips switch panels in the browser without a request, so every tab has
// to carry the label the script puts in the document title.
func TestTabStripsCarryTitleLabels(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name     string
		markup   string
		contains []string
	}{
		{
			name:     "settings",
			markup:   renderComponent(t, SettingsContent(SettingsPageView{ActiveTab: "blocking"})),
			contains: []string{`data-title-base="Settings"`, `data-tab-title="Blocking"`, `data-tab-title="Backup"`},
		},
		{
			name:     "administration",
			markup:   renderComponent(t, AdministrationContent(AdministrationPageView{ActiveTab: "tokens"})),
			contains: []string{`data-title-base="Administration"`, `data-tab-title="API Tokens"`},
		},
		{
			name:     "logs",
			markup:   renderComponent(t, LogsContent(LogsPageView{ActiveTab: "queries"})),
			contains: []string{`data-title-base="Logs"`, `data-tab-title="Query Logs"`},
		},
		{
			name:     "blocking",
			markup:   renderComponent(t, BlockingContent(BlockingPageView{ActiveTab: "allowed"})),
			contains: []string{`data-title-base="DNS Blocking"`, `data-tab-title="Allowed"`},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			for _, want := range testCase.contains {
				if !strings.Contains(testCase.markup, want) {
					t.Fatalf("%s markup missing %s", testCase.name, want)
				}
			}
		})
	}
}
