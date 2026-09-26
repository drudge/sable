package pages

import (
	"regexp"
	"strings"
	"testing"
)

func TestInsightSettingsBellSaysWhetherAlertsAreOn(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		state, icon, word string
	}{
		{"on", "icon-bell", "On"},
		{"paused", "icon-pause", "Paused"},
		{"off", "icon-bell-off", "Off"},
	} {
		t.Run(test.state, func(t *testing.T) {
			t.Parallel()
			bell := renderComponent(t, InsightSettingsBell(test.state))
			// The accessible name carries the word the bell shows.
			for _, expected := range []string{
				`id="insight-settings-bell"`, `data-dialog-open="insight-settings-dialog"`, test.icon,
				`aria-label="Insights settings, alerts ` + strings.ToLower(test.word) + `"`, `<span>` + test.word + `</span>`,
			} {
				if !strings.Contains(bell, expected) {
					t.Errorf("bell is missing %q:\n%s", expected, bell)
				}
			}
		})
	}
	if bell := renderComponent(t, InsightSettingsBell("")); strings.TrimSpace(bell) != "" {
		t.Fatalf("an operator who may not open the settings got a bell: %s", bell)
	}
}

func insightSettingsFixture(canEdit bool) InsightSettingsView {
	return InsightSettingsView{
		CanEdit: canEdit,
		Alerts:  InsightAlertStatusView{State: "paused", Detail: "Nothing is sent until alerts resume.", Link: "/settings?tab=alerts"},
		Groups: []InsightSettingGroupView{
			{ID: "devices", Title: "Devices", Kinds: []InsightKindSettingView{{
				Key: "went_quiet", Title: "Went quiet", Description: "A device that was busy all week sends nothing for a day.",
				Icon: "power", Mode: "show", CanAlert: true,
				Limits: []InsightLimitView{{
					Name: "went_quiet.minimum_daily_lookups", Label: "Lookups a day before", Help: "It must have averaged at least this many.",
					Value: "0", Minimum: "1", Maximum: "100000", Step: "1",
					Error: "Lookups a day before must be between 1 and 100,000.", Focus: true,
				}},
			}}},
			{ID: "blocking", Title: "Blocking", Kinds: []InsightKindSettingView{{
				Key: "low_unique_coverage", Title: "Little unique coverage", Description: "A block list mostly repeats your other lists.",
				Icon: "layers", Mode: "show", Note: "It describes your lists rather than news, so it never alerts.",
			}}},
		},
	}
}

// Each kind is a named group of three choices, and every field and note a
// control points at is there to be read.
func TestInsightSettingsNameEveryChoiceAndField(t *testing.T) {
	t.Parallel()
	form := renderComponent(t, InsightSettingsDialog(insightSettingsFixture(true)))
	for _, expected := range []string{
		`id="insight-settings-dialog" aria-labelledby="insight-settings-title"`, `<h2 id="insight-settings-title">Insights Settings</h2>`,
		`hx-post="/ui/insights/settings" hx-target="#insight-settings"`,
		`<strong>Alerts are paused</strong>`, `href="/settings?tab=alerts"`,
		`role="radiogroup" aria-labelledby="insight-setting-went-quiet-title" aria-describedby="insight-setting-went-quiet-description"`,
		`<strong id="insight-setting-went-quiet-title">Went quiet</strong>`,
		`<input type="radio" name="went_quiet.mode" value="show" checked>`,
		// Findings that are never news say why they cannot alert.
		`<input type="radio" name="low_unique_coverage.mode" value="alert" disabled aria-describedby="insight-setting-low-unique-coverage-note">`,
		`id="insight-setting-low-unique-coverage-note">It describes your lists rather than news, so it never alerts.</small>`,
		// A refused limit keeps what was typed and says what it needs.
		`id="insight-setting-went-quiet-minimum-daily-lookups" name="went_quiet.minimum_daily_lookups" value="0" min="1" max="100000" step="1" required autofocus aria-invalid="true"`,
		`aria-describedby="insight-setting-went-quiet-minimum-daily-lookups-help insight-setting-went-quiet-minimum-daily-lookups-error"`,
		`id="insight-setting-went-quiet-minimum-daily-lookups-error">Lookups a day before must be between 1 and 100,000.</small>`,
		`data-confirm-title="Reset Insights settings?"`, `id="insight-settings-save"`,
	} {
		if !strings.Contains(form, expected) {
			t.Errorf("Insights settings are missing %q", expected)
		}
	}
	// Every ID a control points at exists.
	for _, match := range regexp.MustCompile(`aria-(?:labelledby|describedby)="([^"]+)"`).FindAllStringSubmatch(form, -1) {
		for _, id := range strings.Fields(match[1]) {
			if !strings.Contains(form, `id="`+id+`"`) {
				t.Errorf("a control points at %q, which is not on the page", id)
			}
		}
	}
}

func TestReadOnlyInsightSettingsCannotBeChanged(t *testing.T) {
	t.Parallel()
	form := renderComponent(t, InsightSettings(insightSettingsFixture(false)))
	if strings.Contains(form, `type="submit"`) || strings.Contains(form, "Reset to Defaults") {
		t.Fatal("a read-only view offers Save or Reset")
	}
	if !strings.Contains(form, "Changing them needs permission to change settings.") {
		t.Fatal("a read-only view does not say why it cannot be changed")
	}
	for _, input := range regexp.MustCompile(`<input [^>]*>`).FindAllString(form, -1) {
		if !strings.Contains(input, " disabled") {
			t.Errorf("a read-only view leaves %s enabled", input)
		}
	}
}
