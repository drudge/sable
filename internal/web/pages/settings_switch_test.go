package pages

import (
	"regexp"
	"strings"
	"testing"
)

func TestPersistentBooleanSettingsRenderAsSwitches(t *testing.T) {
	t.Parallel()

	markup := renderComponent(t, SettingsContent(SettingsPageView{
		PasskeysEnabled:        true,
		DNSSECValidation:       true,
		TrustAnchorUpdates:     true,
		SaveCache:              true,
		ServeStale:             true,
		BlockingAllowTXTReport: true,
		QueryLogEnabled:        true,
		ServerLogEnabled:       true,
		UpdatePreferences: SettingsUpdatePreferencesView{
			CanEdit:               true,
			CanEditReleaseChannel: true,
			CheckOnLogin:          true,
			IncludePreRelease:     true,
		},
		Backup: SettingsBackupView{
			Available:       true,
			LocalAvailable:  true,
			CanCreate:       true,
			ScheduleEnabled: true,
		},
	}))

	for _, name := range []string{
		"check_on_login",
		"pre_release",
		"passkeys_enabled",
		"dnssec_validation",
		"trust_anchor_updates",
		"save_cache",
		"serve_stale",
		"blocking_allow_txt_report",
		"query_log_enabled",
		"server_log_enabled",
		"enabled",
	} {
		pattern := regexp.MustCompile(`<input type="checkbox" role="switch"[^>]*name="` + regexp.QuoteMeta(name) + `"[^>]*checked`)
		if !pattern.MatchString(markup) {
			t.Errorf("persistent boolean %q did not render as a checked switch", name)
		}
	}

	if got := strings.Count(markup, `role="switch"`); got != 11 {
		t.Fatalf("settings page rendered %d switches, want 11", got)
	}
	if regexp.MustCompile(`<input[^>]*role="switch"[^>]*name="keep_configuration"`).MatchString(markup) {
		t.Fatal("restore option rendered as a switch instead of an action-scoped checkbox")
	}
}

// Check for updates carries its schedule under it: how often, and the day and
// time for the schedules that use them, all saved with Save Settings.
func TestUpdateCheckScheduleNamesEachControl(t *testing.T) {
	t.Parallel()
	markup := renderComponent(t, SettingsUpdatePreferences(SettingsUpdatePreferencesView{
		CanEdit: true, CheckOnLogin: true, CheckSchedule: "weekly", CheckAt: "18:30", CheckDay: "friday",
	}))
	for _, want := range []string{
		`role="group" aria-label="When to check for updates"`,
		`<select form="settings-form" name="check_schedule" aria-label="How often to check for updates" data-styled-select>`,
		`<option value="hourly">Hourly</option>`, `<option value="weekly" selected>Weekly</option>`,
		`<select form="settings-form" name="check_day" aria-label="Day to check for updates" data-styled-select>`,
		`<option value="friday" selected>Friday</option>`,
		`<input type="time" form="settings-form" name="check_at" value="18:30" step="60" aria-label="Time to check for updates" data-styled-time>`,
	} {
		if !strings.Contains(markup, want) {
			t.Errorf("the schedule lacks %q", want)
		}
	}
	readOnly := renderComponent(t, SettingsUpdatePreferences(SettingsUpdatePreferencesView{CheckOnLogin: true, CheckSchedule: "daily", CheckAt: "09:00", CheckDay: "monday"}))
	for _, name := range []string{"check_schedule", "check_day", "check_at"} {
		if !regexp.MustCompile(`name="` + name + `"[^>]*disabled`).MatchString(readOnly) {
			t.Errorf("an operator who cannot change settings can change %s", name)
		}
	}
}
