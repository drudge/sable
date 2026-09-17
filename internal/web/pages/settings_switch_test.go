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
