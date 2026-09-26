package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

// Anyone who may read the query log may look at Insights settings; changing
// them also needs permission to change settings.
func TestInsightSettingsFollowPermissions(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	for _, test := range []struct {
		session       string
		view, change  int
		editable      bool
		linksSettings bool
	}{
		{"everything", http.StatusOK, http.StatusOK, true, true},
		{"logs-reader", http.StatusOK, http.StatusForbidden, false, true},
		{"logs-only", http.StatusOK, http.StatusForbidden, false, false},
		{"blocking-only", http.StatusForbidden, http.StatusForbidden, false, false},
		{"zones-only", http.StatusForbidden, http.StatusForbidden, false, false},
	} {
		// The sessions share one server and some of them may change it, so
		// they run one after another.
		t.Run(test.session, func(t *testing.T) {
			response := server.get(t, test.session, "/ui/insights/settings", true)
			if response.Code != test.view {
				t.Fatalf("GET = %d, want %d", response.Code, test.view)
			}
			if test.view == http.StatusOK {
				body := response.Body.String()
				if strings.Contains(body, `id="insight-settings-save"`) != test.editable || strings.Contains(body, "Reset to Defaults") != test.editable {
					t.Errorf("editable = %t, want %t", !test.editable, test.editable)
				}
				if !test.editable && (!strings.Contains(body, "Changing them needs permission to change settings.") ||
					!regexp.MustCompile(`<input type="radio" name="went_quiet.mode" value="alert" checked disabled`).MatchString(body)) {
					t.Error("a read-only view does not say so or leaves its fields enabled")
				}
				if strings.Contains(body, `href="/settings?tab=alerts"`) != test.linksSettings {
					t.Errorf("links to Settings = %t, want %t", !test.linksSettings, test.linksSettings)
				}
			}
			for _, target := range []string{"/ui/insights/settings", "/ui/insights/settings/reset"} {
				if response := server.post(t, test.session, target, url.Values{"went_quiet.mode": {"show"}}); response.Code != test.change {
					t.Errorf("POST %s = %d, want %d", target, response.Code, test.change)
				}
			}
		})
	}
	if mode := server.config.Current().Config.Insights.Findings.WentQuiet.Mode; mode != config.InsightModeAlert {
		t.Fatalf("an operator who may not change settings changed them: went quiet is %q", mode)
	}
}

// The bell beside the range control opens Insights settings for anyone who
// may read the query log, and says whether Insights alerts are on.
func TestInsightsBellOpensSettingsAndShowsTheAlertState(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	page := server.get(t, "everything", "/insights", false).Body.String()
	for _, expected := range []string{
		`id="insight-settings-dialog"`, `aria-labelledby="insight-settings-title"`, `id="insight-settings"`,
		`data-dialog-open="insight-settings-dialog" aria-label="Insights settings, alerts off"`,
	} {
		if !strings.Contains(page, expected) {
			t.Errorf("Insights page is missing %q", expected)
		}
	}
	if blockingOnly := server.get(t, "blocking-only", "/insights", false).Body.String(); strings.Contains(blockingOnly, "insight-settings") {
		t.Error("an operator who may not read the query log was offered Insights settings")
	}

	server.updateTestConfiguration(t, func(configuration *config.Config) {
		configuration.Alerts.Destinations = []config.AlertDestination{{ID: "phone", Format: config.AlertFormatPushover}}
	})
	if overview := server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String(); !strings.Contains(overview, `class="button outline compact insight-settings-bell on"`) {
		t.Error("the bell does not say alerts are on")
	}
	server.updateTestConfiguration(t, func(configuration *config.Config) { configuration.Alerts.Paused = true })
	if overview := server.get(t, "everything", "/ui/insights/overview?range=day", true).Body.String(); !strings.Contains(overview, `aria-label="Insights settings, alerts paused"`) {
		t.Error("the bell does not say alerts are paused")
	}
}

func TestInsightAlertStatusSaysWhetherInsightAlertsGoAnywhere(t *testing.T) {
	t.Parallel()
	phone := config.AlertDestination{ID: "phone", Format: config.AlertFormatPushover}
	chat := config.AlertDestination{ID: "chat", Format: config.AlertFormatSlack, Sends: []string{config.AlertGroupCluster}}
	on := config.AlertSwitches{Insights: true}
	for _, test := range []struct {
		name   string
		alerts config.Alerts
		state  string
		detail string
	}{
		{"nowhere to send them", config.Alerts{Send: on}, "off", "Nothing is set up to receive them yet."},
		{"insights switched off", config.Alerts{Send: config.AlertSwitches{}, Destinations: []config.AlertDestination{phone}}, "off", "Insights alerts are turned off."},
		{"no destination takes insights", config.Alerts{Send: on, Destinations: []config.AlertDestination{chat}}, "off", "None of the places alerts go takes Insights alerts."},
		{"paused", config.Alerts{Send: on, Paused: true, Destinations: []config.AlertDestination{phone}}, "paused", "Nothing is sent until alerts resume."},
		{"one place", config.Alerts{Send: on, Destinations: []config.AlertDestination{phone, chat}}, "on", "Kinds set to Show and alert go to 1 place."},
		{"two places", config.Alerts{Send: on, Destinations: []config.AlertDestination{phone, {ID: "hook"}}}, "on", "Kinds set to Show and alert go to 2 places."},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			status := insightAlertStatus(test.alerts, true)
			if status.State != test.state || status.Detail != test.detail || status.Link != "/settings?tab=alerts" {
				t.Fatalf("status = %+v, want %s: %q", status, test.state, test.detail)
			}
			if hidden := insightAlertStatus(test.alerts, false); hidden.Link != "" {
				t.Fatalf("an operator who may not open Settings got a link: %+v", hidden)
			}
		})
	}
}

func TestSavingInsightSettingsChangesWhatInsightsDoes(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	// The audit log names the operator who made each change.
	if _, err := server.store.CreateUser(context.Background(), "operator", "", "", "not-a-real-hash", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"went_quiet.mode": {"show"}, "went_quiet.minimum_daily_lookups": {"200"},
		"traffic_spike.factor": {"2.5"}, "traffic_spike.minimum_lookups": {"1,500"},
		"check_in.mode": {"off"}, "check_in.longest_interval": {"30"}, "check_in.shortest_span": {"6.5"},
		"low_unique_coverage.mode": {"off"},
	}
	response := server.post(t, "everything", "/ui/insights/settings", form)
	if response.Code != http.StatusOK || response.Header().Get("HX-Trigger") != "insightsChanged" {
		t.Fatalf("saving = %d %q %s", response.Code, response.Header().Get("HX-Trigger"), response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{
		"Insights settings saved.", `id="insight-settings"`,
		`<input type="radio" name="went_quiet.mode" value="show" checked`,
		`name="traffic_spike.minimum_lookups" value="1500"`, `name="check_in.shortest_span" value="6.5"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("the saved form is missing %q", expected)
		}
	}
	want := config.DefaultInsightFindings()
	want.WentQuiet = config.InsightWentQuiet{Mode: config.InsightModeShow, MinimumDailyLookups: 200}
	want.TrafficSpike.Factor, want.TrafficSpike.MinimumLookups = 2.5, 1_500
	want.CheckIn = config.InsightCheckIn{
		Mode: config.InsightModeOff, LongestInterval: config.Duration{Duration: 30 * time.Minute}, ShortestSpan: config.Duration{Duration: 6*time.Hour + 30*time.Minute},
	}
	want.LowUniqueCoverage.Mode = config.InsightModeOff
	if got := server.config.Current().Config.Insights.Findings; got != want {
		t.Fatalf("saved settings = %+v, want %+v", got, want)
	}
	records, err := server.store.ListAuditRecords(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 || records[0].Action != "insights.settings" ||
		!strings.Contains(records[0].Details, "went_quiet.mode show") || !strings.Contains(records[0].Details, "check_in.shortest_span 6.5 hours") {
		t.Fatalf("audit records = %+v", records)
	}

	// Resetting puts every kind back and says so in the audit log.
	reset := server.post(t, "everything", "/ui/insights/settings/reset", nil)
	if reset.Code != http.StatusOK || reset.Header().Get("HX-Trigger") != "insightsChanged" || !strings.Contains(reset.Body.String(), "Insights settings are back to their defaults.") {
		t.Fatalf("resetting = %d %s", reset.Code, reset.Body.String())
	}
	if got := server.config.Current().Config.Insights.Findings; got != config.DefaultInsightFindings() {
		t.Fatalf("reset settings = %+v", got)
	}
	if records, err := server.store.ListAuditRecords(context.Background(), 1); err != nil || records[0].Details != "reset Insights settings to their defaults" {
		t.Fatalf("audit records = %+v, %v", records, err)
	}
}

// A refused save changes nothing, shows the operator what they typed, and
// marks the field that needs fixing.
func TestInsightSettingsRefuseWhatInsightsCannotUse(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	for _, test := range []struct {
		name  string
		form  url.Values
		field string
		// problem is what the form says about the field, or the whole form
		// when the problem is not a limit.
		problem string
	}{
		{"a word for a number", url.Values{"went_quiet.minimum_daily_lookups": {"lots"}}, "went_quiet.minimum_daily_lookups", "Lookups a day before must be a number."},
		{"a fraction of a lookup", url.Values{"unusual_hours.minimum_lookups": {"12.5"}}, "unusual_hours.minimum_lookups", "Lookups in the hour must be a whole number."},
		{"a spike of normal variation", url.Values{"traffic_spike.factor": {"1.2"}}, "traffic_spike.factor", "Times its usual day must be between 1.5 and 100."},
		{"a limit past the range", url.Values{"new_destinations.minimum_new_domains": {"99999999999999999999"}}, "new_destinations.minimum_new_domains", "New domains must be between 1 and 10,000."},
		{"a check-in gap too long to see", url.Values{"check_in.longest_interval": {"180"}}, "check_in.longest_interval", "Longest gap (minutes) must be between 2 and 120."},
		{"an alert for findings that are never news", url.Values{"unique_coverage.mode": {"alert"}}, "", "Meaningful unique coverage must be &#34;show&#34; or &#34;off&#34; because these findings are never news."},
		{"an unknown choice", url.Values{"new_app.mode": {"sometimes"}}, "", "Started using a new app must be &#34;alert&#34;, &#34;show&#34;, or &#34;off&#34;."},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// Every case also asks for a change that would be fine alone.
			test.form.Set("past_block.mode", "off")
			response := server.post(t, "everything", "/ui/insights/settings", test.form)
			if response.Code != http.StatusUnprocessableEntity || response.Header().Get(consoleFragmentHeader) != "true" || response.Header().Get("HX-Trigger") != "" {
				t.Fatalf("saving = %d %v", response.Code, response.Header())
			}
			body := response.Body.String()
			if !strings.Contains(body, test.problem) {
				t.Fatalf("the form does not say %q:\n%s", test.problem, body)
			}
			if test.field != "" {
				marked := regexp.MustCompile(`name="` + regexp.QuoteMeta(test.field) + `" value="` + regexp.QuoteMeta(test.form.Get(test.field)) + `"[^>]*autofocus aria-invalid="true"`)
				if !marked.MatchString(body) {
					t.Fatalf("the field is not marked with what was typed:\n%s", body)
				}
			}
			if got := server.config.Current().Config.Insights.Findings; got != config.DefaultInsightFindings() {
				t.Fatalf("a refused save changed the settings: %+v", got)
			}
		})
	}
}
