package pages

import (
	"regexp"
	"strings"
	"testing"
)

func TestAlertsTabRendersGroupsAsSwitchesAndNamesEveryControl(t *testing.T) {
	t.Parallel()
	view := AlertsView{
		Available: true, CanEdit: true, State: AlertsOn, Push: true, BrowserDestination: true,
		Groups: AlertGroupsView{
			Insights: true, Cluster: true, Updates: true, Integrations: true, Backups: "all", Server: true, SignIns: true,
			SignInsAfter: 3, SignInsWithin: 15,
		},
		Destinations: []AlertDestinationView{
			{ID: "phone", Label: "Phone", Format: "text", FormatLabel: "ntfy", Address: "https://ntfy.sh/••••erts", Everything: true},
			{ID: "chat", Label: "Slack", Format: "slack", FormatLabel: "Slack", Groups: []string{"Cluster"}, Problem: "No URL is saved."},
			{ID: "browser", Label: "Browsers", Format: "browser", FormatLabel: "Browsers", Everything: true},
		},
		Browsers: []AlertBrowserView{{ID: "abc", Label: "Safari on iPhone", Added: "Added Sep 25, 2026 by operator"}},
	}
	markup := renderComponent(t, SettingsAlertsPanel(view))
	for _, group := range []string{"insights", "cluster", "updates", "integrations", "server", "sign_ins"} {
		if !regexp.MustCompile(`<input type="checkbox" role="switch" name="` + group + `" value="true" checked`).MatchString(markup) {
			t.Errorf("the %s group is not a checked switch", group)
		}
	}
	for _, want := range []string{
		`aria-label="Alert status"`, `<span class="status-badge success">On</span>`, "<span>Pause</span>",
		`aria-label="Send Test to Phone"`, `aria-label="Edit Phone"`, `aria-label="Remove Phone"`,
		`<span class="sr-only">Gets</span> <span class="alert-group-tag">Everything</span>`,
		`<span class="sr-only">Gets</span> <span class="alert-group-tag">Cluster</span> `, "No URL is saved.",
		`role="radiogroup" aria-label="Backup alerts"`, `name="backups" value="all" checked`,
		`aria-label="Failed sign-ins before an alert" required`, `value="3"`, `value="15"`,
		`aria-label="Remove Safari on iPhone"`, "Browsers getting alerts", "Added Sep 25, 2026 by operator",
		`data-push-panel`, `data-push-form`, "Turn On in This Browser", "forgets every browser that turned them on",
	} {
		if !strings.Contains(markup, want) {
			t.Errorf("the Alerts tab lacks %q", want)
		}
	}
	// The browsers belong to the Browsers destination, inside its row.
	row := markup[strings.Index(markup, `id="alert-destination-browser"`):]
	if row = row[:strings.Index(row, "</article>")]; !strings.Contains(row, "data-push-panel") || !strings.Contains(row, "Safari on iPhone") {
		t.Error("the browsers are not in the Browsers row")
	}
	if strings.Contains(markup, "alerts-browsers-card") {
		t.Error("the browsers still have a card of their own")
	}

	form := renderComponent(t, AlertDestinationDialog(AlertDestinationFormView{
		ID: "phone", Format: "text", SavedURL: "https://ntfy.sh/••••erts",
		Headers: []AlertHeaderView{{Name: "Authorization", Saved: "••••cret"}},
		Groups:  []AlertGroupChoice{{Key: "cluster", Label: "Cluster"}, {Key: "sign_ins", Label: "Failed Sign-Ins", Off: true}},
		Sends:   []string{"cluster"},
	}))
	for _, want := range []string{
		`aria-labelledby="alert-destination-title"`, `<h2 id="alert-destination-title">Edit Destination</h2>`,
		`aria-label="Close"`, `aria-label="Preview of a sample alert"`, `aria-label="Header name"`, `aria-label="Header value"`,
		`placeholder="Saved: https://ntfy.sh/••••erts"`, `data-saved`, "Leave it blank to keep the saved URL.",
		`placeholder="Saved: ••••cret"`, `name="sends" value="cluster" checked`, "Off in Alert Types",
		// Browsers cannot push without a server that pushes.
		`value="browser" disabled`, "Browser alerts are not available on this server.",
	} {
		if !strings.Contains(form, want) {
			t.Errorf("the destination dialog lacks %q", want)
		}
	}
	// The ntfy parts show for ntfy, and the others wait hidden.
	for _, part := range []string{
		`<span data-alert-for="text">Topic URL</span>`,
		`<label class="field-control switch-row setting-switch-row" data-alert-for="text">`,
		`<div class="field-grid two" data-alert-for="pushover" hidden>`,
		`<p class="alert-destination-note" data-alert-for="browser" hidden>`,
	} {
		if !strings.Contains(form, part) {
			t.Errorf("the ntfy form lacks %q", part)
		}
	}
}

func TestAlertsTabWithoutEditingShowsNoActions(t *testing.T) {
	t.Parallel()
	markup := renderComponent(t, SettingsAlertsPanel(AlertsView{
		Available: true, State: AlertsPaused, Push: true,
		Groups: AlertGroupsView{Backups: "failures", SignInsAfter: 5, SignInsWithin: 10},
		Destinations: []AlertDestinationView{
			{ID: "phone", Label: "Phone", Format: "text", FormatLabel: "ntfy", Everything: true},
			{ID: "browser", Label: "Browsers", Format: "browser", FormatLabel: "Browsers", Everything: true},
		},
	}))
	for _, action := range []string{"alert-destination-add", "alert-destination-edit-phone", "Resume", "Save Alert Types", "Turn On in This Browser", "data-push-form"} {
		if strings.Contains(markup, action) {
			t.Errorf("an operator who cannot change settings gets %q", action)
		}
	}
	if !strings.Contains(markup, `<span class="status-badge warning">Paused</span>`) || !strings.Contains(markup, "No browser has turned alerts on yet.") {
		t.Fatal("the read-only tab does not say how alerts stand")
	}
	unavailable := renderComponent(t, SettingsAlertsPanel(AlertsView{}))
	if !strings.Contains(unavailable, "Alerts are not available on this server.") || strings.Contains(unavailable, "alert-destination-list") {
		t.Fatal("a server without alerts renders the tab")
	}
}

// Only alerts that go out can be paused. With destinations that cannot send
// yet, alerts are off and there is nothing to pause.
func TestAlertsOffOffersNoPause(t *testing.T) {
	t.Parallel()
	markup := renderComponent(t, SettingsAlertsPanel(AlertsView{
		Available: true, CanEdit: true, State: AlertsOff, Push: true,
		Groups:       AlertGroupsView{Backups: "failures", SignInsAfter: 5, SignInsWithin: 10},
		Destinations: []AlertDestinationView{{ID: "browser", Label: "Browsers", Format: "browser", FormatLabel: "Browsers", Everything: true}},
	}))
	if strings.Contains(markup, `id="alerts-pause"`) {
		t.Error("alerts that are off offer Pause or Resume")
	}
	if !strings.Contains(markup, "Turn On in This Browser") {
		t.Error("Browsers with no browser yet does not offer to add this one")
	}
	// Browsers left subscribed without the destination are named, so they
	// are not forgotten silently.
	orphans := renderComponent(t, SettingsAlertsPanel(AlertsView{
		Available: true, CanEdit: true, State: AlertsOff, Push: true,
		Groups:   AlertGroupsView{Backups: "failures", SignInsAfter: 5, SignInsWithin: 10},
		Browsers: []AlertBrowserView{{ID: "abc", Label: "Safari on iPhone"}, {ID: "def", Label: "Chrome on macOS"}},
	}))
	if !strings.Contains(orphans, "2 browsers turned alerts on, but Browsers is not a destination") {
		t.Error("browsers without the destination are not mentioned")
	}
}

func TestAlertPreviewReadsLikeTheRequest(t *testing.T) {
	t.Parallel()
	preview := AlertPreview{
		Method: "POST", URL: "https://ntfy.sh/••••erts", ContentType: "text/plain; charset=utf-8",
		Headers: []AlertHeaderPreview{{Name: "Title", Value: "Test alert: Sable"}}, Body: "This is a test.",
	}
	want := "POST https://ntfy.sh/••••erts\nContent-Type: text/plain; charset=utf-8\nTitle: Test alert: Sable\n\nThis is a test."
	if got := preview.Text(); got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
	if got := (AlertPreview{Method: "POST", ContentType: "text/plain"}).Text(); !strings.HasPrefix(got, "POST (no URL yet)\n") {
		t.Fatalf("a preview with no URL = %q", got)
	}
}
