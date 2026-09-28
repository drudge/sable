package config

import (
	"strings"
	"testing"
	"time"
)

// A file from an older release kept its one alert destination under
// [insights.webhook]. It loads as the first destination, keyed the way the
// older release keyed its record of what was sent, and is written back only
// in the new shape.
func TestAnOlderWebhookBecomesTheFirstAlertDestination(t *testing.T) {
	t.Parallel()
	loaded, err := Decode(strings.NewReader(`
[insights.webhook]
url = " https://ntfy.sh/sable-alerts "
format = " TEXT "
paused = true
ntfy_receipt = true

[[insights.webhook.headers]]
name = "Authorization"
value = "Bearer tk_secret"
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Alerts.Destinations) != 1 || !loaded.Alerts.Paused {
		t.Fatalf("alerts = %+v", loaded.Alerts)
	}
	destination := loaded.Alerts.Destinations[0]
	if destination.ID != AlertTarget("https://ntfy.sh/sable-alerts") || destination.Format != AlertFormatText ||
		destination.URL != "https://ntfy.sh/sable-alerts" || !destination.NtfyReceipt || len(destination.Headers) != 1 {
		t.Fatalf("destination = %+v", destination)
	}
	if loaded.Insights.Webhook.URL != "" {
		t.Fatalf("the old webhook was kept: %+v", loaded.Insights.Webhook)
	}
	encoded, err := Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if text := string(encoded); strings.Contains(text, "[insights.webhook]") || !strings.Contains(text, "[[alerts.destinations]]") {
		t.Fatalf("written back as:\n%s", text)
	}
	if again, err := Decode(strings.NewReader(string(encoded))); err != nil || len(again.Alerts.Destinations) != 1 ||
		again.Alerts.Destinations[0].ID != destination.ID {
		t.Fatalf("reloaded = %+v, %v", again.Alerts, err)
	}
}

func TestOlderPushoverAndBrowserWebhooksKeepTheirKeys(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		webhook InsightsWebhook
		want    AlertDestination
		found   bool
	}{
		{InsightsWebhook{Format: "pushover", PushoverToken: "app", PushoverUser: "user"},
			AlertDestination{ID: AlertTarget(PushoverMessagesURL), Format: AlertFormatPushover, URL: PushoverMessagesURL, PushoverToken: "app", PushoverUser: "user"}, true},
		{InsightsWebhook{Format: "browser", Paused: true},
			AlertDestination{ID: AlertFormatBrowser, Format: AlertFormatBrowser}, true},
		{InsightsWebhook{Format: "pushover"}, AlertDestination{}, false},
		{InsightsWebhook{Paused: true}, AlertDestination{}, false},
	} {
		configuration := Defaults()
		configuration.Insights.Webhook = test.webhook
		configuration.normalize()
		if !test.found {
			if len(configuration.Alerts.Destinations) != 0 || configuration.Alerts.Paused {
				t.Errorf("%+v became %+v", test.webhook, configuration.Alerts)
			}
			continue
		}
		if len(configuration.Alerts.Destinations) != 1 {
			t.Fatalf("%+v became %+v", test.webhook, configuration.Alerts)
		}
		got := configuration.Alerts.Destinations[0]
		if got.ID != test.want.ID || got.Format != test.want.Format || got.URL != test.want.URL ||
			got.PushoverToken != test.want.PushoverToken || got.PushoverUser != test.want.PushoverUser {
			t.Errorf("%+v became %+v, want %+v", test.webhook, got, test.want)
		}
	}
	// A file that already has destinations keeps them, and drops the old one.
	both := Defaults()
	both.Alerts.Destinations = []AlertDestination{{ID: "phone", Format: "pushover"}}
	both.Insights.Webhook = InsightsWebhook{URL: "https://example.com/hook"}
	both.normalize()
	if len(both.Alerts.Destinations) != 1 || both.Alerts.Destinations[0].ID != "phone" || both.Insights.Webhook.URL != "" {
		t.Fatalf("alerts = %+v, webhook = %+v", both.Alerts, both.Insights.Webhook)
	}
}

func TestAlertDestinationsNormalizeWithoutTheirSecrets(t *testing.T) {
	t.Parallel()
	configuration := Defaults()
	configuration.Alerts.Paused = true
	configuration.Alerts.Destinations = []AlertDestination{
		// Moved to the vault: nothing secret is left, and it stays as it is.
		{ID: "phone", Name: " Phone ", Format: "Pushover", Sends: []string{" Cluster", "sign_ins", "cluster", ""}},
		{ID: "chat", Format: "slack", NtfyReceipt: true, Headers: []AlertHeader{{Name: "X", Value: "y"}}},
		{ID: "hook", Format: "json", PushoverToken: "stray"},
		{Format: "browser", URL: "https://example.com"},
	}
	configuration.normalize()
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	destinations := configuration.Alerts.Destinations
	if phone := destinations[0]; phone.Name != "Phone" || phone.Format != AlertFormatPushover ||
		strings.Join(phone.Sends, ",") != "cluster,sign_ins" || phone.URL != "" || !phone.Gets(AlertGroupCluster) || phone.Gets(AlertGroupInsights) {
		t.Fatalf("phone = %+v", phone)
	}
	if chat := destinations[1]; chat.NtfyReceipt || chat.Headers != nil || !chat.Gets(AlertGroupBackups) || chat.Label() != "Slack" {
		t.Fatalf("chat = %+v", chat)
	}
	if hook := destinations[2]; hook.Format != "" || hook.PushoverToken != "" || hook.Label() != "Webhook" {
		t.Fatalf("hook = %+v", hook)
	}
	if browser := destinations[3]; browser.ID != AlertFormatBrowser || browser.URL != "" {
		t.Fatalf("browser = %+v", browser)
	}
	if !configuration.Alerts.Paused {
		t.Fatal("pausing was lost")
	}
	// With nowhere to send, alerts cannot be paused; they are simply off.
	off := Defaults()
	off.Alerts.Paused = true
	off.normalize()
	if off.Alerts.Paused {
		t.Fatal("alerts with no destination stayed paused")
	}
}

func TestAlertDefaultsAndSwitches(t *testing.T) {
	t.Parallel()
	defaults := Defaults()
	defaults.normalize()
	if err := defaults.Validate(); err != nil {
		t.Fatal(err)
	}
	send := defaults.Alerts.Send
	for _, group := range []string{AlertGroupInsights, AlertGroupCluster, AlertGroupUpdates, AlertGroupIntegrations, AlertGroupServer} {
		if !send.Allows(group, false) {
			t.Errorf("%s is off by default", group)
		}
	}
	if send.Allows(AlertGroupSignIns, true) {
		t.Error("sign-in alerts are on by default")
	}
	if !send.Allows(AlertGroupBackups, true) || send.Allows(AlertGroupBackups, false) {
		t.Error("backups should alert on failures only by default")
	}
	send.Backups = AlertBackupsAll
	if !send.Allows(AlertGroupBackups, false) {
		t.Error(`backups "all" left out a finished backup`)
	}
	send.Backups = AlertBackupsOff
	if send.Allows(AlertGroupBackups, true) || send.Allows("unknown", true) {
		t.Error(`backups "off" or an unknown group let an alert through`)
	}
	if signIns := defaults.Alerts.SignIns; signIns.After != 5 || signIns.Within.Duration != 10*time.Minute {
		t.Fatalf("sign-in limit = %+v", signIns)
	}
	encoded, err := Marshal(defaults)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "[alerts.send]") || strings.Contains(string(encoded), "[[alerts.destinations]]") {
		t.Fatalf("defaults written as:\n%s", encoded)
	}
}

func TestAlertConfigurationIsValidated(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		change func(*Alerts)
		want   string
	}{
		{func(alerts *Alerts) {
			alerts.Destinations = []AlertDestination{{ID: "a", URL: "ftp://example.com/hook"}}
		}, "http or https"},
		{func(alerts *Alerts) { alerts.Destinations = []AlertDestination{{ID: "a", URL: "https://"}} }, "http or https"},
		{func(alerts *Alerts) { alerts.Destinations = []AlertDestination{{ID: "a", Format: "xml"}} }, "format must be"},
		{func(alerts *Alerts) { alerts.Destinations = []AlertDestination{{ID: "a b"}} }, "letters, digits"},
		{func(alerts *Alerts) { alerts.Destinations = []AlertDestination{{ID: "a"}, {ID: "a"}} }, "used by another destination"},
		{func(alerts *Alerts) {
			alerts.Destinations = []AlertDestination{{ID: "a", Format: "browser"}, {ID: "b", Format: "browser"}}
		}, "only one destination can push to browsers"},
		{func(alerts *Alerts) { alerts.Destinations = []AlertDestination{{ID: "a", Sends: []string{"weather"}}} }, "not an alert type"},
		{func(alerts *Alerts) {
			alerts.Destinations = []AlertDestination{{ID: "a", Headers: []AlertHeader{{Value: "orphan"}}}}
		}, "needs a name"},
		{func(alerts *Alerts) {
			alerts.Destinations = []AlertDestination{{ID: "a", Headers: []AlertHeader{{Name: "Bad Name", Value: "x"}}}}
		}, "not a valid header name"},
		{func(alerts *Alerts) {
			alerts.Destinations = []AlertDestination{{ID: "a", Headers: []AlertHeader{{Name: "content-length", Value: "1"}}}}
		}, "Sable sets Content-Length"},
		{func(alerts *Alerts) {
			alerts.Destinations = []AlertDestination{{ID: "a", Headers: []AlertHeader{{Name: "X-Test", Value: "a\r\nb"}}}}
		}, "line breaks"},
		{func(alerts *Alerts) { alerts.Send.Backups = "sometimes" }, "alerts.send.backups"},
		{func(alerts *Alerts) { alerts.SignIns.After = -1 }, "alerts.sign_ins.after"},
		{func(alerts *Alerts) { alerts.SignIns.Within = Duration{Duration: time.Second} }, "alerts.sign_ins.within"},
	} {
		invalid := Defaults()
		test.change(&invalid.Alerts)
		if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("Validate() = %v, want %q", err, test.want)
		}
	}
	if err := (AlertDestination{Format: AlertFormatPushover, PushoverToken: "app"}).ValidateSecrets(); err == nil {
		t.Error("Pushover without a user key was accepted")
	}
	if err := (AlertDestination{Format: AlertFormatSlack}).ValidateSecrets(); err == nil || !strings.Contains(err.Error(), "Slack needs a URL") {
		t.Errorf("Slack without a URL = %v", err)
	}
	if err := (AlertDestination{Format: AlertFormatBrowser}).ValidateSecrets(); err != nil {
		t.Errorf("browsers need no secrets, got %v", err)
	}
}
