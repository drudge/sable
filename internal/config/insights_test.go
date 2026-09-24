package config

import (
	"strings"
	"testing"
)

func TestInsightsWebhookValidatesAndNormalizes(t *testing.T) {
	t.Parallel()
	configuration := Defaults()
	configuration.Insights.Webhook = InsightsWebhook{URL: " https://ntfy.sh/sable-alerts ", Format: " TEXT "}
	configuration.normalize()
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	if configuration.Insights.Webhook != (InsightsWebhook{URL: "https://ntfy.sh/sable-alerts", Format: "text"}) {
		t.Fatalf("webhook = %+v", configuration.Insights.Webhook)
	}
	// A webhook with no URL cannot be paused; alerts are simply off.
	off := Defaults()
	off.Insights.Webhook = InsightsWebhook{Paused: true}
	off.normalize()
	if off.Insights.Webhook.Paused {
		t.Fatal("an empty webhook stayed paused")
	}
	for _, test := range []struct {
		webhook InsightsWebhook
		want    string
	}{
		{InsightsWebhook{URL: "ftp://example.com/hook"}, "http or https"},
		{InsightsWebhook{URL: "https://"}, "http or https"},
		{InsightsWebhook{URL: "https://example.com", Format: "xml"}, "format must be"},
	} {
		invalid := Defaults()
		invalid.Insights.Webhook = test.webhook
		if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("Validate(%+v) = %v, want %q", test.webhook, err, test.want)
		}
	}
}
