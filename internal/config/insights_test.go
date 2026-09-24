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
	if webhook := configuration.Insights.Webhook; webhook.URL != "https://ntfy.sh/sable-alerts" || webhook.Format != "text" {
		t.Fatalf("webhook = %+v", configuration.Insights.Webhook)
	}
	// Only plain text, ntfy's format, can expect an ntfy receipt.
	json := Defaults()
	json.Insights.Webhook = InsightsWebhook{URL: "https://example.com/hook", NtfyReceipt: true}
	json.normalize()
	if json.Insights.Webhook.NtfyReceipt {
		t.Fatal("a JSON webhook kept the ntfy receipt check")
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
		{InsightsWebhook{URL: "https://api.pushover.net/1/messages.json", Format: "pushover", PushoverToken: "app"}, "application token and a user key"},
		{InsightsWebhook{URL: "https://example.com", Headers: []InsightsWebhookHeader{{Value: "orphan"}}}, "needs a name"},
		{InsightsWebhook{URL: "https://example.com", Headers: []InsightsWebhookHeader{{Name: "Bad Name", Value: "x"}}}, "not a valid header name"},
		{InsightsWebhook{URL: "https://example.com", Headers: []InsightsWebhookHeader{{Name: "content-length", Value: "1"}}}, "Sable sets Content-Length"},
		{InsightsWebhook{URL: "https://example.com", Headers: []InsightsWebhookHeader{{Name: "X-Test", Value: "a\r\nb"}}}, "line breaks"},
	} {
		invalid := Defaults()
		invalid.Insights.Webhook = test.webhook
		if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("Validate(%+v) = %v, want %q", test.webhook, err, test.want)
		}
	}
}
