package config

import "strings"

// Insights configures what Insights does beyond the console.
type Insights struct {
	// Webhook is where older releases sent Insights alerts, before alerts got
	// their own [alerts] section. It is read only to move an older file's
	// setup into [[alerts.destinations]], and is never written back.
	Webhook InsightsWebhook `toml:"webhook,omitempty"`
}

// InsightsWebhook is the one alert destination older releases kept under
// [insights.webhook]. An empty URL meant alerts were off.
type InsightsWebhook struct {
	URL           string        `toml:"url,omitempty"`
	Format        string        `toml:"format,omitempty"`
	Paused        bool          `toml:"paused,omitempty"`
	NtfyReceipt   bool          `toml:"ntfy_receipt,omitempty"`
	PushoverToken string        `toml:"pushover_token,omitempty"`
	PushoverUser  string        `toml:"pushover_user,omitempty"`
	Headers       []AlertHeader `toml:"headers,omitempty"`
}

// destination turns an older release's webhook into an alert destination. Its
// ID is the key the older release gave its record of what was sent: a hash of
// the URL, or "browser". found is false when the webhook sent nowhere.
func (webhook InsightsWebhook) destination() (AlertDestination, bool) {
	destination := AlertDestination{
		URL: strings.TrimSpace(webhook.URL), Format: webhook.Format, NtfyReceipt: webhook.NtfyReceipt,
		PushoverToken: strings.TrimSpace(webhook.PushoverToken), PushoverUser: strings.TrimSpace(webhook.PushoverUser),
		Headers: append([]AlertHeader(nil), webhook.Headers...),
	}
	destination.Normalize()
	switch destination.Format {
	case AlertFormatBrowser:
		destination.ID = AlertFormatBrowser
	case AlertFormatPushover:
		// An older release posted to Pushover's API unless the file named
		// another, and its keys, not a URL, said whether alerts were on.
		if destination.PushoverToken == "" && destination.PushoverUser == "" {
			return AlertDestination{}, false
		}
		if destination.URL == "" {
			destination.URL = PushoverMessagesURL
		}
		destination.ID = AlertTarget(destination.URL)
	default:
		if destination.URL == "" {
			return AlertDestination{}, false
		}
		destination.ID = AlertTarget(destination.URL)
	}
	return destination, true
}
