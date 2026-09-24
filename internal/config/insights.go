package config

import (
	"fmt"
	"net/url"
	"strings"
)

// Webhook formats Insights can send.
const (
	// InsightsWebhookJSON posts a JSON object that also carries "text" and
	// "content" fields, which Slack and Discord show as the message.
	InsightsWebhookJSON = "json"
	// InsightsWebhookText posts the finding as plain text with a Title
	// header, which ntfy and most chat bridges show as-is.
	InsightsWebhookText = "text"
)

// Insights configures what Insights does beyond the console.
type Insights struct {
	Webhook InsightsWebhook `toml:"webhook"`
}

// InsightsWebhook is where Insights sends each new finding worth a look. An
// empty URL turns alerts off; Paused keeps the URL but sends nothing.
type InsightsWebhook struct {
	URL    string `toml:"url,omitempty"`
	Format string `toml:"format,omitempty"`
	Paused bool   `toml:"paused,omitempty"`
}

func validateInsights(insights Insights) error { return insights.Webhook.Validate() }

// Validate reports whether a webhook can be used as written.
func (webhook InsightsWebhook) Validate() error {
	if webhook.URL != "" {
		parsed, err := url.Parse(webhook.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return fmt.Errorf("insights.webhook.url must be an http or https URL")
		}
	}
	switch webhook.Format {
	case "", InsightsWebhookJSON, InsightsWebhookText:
		return nil
	default:
		return fmt.Errorf("insights.webhook.format must be %q or %q", InsightsWebhookJSON, InsightsWebhookText)
	}
}

func (configuration *Config) normalizeInsights() {
	webhook := &configuration.Insights.Webhook
	webhook.URL = strings.TrimSpace(webhook.URL)
	webhook.Format = strings.ToLower(strings.TrimSpace(webhook.Format))
	if webhook.Format == InsightsWebhookJSON {
		webhook.Format = ""
	}
	if webhook.URL == "" {
		webhook.Paused = false
	}
}
