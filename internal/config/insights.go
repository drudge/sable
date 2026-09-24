package config

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpguts"
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
	// NtfyReceipt fails a send unless the answer is ntfy's receipt for a
	// published message, so a mistyped server that answers anything is caught.
	// It applies only to the text format, which is what ntfy takes.
	NtfyReceipt bool `toml:"ntfy_receipt,omitempty"`
	// Headers are sent with every request, such as an ntfy access token or
	// priority.
	Headers []InsightsWebhookHeader `toml:"headers,omitempty"`
}

// InsightsWebhookHeader is one extra request header.
type InsightsWebhookHeader struct {
	Name  string `toml:"name"`
	Value string `toml:"value"`
}

// insightsWebhookReservedHeaders are set by the HTTP client itself.
var insightsWebhookReservedHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true,
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
	default:
		return fmt.Errorf("insights.webhook.format must be %q or %q", InsightsWebhookJSON, InsightsWebhookText)
	}
	for _, header := range webhook.Headers {
		switch {
		case header.Name == "":
			return fmt.Errorf("insights.webhook.headers: a header with a value needs a name")
		case !httpguts.ValidHeaderFieldName(header.Name):
			return fmt.Errorf("insights.webhook.headers: %q is not a valid header name", header.Name)
		case insightsWebhookReservedHeaders[http.CanonicalHeaderKey(header.Name)]:
			return fmt.Errorf("insights.webhook.headers: Sable sets %s itself", http.CanonicalHeaderKey(header.Name))
		case !httpguts.ValidHeaderFieldValue(header.Value):
			return fmt.Errorf("insights.webhook.headers: the value for %s cannot contain line breaks", header.Name)
		}
	}
	return nil
}

func (configuration *Config) normalizeInsights() { configuration.Insights.Webhook.Normalize() }

// Normalize tidies a webhook as written by hand or in the console.
func (webhook *InsightsWebhook) Normalize() {
	webhook.URL = strings.TrimSpace(webhook.URL)
	webhook.Format = strings.ToLower(strings.TrimSpace(webhook.Format))
	if webhook.Format == InsightsWebhookJSON {
		webhook.Format = ""
	}
	if webhook.URL == "" {
		webhook.Paused = false
	}
	// ntfy takes plain text, so only that format can expect its receipt.
	if webhook.Format != InsightsWebhookText {
		webhook.NtfyReceipt = false
	}
	// Rows left blank in the console are not headers.
	var headers []InsightsWebhookHeader
	for _, header := range webhook.Headers {
		header.Name, header.Value = strings.TrimSpace(header.Name), strings.TrimSpace(header.Value)
		if header.Name != "" || header.Value != "" {
			headers = append(headers, header)
		}
	}
	webhook.Headers = headers
}
