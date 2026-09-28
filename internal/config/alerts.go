package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

// Alert destination formats.
const (
	// AlertFormatJSON posts a JSON object that also carries "text" and
	// "content" fields, which Slack and Discord show as the message. It is the
	// default, so it is written as no format at all.
	AlertFormatJSON = "json"
	// AlertFormatText posts the alert as plain text with a Title header, which
	// ntfy and most chat bridges show as-is.
	AlertFormatText = "text"
	// AlertFormatSlack posts a Slack incoming-webhook message: a card with a
	// colored bar, the alert's reasons, and a button back to the console.
	AlertFormatSlack = "slack"
	// AlertFormatDiscord posts a Discord webhook embed colored by tone.
	AlertFormatDiscord = "discord"
	// AlertFormatBrowser pushes each alert to the browsers that turned alerts
	// on, through their own push services. It needs no URL.
	AlertFormatBrowser = "browser"
	// AlertFormatPushover posts the form Pushover's message API takes, with the
	// application token and user key it needs.
	AlertFormatPushover = "pushover"
)

// PushoverMessagesURL is Pushover's message API.
const PushoverMessagesURL = "https://api.pushover.net/1/messages.json"

// Alert groups. Each has one switch in [alerts.send], and a destination can
// name the groups it gets in its sends list.
const (
	AlertGroupInsights     = "insights"
	AlertGroupCluster      = "cluster"
	AlertGroupUpdates      = "updates"
	AlertGroupIntegrations = "integrations"
	AlertGroupBackups      = "backups"
	AlertGroupServer       = "server"
	AlertGroupSignIns      = "sign_ins"
)

// AlertGroupNames lists every alert group in the order the console shows them.
func AlertGroupNames() []string {
	return []string{
		AlertGroupInsights, AlertGroupCluster, AlertGroupUpdates, AlertGroupIntegrations,
		AlertGroupBackups, AlertGroupServer, AlertGroupSignIns,
	}
}

// Backup alert choices for [alerts.send] backups.
const (
	// AlertBackupsFailures sends a backup alert only when one fails.
	AlertBackupsFailures = "failures"
	// AlertBackupsAll also sends one when a backup finishes.
	AlertBackupsAll = "all"
	// AlertBackupsOff sends no backup alerts.
	AlertBackupsOff = "off"
)

// Failed sign-in limits: how many failures, inside how long, make an alert.
const (
	defaultAlertSignInsAfter  = 5
	defaultAlertSignInsWithin = 10 * time.Minute
	maximumAlertSignInsAfter  = 1000
	minimumAlertSignInsWithin = time.Minute
	maximumAlertSignInsWithin = 24 * time.Hour
)

// Alerts configures where Sable sends alerts and which ones it sends.
type Alerts struct {
	// Paused keeps every destination but sends nothing. Alerts that come up
	// while paused count as seen, so resuming never sends the backlog.
	Paused bool `toml:"paused,omitempty"`
	// Send turns whole groups of alerts on or off.
	Send AlertSwitches `toml:"send"`
	// SignIns sets when failed sign-ins are worth an alert.
	SignIns AlertSignIns `toml:"sign_ins"`
	// Destinations are where alerts go. Their URLs, keys, and header values
	// live in the encrypted vault, not in this file.
	Destinations []AlertDestination `toml:"destinations,omitempty"`
}

// AlertSwitches turns whole groups of alerts on or off.
type AlertSwitches struct {
	Insights     bool `toml:"insights"`
	Cluster      bool `toml:"cluster"`
	Updates      bool `toml:"updates"`
	Integrations bool `toml:"integrations"`
	// Backups is "failures", "all" to hear about every finished backup too,
	// or "off".
	Backups string `toml:"backups"`
	// Server covers certificate renewals, secondary zones, and DNSSEC keys.
	Server  bool `toml:"server"`
	SignIns bool `toml:"sign_ins"`
}

// Allows reports whether alerts of a group are on. Problem marks an alert
// about something wrong, which is all "failures" lets through for backups.
func (switches AlertSwitches) Allows(group string, problem bool) bool {
	switch group {
	case AlertGroupInsights:
		return switches.Insights
	case AlertGroupCluster:
		return switches.Cluster
	case AlertGroupUpdates:
		return switches.Updates
	case AlertGroupIntegrations:
		return switches.Integrations
	case AlertGroupBackups:
		return switches.Backups == AlertBackupsAll || (problem && switches.Backups == AlertBackupsFailures)
	case AlertGroupServer:
		return switches.Server
	case AlertGroupSignIns:
		return switches.SignIns
	default:
		return false
	}
}

// AlertSignIns sets when failed sign-ins are worth an alert: After failures on
// one node inside Within send one alert for the burst.
type AlertSignIns struct {
	After  int      `toml:"after"`
	Within Duration `toml:"within"`
}

// AlertDestination is one place alerts go.
type AlertDestination struct {
	// ID names the destination for its vault entry and its record of what was
	// sent. It never changes, however the destination is renamed.
	ID string `toml:"id"`
	// Name is what people call it, such as "Phone". Empty names it by format.
	Name   string `toml:"name,omitempty"`
	Format string `toml:"format,omitempty"`
	// NtfyReceipt fails a send unless the answer is ntfy's receipt for a
	// published message, so a mistyped server that answers anything is caught.
	// It applies only to the text format, which is what ntfy takes.
	NtfyReceipt bool `toml:"ntfy_receipt,omitempty"`
	// Sends lists the groups this destination gets. Empty means all of them.
	Sends []string `toml:"sends,omitempty"`
	// URL, PushoverToken, PushoverUser, and Headers are secrets: a webhook URL
	// usually carries a token. Sable keeps them in the encrypted vault. They
	// appear here only when written by hand or by an older release, and move
	// to the vault the next time Sable starts.
	URL           string        `toml:"url,omitempty"`
	PushoverToken string        `toml:"pushover_token,omitempty"`
	PushoverUser  string        `toml:"pushover_user,omitempty"`
	Headers       []AlertHeader `toml:"headers,omitempty"`
}

// AlertHeader is one extra request header, such as an ntfy access token.
type AlertHeader struct {
	Name  string `toml:"name" json:"name"`
	Value string `toml:"value" json:"value"`
}

// alertReservedHeaders are set by the HTTP client itself.
var alertReservedHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true,
}

// Gets reports whether the destination takes alerts of a group.
func (destination AlertDestination) Gets(group string) bool {
	return len(destination.Sends) == 0 || slices.Contains(destination.Sends, group)
}

// HasSecrets reports whether any secret is still written in the file.
func (destination AlertDestination) HasSecrets() bool {
	return destination.URL != "" || destination.PushoverToken != "" || destination.PushoverUser != "" || len(destination.Headers) > 0
}

// FormatLabel names a destination's format the way the console does.
func (destination AlertDestination) FormatLabel() string {
	switch destination.Format {
	case AlertFormatText:
		return "ntfy"
	case AlertFormatSlack:
		return "Slack"
	case AlertFormatDiscord:
		return "Discord"
	case AlertFormatBrowser:
		return "Browsers"
	case AlertFormatPushover:
		return "Pushover"
	default:
		return "Webhook"
	}
}

// Label is what people call the destination: its name, or its format.
func (destination AlertDestination) Label() string {
	if destination.Name != "" {
		return destination.Name
	}
	return destination.FormatLabel()
}

// Normalize tidies a destination as written by hand or in the console. It
// never looks at whether a secret is present, because a destination whose
// secrets moved to the vault has none left here.
func (destination *AlertDestination) Normalize() {
	destination.ID = strings.TrimSpace(destination.ID)
	destination.Name = strings.TrimSpace(destination.Name)
	destination.URL = strings.TrimSpace(destination.URL)
	destination.Format = strings.ToLower(strings.TrimSpace(destination.Format))
	if destination.Format == AlertFormatJSON {
		destination.Format = ""
	}
	destination.PushoverToken = strings.TrimSpace(destination.PushoverToken)
	destination.PushoverUser = strings.TrimSpace(destination.PushoverUser)
	// Rows left blank in the console are not headers.
	var headers []AlertHeader
	for _, header := range destination.Headers {
		header.Name, header.Value = strings.TrimSpace(header.Name), strings.TrimSpace(header.Value)
		if header.Name != "" || header.Value != "" {
			headers = append(headers, header)
		}
	}
	destination.Headers = headers
	sends := make([]string, 0, len(destination.Sends))
	for _, group := range destination.Sends {
		group = strings.ToLower(strings.TrimSpace(group))
		if group != "" && !slices.Contains(sends, group) {
			sends = append(sends, group)
		}
	}
	destination.Sends = sends
	if len(destination.Sends) == 0 {
		destination.Sends = nil
	}
	if destination.Format != AlertFormatPushover {
		destination.PushoverToken, destination.PushoverUser = "", ""
	}
	// Only a plain webhook and ntfy can use extra headers; Slack, Discord, and
	// Pushover carry their secrets in the URL or the body.
	if destination.Format != "" && destination.Format != AlertFormatText {
		destination.Headers = nil
	}
	// Browsers subscribe on their own, so there is no URL to keep.
	if destination.Format == AlertFormatBrowser {
		destination.URL = ""
	}
	// ntfy takes plain text, so only that format can expect its receipt.
	if destination.Format != AlertFormatText {
		destination.NtfyReceipt = false
	}
	if destination.ID == "" {
		destination.ID = derivedAlertDestinationID(*destination)
	}
}

// ValidateSecrets reports whether a destination with its secrets filled in
// can send: whether it has an address and whatever keys its format needs.
// The file alone cannot say, because the secrets live in the vault.
func (destination AlertDestination) ValidateSecrets() error {
	switch destination.Format {
	case AlertFormatBrowser:
		return nil
	case AlertFormatPushover:
		if destination.PushoverToken == "" || destination.PushoverUser == "" {
			return fmt.Errorf("Pushover needs an application token and a user key")
		}
		return nil
	default:
		if destination.URL == "" {
			return fmt.Errorf("%s needs a URL", destination.Label())
		}
		return nil
	}
}

// AlertTarget names an alert destination by a hash of its URL, without keeping
// the URL, which often carries a token. It is how older releases keyed their
// record of what was sent, so a moved destination keeps its record.
func AlertTarget(address string) string {
	sum := sha256.Sum256([]byte(address))
	return hex.EncodeToString(sum[:16])
}

// derivedAlertDestinationID names a destination written by hand without an ID
// the way an older release would have, so it keeps the same ID on every load
// until Sable writes one back.
func derivedAlertDestinationID(destination AlertDestination) string {
	switch {
	case destination.Format == AlertFormatBrowser:
		return AlertFormatBrowser
	case destination.Format == AlertFormatPushover && destination.PushoverUser != "":
		return AlertTarget(AlertFormatPushover + "\x00" + destination.PushoverUser)
	case destination.URL != "":
		return AlertTarget(destination.URL)
	case destination.Format == AlertFormatPushover:
		return AlertTarget(PushoverMessagesURL)
	default:
		return AlertTarget(destination.Format + "\x00" + destination.Name)
	}
}

// validAlertDestinationID limits IDs to what is safe in a vault entry name and
// a URL: letters, digits, dashes, and underscores.
func validAlertDestinationID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, character := range id {
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9', character == '-', character == '_':
		default:
			return false
		}
	}
	return true
}

func (configuration *Config) normalizeAlerts() {
	alerts := &configuration.Alerts
	// An older release kept one destination under [insights.webhook]. It
	// becomes the first destination, keyed the way the old release keyed its
	// record of what was sent, so nothing already sent goes out again.
	if destination, found := configuration.Insights.Webhook.destination(); found && len(alerts.Destinations) == 0 {
		alerts.Destinations = []AlertDestination{destination}
		alerts.Paused = alerts.Paused || configuration.Insights.Webhook.Paused
	}
	configuration.Insights.Webhook = InsightsWebhook{}
	for index := range alerts.Destinations {
		alerts.Destinations[index].Normalize()
	}
	if len(alerts.Destinations) == 0 {
		alerts.Destinations = nil
		alerts.Paused = false
	}
	alerts.Send.Backups = strings.ToLower(strings.TrimSpace(alerts.Send.Backups))
	if alerts.Send.Backups == "" {
		alerts.Send.Backups = AlertBackupsFailures
	}
	if alerts.SignIns.After == 0 {
		alerts.SignIns.After = defaultAlertSignInsAfter
	}
	if alerts.SignIns.Within.Duration == 0 {
		alerts.SignIns.Within.Duration = defaultAlertSignInsWithin
	}
}

func validateAlerts(alerts Alerts) error {
	ids := make(map[string]bool, len(alerts.Destinations))
	browsers := 0
	for index, destination := range alerts.Destinations {
		field := fmt.Sprintf("alerts.destinations[%d]", index)
		if !validAlertDestinationID(destination.ID) {
			return fmt.Errorf("%s.id must be 1 to 64 letters, digits, dashes, or underscores", field)
		}
		if ids[destination.ID] {
			return fmt.Errorf("%s.id %q is used by another destination", field, destination.ID)
		}
		ids[destination.ID] = true
		switch destination.Format {
		case "", AlertFormatJSON, AlertFormatText, AlertFormatSlack, AlertFormatDiscord, AlertFormatPushover:
		case AlertFormatBrowser:
			browsers++
		default:
			return fmt.Errorf("%s.format must be %q, %q, %q, %q, %q, or %q", field,
				AlertFormatJSON, AlertFormatSlack, AlertFormatDiscord, AlertFormatText, AlertFormatPushover, AlertFormatBrowser)
		}
		if destination.URL != "" {
			parsed, err := url.Parse(destination.URL)
			if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
				return fmt.Errorf("%s.url must be an http or https URL", field)
			}
		}
		if err := validateAlertHeaders(field, destination.Headers); err != nil {
			return err
		}
		for _, group := range destination.Sends {
			if !slices.Contains(AlertGroupNames(), group) {
				return fmt.Errorf("%s.sends: %q is not an alert type; use %s", field, group, strings.Join(AlertGroupNames(), ", "))
			}
		}
	}
	if browsers > 1 {
		return fmt.Errorf("alerts.destinations: only one destination can push to browsers")
	}
	switch alerts.Send.Backups {
	case AlertBackupsFailures, AlertBackupsAll, AlertBackupsOff:
	default:
		return fmt.Errorf("alerts.send.backups must be %q, %q, or %q", AlertBackupsFailures, AlertBackupsAll, AlertBackupsOff)
	}
	if alerts.SignIns.After < 1 || alerts.SignIns.After > maximumAlertSignInsAfter {
		return fmt.Errorf("alerts.sign_ins.after must be between 1 and %d", maximumAlertSignInsAfter)
	}
	if within := alerts.SignIns.Within.Duration; within < minimumAlertSignInsWithin || within > maximumAlertSignInsWithin {
		return fmt.Errorf("alerts.sign_ins.within must be between 1 minute and 24 hours")
	}
	return nil
}

func validateAlertHeaders(field string, headers []AlertHeader) error {
	for _, header := range headers {
		switch {
		case header.Name == "":
			return fmt.Errorf("%s.headers: a header with a value needs a name", field)
		case !httpguts.ValidHeaderFieldName(header.Name):
			return fmt.Errorf("%s.headers: %q is not a valid header name", field, header.Name)
		case alertReservedHeaders[http.CanonicalHeaderKey(header.Name)]:
			return fmt.Errorf("%s.headers: Sable sets %s itself", field, http.CanonicalHeaderKey(header.Name))
		case !httpguts.ValidHeaderFieldValue(header.Value):
			return fmt.Errorf("%s.headers: the value for %s cannot contain line breaks", field, header.Name)
		}
	}
	return nil
}

// ValidateAlertDestination reports whether one destination is sound, as the
// console checks it before saving.
func ValidateAlertDestination(destination AlertDestination) error {
	return validateAlerts(Alerts{
		Destinations: []AlertDestination{destination},
		Send:         AlertSwitches{Backups: AlertBackupsFailures},
		SignIns:      AlertSignIns{After: defaultAlertSignInsAfter, Within: Duration{defaultAlertSignInsWithin}},
	})
}
