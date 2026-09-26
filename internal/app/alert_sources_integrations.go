package app

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dynamicdns"
	"github.com/drudge/sable/internal/unifi"
	"github.com/drudge/sable/internal/update"
)

// The sources here read a status the integrations and the updater already
// keep, so the dispatcher can ask every minute without anything contacting a
// controller, a provider, or GitHub. They run on the lead, which is also the
// writable node the integrations run on.

const (
	unifiFailingAlert         = "integrations.unifi-failing"
	dynamicDNSFailingAlert    = "integrations.ddns-failing"
	publicAddressChangedAlert = "integrations.ddns-ip-changed"
	updateAvailableAlert      = "updates.available"
)

const (
	// integrationFailuresBeforeAlert is how many attempts in a row must fail
	// before an integration alerts, so one dropped request stays quiet.
	integrationFailuresBeforeAlert = 3
	// publicAddressNews is how long a changed public address stays news.
	publicAddressNews = 24 * time.Hour
	// integrationAlertErrorLength keeps an error a short fact rather than the
	// whole alert.
	integrationAlertErrorLength = 300
)

// integrationAlertConfiguration reads the settings alerts name things by.
type integrationAlertConfiguration interface {
	Current() config.Snapshot
}

type unifiStatusReader interface {
	Status() unifi.Status
}

type dynamicDNSStatusReader interface {
	Status(context.Context) dynamicdns.Status
}

type updateStatusReader interface {
	Status() update.Status
}

// unifiAlertSource reports a UniFi sync that keeps failing. Its alert keeps
// one ID while the failures last, so it goes out once, and it leaves the list
// as soon as a sync works.
type unifiAlertSource struct {
	syncer        unifiStatusReader
	configuration integrationAlertConfiguration
}

func newUniFiAlertSource(syncer unifiStatusReader, configuration integrationAlertConfiguration) alerts.Source {
	return unifiAlertSource{syncer: syncer, configuration: configuration}
}

func (source unifiAlertSource) Alerts(_ context.Context, now time.Time) ([]alerts.Alert, error) {
	status := source.syncer.Status()
	if !status.Enabled || status.ConsecutiveFailures < integrationFailuresBeforeAlert {
		return nil, nil
	}
	lastSuccess := "No sync has worked since Sable started"
	if !status.LastSuccess.IsZero() {
		lastSuccess = "Last success: " + integrationAlertTime(status.LastSuccess)
	}
	return []alerts.Alert{{
		ID: unifiFailingAlert, Group: config.AlertGroupIntegrations, Kind: unifiFailingAlert,
		Problem: true, Tone: alerts.ToneAttention,
		Title:    "UniFi sync failing",
		Subject:  unifiControllerName(source.configuration.Current().Config.UniFi.ControllerURL),
		Headline: fmt.Sprintf("UniFi sync failed %d times in a row", status.ConsecutiveFailures),
		Summary: fmt.Sprintf("The last %d tries to sync with the UniFi controller failed. "+
			"Records from UniFi stay as they were until one works.", status.ConsecutiveFailures),
		Reasons:    integrationAlertReasons(status.LastError, lastSuccess),
		Path:       "/integrations",
		PathLabel:  "Open Integrations",
		ObservedAt: integrationObservedAt(status.LastAttempt, now),
	}}, nil
}

// dynamicDNSAlertSource reports dynamic DNS that keeps failing, and a public
// address that changed within the last day. A change is named by its new
// address, so each one alerts once, and it stays news for a day even across
// a restart.
type dynamicDNSAlertSource struct {
	manager       dynamicDNSStatusReader
	configuration integrationAlertConfiguration
}

func newDynamicDNSAlertSource(manager dynamicDNSStatusReader, configuration integrationAlertConfiguration) alerts.Source {
	return dynamicDNSAlertSource{manager: manager, configuration: configuration}
}

func (source dynamicDNSAlertSource) Alerts(ctx context.Context, now time.Time) ([]alerts.Alert, error) {
	status := source.manager.Status(ctx)
	if !status.Enabled {
		return nil, nil
	}
	settings := source.configuration.Current().Config.DynamicDNS
	var news []alerts.Alert
	if status.ConsecutiveFailures >= integrationFailuresBeforeAlert {
		news = append(news, dynamicDNSFailing(status, dynamicDNSNames(settings, true, true), now))
	}
	for _, change := range []publicAddressChange{
		{family: "IPv4", previous: status.PreviousIPv4, current: status.IPv4, at: status.IPv4ChangedAt, names: dynamicDNSNames(settings, true, false)},
		{family: "IPv6", previous: status.PreviousIPv6, current: status.IPv6, at: status.IPv6ChangedAt, names: dynamicDNSNames(settings, false, true)},
	} {
		// A change is news for a day, and only while some name still
		// publishes that family.
		if change.previous == "" || change.current == "" || change.at.IsZero() || len(change.names) == 0 ||
			now.Sub(change.at) >= publicAddressNews {
			continue
		}
		// A run that worked since the change put the new address in every
		// record; the run that found it counts.
		news = append(news, publicAddressChanged(change, !status.LastSuccess.Before(change.at)))
	}
	return news, nil
}

// dynamicDNSFailing tells of publishes that keep failing, naming what they
// publish.
func dynamicDNSFailing(status dynamicdns.Status, names []string, now time.Time) alerts.Alert {
	lastSuccess := "Nothing has been published yet"
	if !status.LastSuccess.IsZero() {
		lastSuccess = "Last success: " + integrationAlertTime(status.LastSuccess)
	}
	return alerts.Alert{
		ID: dynamicDNSFailingAlert, Group: config.AlertGroupIntegrations, Kind: dynamicDNSFailingAlert,
		Problem: true, Tone: alerts.ToneAttention,
		Title:    "Dynamic DNS failing",
		Subject:  dynamicDNSSubject(names),
		Headline: fmt.Sprintf("Dynamic DNS failed %d times in a row", status.ConsecutiveFailures),
		Summary: fmt.Sprintf("The last %d tries to publish this network's public address failed. "+
			"The records keep the last address Sable published until one works.", status.ConsecutiveFailures),
		Reasons:    integrationAlertReasons(status.LastError, lastSuccess),
		Path:       "/integrations",
		PathLabel:  "Open Integrations",
		ObservedAt: integrationObservedAt(status.LastAttempt, now),
	}
}

// publicAddressChange is one family's latest public address change and the
// names that publish that family.
type publicAddressChange struct {
	family, previous, current string
	at                        time.Time
	names                     []string
}

// publicAddressChanged tells of a changed public address. published says
// whether the new address is in every record yet; if it is not, a failing
// alert follows unless the next tries work.
func publicAddressChanged(change publicAddressChange, published bool) alerts.Alert {
	subject := dynamicDNSSubject(change.names)
	moved := "Dynamic DNS moved " + subject + " to the new address."
	if !published {
		moved = "Dynamic DNS is still trying to move " + subject + " to it."
	}
	headline := fmt.Sprintf("The public %s address changed from %s to %s", change.family, change.previous, change.current)
	reasons := []string{"Old address: " + change.previous, "New address: " + change.current}
	if len(change.names) > 1 {
		reasons = append(reasons, "Names: "+strings.Join(change.names, ", "))
	}
	return alerts.Alert{
		ID: publicAddressChangedAlert + ":" + change.current, Group: config.AlertGroupIntegrations, Kind: publicAddressChangedAlert,
		Tone:       alerts.ToneNotice,
		Title:      "Public IP changed",
		Subject:    subject,
		Headline:   headline,
		Summary:    headline + ". " + moved,
		Reasons:    reasons,
		Path:       "/integrations",
		PathLabel:  "Open Integrations",
		ObservedAt: change.at,
	}
}

// updateAlertSource reports a Sable release newer than the running build for
// as long as it stays newer, which lasts until Sable restarts into it. The
// daily update check keeps the answer fresh.
type updateAlertSource struct {
	updates updateStatusReader
}

func newUpdateAlertSource(updates updateStatusReader) alerts.Source {
	return updateAlertSource{updates: updates}
}

func (source updateAlertSource) Alerts(_ context.Context, now time.Time) ([]alerts.Alert, error) {
	status := source.updates.Status()
	if !status.NewerRelease() {
		return nil, nil
	}
	latest, running := updateAlertVersion(status.LatestVersion), updateAlertVersion(status.CurrentVersion)
	headline := "Sable " + latest + " is available"
	summary := fmt.Sprintf("Sable %s is out, and this server runs %s.", latest, running)
	newest := "Newest " + latest
	if status.PreRelease {
		headline = "Sable " + latest + " is available as a pre-release"
		summary = fmt.Sprintf("Sable %s is out as a pre-release, and this server runs %s.", latest, running)
		newest += ", a pre-release"
	}
	if status.Installed {
		summary += " It is installed and starts when Sable restarts."
	} else {
		summary += " Read what changed and install it from the About page when you're ready."
	}
	return []alerts.Alert{{
		ID: updateAvailableAlert + ":" + strings.TrimPrefix(status.LatestVersion, "v"), Group: config.AlertGroupUpdates,
		Kind: updateAvailableAlert, Tone: alerts.ToneNotice,
		Title:      "Update available",
		Subject:    "Sable " + latest,
		Headline:   headline,
		Summary:    summary,
		Reasons:    []string{"Running " + running, newest},
		Path:       "/about",
		PathLabel:  "Open About",
		ObservedAt: integrationObservedAt(status.CheckedAt, now),
	}}, nil
}

// updateAlertVersion writes a version the way the console does, such as
// v1.6.0.
func updateAlertVersion(release string) string {
	return "v" + strings.TrimPrefix(release, "v")
}

// unifiControllerName names the controller by its host, the way people know
// it.
func unifiControllerName(controllerURL string) string {
	if parsed, err := url.Parse(strings.TrimSpace(controllerURL)); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return "UniFi controller"
}

// dynamicDNSNames lists the names dynamic DNS publishes an IPv4 or IPv6
// address for, each once, in the order they are configured.
func dynamicDNSNames(settings config.DynamicDNS, ipv4, ipv6 bool) []string {
	var names []string
	for _, record := range settings.AllRecords() {
		if !(ipv4 && record.IPv4) && !(ipv6 && record.IPv6) {
			continue
		}
		if name := strings.TrimSuffix(record.Name, "."); name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}

// dynamicDNSSubject names what dynamic DNS publishes briefly: the first name,
// and how many more.
func dynamicDNSSubject(names []string) string {
	switch len(names) {
	case 0:
		return "Dynamic DNS"
	case 1:
		return names[0]
	default:
		return fmt.Sprintf("%s and %d more", names[0], len(names)-1)
	}
}

// integrationAlertReasons lists an integration's last error, when it has one,
// and when it last worked.
func integrationAlertReasons(lastError, lastSuccess string) []string {
	reasons := make([]string, 0, 2)
	if text := integrationAlertError(lastError); text != "" {
		reasons = append(reasons, "Last error: "+text)
	}
	return append(reasons, lastSuccess)
}

// integrationAlertError fits an error on one short line. Dynamic DNS joins
// one line per provider that failed.
func integrationAlertError(message string) string {
	var lines []string
	for line := range strings.Lines(message) {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	text := strings.Join(lines, "; ")
	if runes := []rune(text); len(runes) > integrationAlertErrorLength {
		text = string(runes[:integrationAlertErrorLength-1]) + "…"
	}
	return text
}

// integrationAlertTime writes a time for an alert. Alerts are read later and
// elsewhere, so it is a date and a time in UTC rather than "an hour ago".
func integrationAlertTime(at time.Time) string {
	return at.UTC().Format("Jan 2, 2006 15:04 UTC")
}

// integrationObservedAt is when an alert's news happened, or now when that is
// not known.
func integrationObservedAt(at, now time.Time) time.Time {
	if at.IsZero() {
		return now
	}
	return at
}
