package app

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/trustanchor"
)

// These sources report problems a node sees in itself, so each runs on every
// node and a replica hands what it finds to the lead, which sends it. Every
// alert names its node twice: in its ID, so two nodes' news never merges into
// one alert, and in its subject, so people know which node to look at.

const (
	// certificateRenewalWarning is how close to expiring a certificate that
	// failed to renew must be to alert on the first failure. Renewal starts
	// well before this, so there is still time to fix it.
	certificateRenewalWarning = 14 * 24 * time.Hour
	// certificateRenewalFailures is how many renewals in a row must fail to
	// alert however far off expiry is.
	certificateRenewalFailures = 3
	// zoneRefreshFailures is how many refreshes in a row must fail to alert. A
	// single failure is usually a primary restarting, and the zone keeps
	// answering from its last copy until it expires.
	zoneRefreshFailures = 3
	// trustAnchorMissedRefreshes is how many refresh intervals may pass without
	// a DNSSEC key update working before it is worth an alert. Keys change
	// over months, so a day or two of failures is no emergency.
	trustAnchorMissedRefreshes = 2
)

// alertNode is the node an alert is about.
type alertNode struct {
	// ID is the node's cluster identity, which a node has even while it runs
	// alone.
	ID string
	// Name is what people call the node: its name in the cluster, or the
	// configured node name or hostname.
	Name string
	// Clustered reports whether the node belongs to a cluster, where alerts
	// about something on it, such as a zone, name the node as well.
	Clustered bool
}

// key names the node in alert IDs.
func (node alertNode) key() string {
	if node.ID != "" {
		return node.ID
	}
	return node.Name
}

// on names something on the node, such as a zone, adding the node when it is
// one of several.
func (node alertNode) on(subject string) string {
	if !node.Clustered {
		return subject
	}
	return subject + " on " + node.Name
}

// clusterAlertNode reads the node's identity each time it is asked, since a
// node can join or leave a cluster while it runs.
func clusterAlertNode(service *cluster.Service, configuration *config.Manager) func() alertNode {
	return func() alertNode {
		state := service.Snapshot()
		node := alertNode{
			ID: state.NodeID, Name: clusterNodeName(configuration.Current().Config.Cluster.NodeName), Clustered: state.Initialized,
		}
		for _, member := range state.Nodes {
			if member.ID == state.NodeID && member.Name != "" {
				node.Name = member.Name
				break
			}
		}
		return node
	}
}

// nodeHealth is what the alerts about this node's own health read.
type nodeHealth struct {
	node          func() alertNode
	configuration *config.Manager
	certificates  *certificates.Manager
	zones         *zoneRefresher
	trustAnchors  *trustanchor.Manager
	// trustAnchorUpdates reports whether this node keeps its DNSSEC root keys
	// up to date itself.
	trustAnchorUpdates func() bool
}

// alertSources returns the sources of alerts about this node, each placed on
// every node.
func (health nodeHealth) alertSources() []alerts.Source {
	configuration := func() config.Config { return health.configuration.Current().Config }
	sources := []alerts.Source{
		certificateAlertSource{node: health.node, configuration: configuration, status: health.certificates.Status},
		zoneRefreshAlertSource{node: health.node, status: health.zones.Status},
		trustAnchorAlertSource{
			node: health.node, enabled: health.trustAnchorUpdates,
			status: health.trustAnchors.Status, interval: health.trustAnchors.RefreshInterval,
		},
	}
	for index, source := range sources {
		sources[index] = alerts.Place(source, alerts.OnEachNode)
	}
	return sources
}

// certificateAlertSource warns when the certificate Sable renews for itself
// through ACME fails to renew. A certificate installed by hand is renewed by
// whoever installed it, so it is left out.
type certificateAlertSource struct {
	node          func() alertNode
	configuration func() config.Config
	status        func(context.Context, config.EncryptedDNS) certificates.Status
}

func (source certificateAlertSource) Alerts(ctx context.Context, now time.Time) ([]alerts.Alert, error) {
	encrypted := source.configuration().EncryptedDNS
	if encrypted.CertificateMode != "acme" {
		return nil, nil
	}
	status := source.status(ctx, encrypted)
	if status.ConsecutiveFailures == 0 {
		return nil, nil
	}
	expiryKnown := !status.NotAfter.IsZero()
	if (!expiryKnown || status.NotAfter.Sub(now) > certificateRenewalWarning) && status.ConsecutiveFailures < certificateRenewalFailures {
		return nil, nil
	}
	node := source.node()
	name := "its certificate"
	if len(status.Domains) > 0 {
		name = "the certificate for " + status.Domains[0]
	}
	summary := fmt.Sprintf("Sable could not renew %s on %s.", name, node.Name)
	var reasons []string
	switch {
	case !expiryKnown:
		summary += fmt.Sprintf(" Renewal has failed %d times in a row.", status.ConsecutiveFailures)
	case now.Before(status.NotAfter):
		summary += " It expires " + alertIn(status.NotAfter, now) + "."
		reasons = append(reasons, "Expires "+alertIn(status.NotAfter, now))
	default:
		summary += " It expired " + alertAgo(status.NotAfter, now) + ", so browsers and encrypted DNS clients refuse it."
		reasons = append(reasons, "Expired "+alertAgo(status.NotAfter, now))
	}
	reasons = append(reasons, failedInARow(status.ConsecutiveFailures), "Last error: "+status.LastError)
	observed := status.LastAttempt
	if observed.IsZero() {
		observed = now
	}
	return []alerts.Alert{{
		ID: "server.certificate-renewal:" + node.key(), Group: config.AlertGroupServer, Kind: "server.certificate-renewal",
		Problem: true, Tone: alerts.ToneAttention, Title: "Certificate renewal failing", Subject: node.Name,
		Headline: node.Name + " cannot renew " + name, Summary: summary, Reasons: reasons,
		Path: "/settings?tab=protocols#public-certificates", PathLabel: "Open Certificate Settings", ObservedAt: observed,
	}}, nil
}

// zoneRefreshAlertSource warns about each secondary zone this node keeps
// failing to refresh from its primaries, and each one that has expired.
type zoneRefreshAlertSource struct {
	node   func() alertNode
	status func() []zoneRefreshStatus
}

func (source zoneRefreshAlertSource) Alerts(_ context.Context, now time.Time) ([]alerts.Alert, error) {
	var failing []zoneRefreshStatus
	for _, zone := range source.status() {
		if zone.Failures >= zoneRefreshFailures || zoneExpired(zone, now) {
			failing = append(failing, zone)
		}
	}
	if len(failing) == 0 {
		return nil, nil
	}
	node := source.node()
	found := make([]alerts.Alert, 0, len(failing))
	for _, zone := range failing {
		expired := zoneExpired(zone, now)
		title, headline := "Zone refresh failing", node.Name+" cannot refresh "+zone.Zone
		summary := fmt.Sprintf("%s could not refresh %s from its primary.", node.Name, zone.Zone)
		var reasons []string
		switch {
		case expired:
			title, headline = "Zone expired", zone.Zone+" expired on "+node.Name
			summary = fmt.Sprintf("%s could not refresh %s from its primary, so the zone expired. Queries for it fail until a refresh works.", node.Name, zone.Zone)
			reasons = append(reasons, "Expired "+alertAgo(zone.ExpiresAt, now))
		case zone.ExpiresAt.IsZero():
			// A zone a catalog added has nothing to answer with until its first
			// transfer works.
			headline = node.Name + " cannot transfer " + zone.Zone
			summary = fmt.Sprintf("%s could not transfer %s from its primary. The zone has no records to answer with until a transfer works.", node.Name, zone.Zone)
		default:
			summary += " It keeps answering from its last copy, which expires " + alertIn(zone.ExpiresAt, now) + "."
			reasons = append(reasons, "Expires "+alertIn(zone.ExpiresAt, now))
		}
		observed := zone.FailingSince
		if zone.Failures > 0 {
			reasons = append(reasons, failedInARow(zone.Failures), "First failed "+alertAgo(zone.FailingSince, now), "Last error: "+zone.LastError)
		} else {
			observed = zone.ExpiresAt
		}
		found = append(found, alerts.Alert{
			ID: "server.zone-refresh:" + node.key() + ":" + zone.Zone, Group: config.AlertGroupServer, Kind: "server.zone-refresh",
			Problem: true, Tone: alerts.ToneAttention, Title: title, Subject: node.on(zone.Zone),
			Headline: headline, Summary: summary, Reasons: reasons,
			Path: "/zones/" + url.PathEscape(zone.Zone), PathLabel: "Open Zone", ObservedAt: observed,
		})
	}
	return found, nil
}

// zoneExpired reports whether a zone has gone past its SOA expiry, when it
// stops answering. A zone that has never transferred has no expiry.
func zoneExpired(zone zoneRefreshStatus, now time.Time) bool {
	return !zone.ExpiresAt.IsZero() && !now.Before(zone.ExpiresAt)
}

// trustAnchorAlertSource warns when this node has stopped keeping its DNSSEC
// root keys up to date: the latest update failed, and none has worked for
// longer than trustAnchorMissedRefreshes refresh intervals.
type trustAnchorAlertSource struct {
	node     func() alertNode
	enabled  func() bool
	status   func() trustanchor.Status
	interval func() time.Duration
}

func (source trustAnchorAlertSource) Alerts(_ context.Context, now time.Time) ([]alerts.Alert, error) {
	if !source.enabled() {
		return nil, nil
	}
	status := source.status()
	if status.LastError == "" {
		return nil, nil
	}
	overdue := trustAnchorMissedRefreshes * source.interval()
	if !status.LastSuccess.IsZero() && now.Sub(status.LastSuccess) <= overdue {
		return nil, nil
	}
	node := source.node()
	// A node that has never managed an update has no last success to count
	// from, so it is overdue from the start.
	summary := fmt.Sprintf("%s has never been able to check the root zone's DNSSEC keys. It validates with the keys Sable ships with, but could miss a change to them.", node.Name)
	reasons := []string{"Has never worked"}
	observed := now
	if !status.LastSuccess.IsZero() {
		summary = fmt.Sprintf("%s has not been able to check the root zone's DNSSEC keys for %s. It keeps validating with the keys it has, but could miss a change to them.",
			node.Name, alertDuration(now.Sub(status.LastSuccess)))
		reasons = []string{"Last worked " + alertAgo(status.LastSuccess, now)}
		observed = status.LastSuccess.Add(overdue)
	}
	if status.NextRefresh.After(now) {
		reasons = append(reasons, "Next try "+alertIn(status.NextRefresh, now))
	}
	reasons = append(reasons, "Last error: "+status.LastError)
	return []alerts.Alert{{
		ID: "server.dnssec-trust-anchors:" + node.key(), Group: config.AlertGroupServer, Kind: "server.dnssec-trust-anchors",
		Problem: true, Tone: alerts.ToneAttention, Title: "DNSSEC key updates failing", Subject: node.Name,
		Headline: node.Name + " cannot update its DNSSEC root keys", Summary: summary, Reasons: reasons,
		Path: "/settings?tab=recursion", PathLabel: "Open Recursion Settings", ObservedAt: observed,
	}}, nil
}

// failedInARow says how many attempts in a row failed.
func failedInARow(failures int) string {
	if failures == 1 {
		return "Failed once"
	}
	return "Failed " + strconv.Itoa(failures) + " times in a row"
}

// alertDuration says how long in plain words: "under a minute", "5 minutes",
// "3 hours", or "2 days".
func alertDuration(elapsed time.Duration) string {
	switch {
	case elapsed < time.Minute:
		return "under a minute"
	case elapsed < time.Hour:
		return countOf(int(elapsed/time.Minute), "minute", "minutes")
	case elapsed < 24*time.Hour:
		return countOf(int(elapsed/time.Hour), "hour", "hours")
	default:
		// Past a day, the nearest whole day reads better than a floor: 47
		// hours is 2 days, not 1.
		return countOf(int((elapsed+12*time.Hour)/(24*time.Hour)), "day", "days")
	}
}

// alertAgo says how long ago something happened, such as "3 hours ago".
func alertAgo(then, now time.Time) string {
	if now.Sub(then) < time.Minute {
		return "just now"
	}
	return alertDuration(now.Sub(then)) + " ago"
}

// alertIn says how long until something happens, such as "in 3 days".
func alertIn(then, now time.Time) string {
	return "in " + alertDuration(then.Sub(now))
}

// countOf says how many of something, such as "1 day" or "3 days".
func countOf(count int, singular, plural string) string {
	if count == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(count) + " " + plural
}
