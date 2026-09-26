package app

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/backup"
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
	// eventNews is how long an event, such as a finished backup, stays news.
	// The dispatcher tries again each round while it is, so a destination that
	// is down for a while still hears of it.
	eventNews = 24 * time.Hour
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
	backups            *scheduledBackupService
	auditLog           signInAuditLog
	// signIns reports whether anyone signs in to this node at all. With
	// security switched off nobody does, and there is nothing to count.
	signIns bool
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
		backupAlertSource{node: health.node, schedule: health.backups.schedule},
	}
	if health.signIns {
		sources = append(sources, &signInAlertSource{
			node: health.node, auditLog: health.auditLog,
			settings: func() config.AlertSignIns { return configuration().Alerts.SignIns },
		})
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

// backupAlertSource tells people how this node's scheduled backups went: a
// problem while the latest one has failed, and news each time one finishes.
// Backups run on every node, each into its own directory.
type backupAlertSource struct {
	node     func() alertNode
	schedule func() backup.Schedule
}

func (source backupAlertSource) Alerts(_ context.Context, now time.Time) ([]alerts.Alert, error) {
	schedule := source.schedule()
	// A failure stops mattering once scheduled backups are switched off, but a
	// backup that finished stays news for a day either way.
	failed := schedule.Enabled && schedule.LastError != ""
	finished := !schedule.LastSuccess.IsZero() && now.Sub(schedule.LastSuccess) < eventNews
	if !failed && !finished {
		return nil, nil
	}
	node := source.node()
	var found []alerts.Alert
	if failed {
		summary := fmt.Sprintf("The scheduled backup on %s failed, and none has worked there yet.", node.Name)
		reasons := []string{"Last error: " + schedule.LastError, "No good backup yet"}
		if !schedule.LastSuccess.IsZero() {
			summary = fmt.Sprintf("The scheduled backup on %s failed. Its last good backup is %s old.", node.Name, alertDuration(now.Sub(schedule.LastSuccess)))
			reasons[1] = "Last good backup " + alertAgo(schedule.LastSuccess, now)
		}
		if schedule.NextRun.After(now) {
			reasons = append(reasons, "Next try "+alertIn(schedule.NextRun, now))
		}
		observed := schedule.LastErrorAt
		if observed.IsZero() {
			observed = now
		}
		found = append(found, alerts.Alert{
			ID: "backups.failed:" + node.key(), Group: config.AlertGroupBackups, Kind: "backups.failed",
			Problem: true, Tone: alerts.ToneAttention, Title: "Backup failed", Subject: node.Name,
			Headline: "The scheduled backup on " + node.Name + " failed", Summary: summary, Reasons: reasons,
			Path: "/settings?tab=backup", PathLabel: "Open Backup Settings", ObservedAt: observed,
		})
	}
	if finished {
		reasons := []string{"Saved in " + schedule.ResolvedDirectory}
		if schedule.NextRun.After(now) {
			reasons = append(reasons, "Next backup "+alertIn(schedule.NextRun, now))
		}
		found = append(found, alerts.Alert{
			// Each backup is its own news, named by when it was taken.
			ID:    "backups.finished:" + node.key() + ":" + strconv.FormatInt(schedule.LastSuccess.Unix(), 10),
			Group: config.AlertGroupBackups, Kind: "backups.finished", Tone: alerts.TonePositive,
			Title: "Backup finished", Subject: node.Name, Headline: node.Name + " finished a scheduled backup",
			Summary: fmt.Sprintf("The scheduled backup on %s finished and was saved in %s.", node.Name, schedule.ResolvedDirectory),
			Reasons: reasons, Path: "/settings?tab=backup", PathLabel: "Open Backup Settings", ObservedAt: schedule.LastSuccess,
		})
	}
	return found, nil
}

// signInAuditLog is where this node records sign-ins, one log per node.
type signInAuditLog interface {
	ListAuditRecordsSince(ctx context.Context, actions []string, since time.Time, limit int) ([]auth.AuditRecord, error)
}

// signInAlertSource sends one alert for each burst of failed sign-ins on this
// node: a wrong password, a passkey that did not verify, a single sign-on
// identity turned away, or a lockout. A burst begins once After failures fall
// inside Within of each other, and lasts until a whole Within passes with no
// failure, so one that keeps going stays one alert. Each burst stays news for
// a day after its last failure.
type signInAlertSource struct {
	node     func() alertNode
	settings func() config.AlertSignIns
	auditLog signInAuditLog

	mu sync.Mutex
	// reported is what the last look found. The log is read a day back, and
	// no further, so a burst that has gone on longer than that starts before
	// what is read; remembering it keeps the start, and so the ID, it was
	// first reported with.
	reported []signInBurst
}

// signInBurst is a run of failed sign-ins close enough together to be one
// event.
type signInBurst struct {
	// start is the first failure of the first window that held enough of
	// them, and last is the latest failure.
	start, last time.Time
	failures    int
	lockouts    int
	// usernames and addresses list what was tried and where from, most often
	// first.
	usernames []string
	addresses []string
}

const (
	// signInRecordLimit caps how many failures one look reads, far more than
	// any alert needs. The newest are read, so a flood is still seen.
	signInRecordLimit = 5000
	// signInListLimit is how many usernames and addresses an alert names.
	signInListLimit = 5
)

func (source *signInAlertSource) Alerts(ctx context.Context, now time.Time) ([]alerts.Alert, error) {
	// The limit is read afresh each time, so a change applies at once. Loading
	// a configuration fills it in; one that never went through loading gets
	// the defaults.
	settings := source.settings()
	if settings.After < 1 || settings.Within.Duration <= 0 {
		settings = config.Defaults().Alerts.SignIns
	}
	since := now.Add(-eventNews)
	records, err := source.auditLog.ListAuditRecordsSince(ctx, auth.FailedSignInActions(), since, signInRecordLimit)
	if err != nil {
		return nil, err
	}
	slices.Reverse(records)
	source.mu.Lock()
	bursts := findSignInBursts(records, settings.After, settings.Within.Duration, since, source.reported)
	source.reported = bursts
	source.mu.Unlock()
	if len(bursts) == 0 {
		return nil, nil
	}
	node := source.node()
	found := make([]alerts.Alert, 0, len(bursts))
	for _, burst := range bursts {
		count := countOf(burst.failures, "sign-in", "sign-ins")
		summary := fmt.Sprintf("%s failed on %s in %s.", count, node.Name, alertDuration(burst.last.Sub(burst.start)))
		var reasons []string
		switch {
		case len(burst.usernames) > 0 && len(burst.addresses) > 0:
			summary += " They tried " + listSome(burst.usernames) + " from " + listSome(burst.addresses) + "."
		case len(burst.usernames) > 0:
			summary += " They tried " + listSome(burst.usernames) + "."
		case len(burst.addresses) > 0:
			summary += " They came from " + listSome(burst.addresses) + "."
		}
		if len(burst.usernames) > 0 {
			reasons = append(reasons, "Tried "+listSome(burst.usernames))
		}
		if len(burst.addresses) > 0 {
			reasons = append(reasons, "From "+listSome(burst.addresses))
		}
		if burst.lockouts > 0 {
			reasons = append(reasons, countOf(burst.lockouts, "lockout", "lockouts"))
		}
		reasons = append(reasons, "Last failure "+alertAgo(burst.last, now))
		found = append(found, alerts.Alert{
			ID:    "sign_ins.failed:" + node.key() + ":" + strconv.FormatInt(burst.start.Unix(), 10),
			Group: config.AlertGroupSignIns, Kind: "sign_ins.failed", Tone: alerts.ToneNotice,
			Title: "Failed sign-ins", Subject: node.Name, Headline: count + " failed on " + node.Name,
			Summary: summary, Reasons: reasons,
			Path: "/administration?tab=sessions", PathLabel: "Open Sessions", ObservedAt: burst.start,
		})
	}
	return found, nil
}

// findSignInBursts groups failed sign-ins, oldest first, into bursts. The
// records reach back only to since, so the oldest run of failures may have
// begun before it. Such a run keeps the start of the burst it continues from
// reported, the bursts the last look found. A run that continues none of them
// and turns dense within a window of since is left out: it began a day ago,
// and was reported then if it was news, so reporting it now under a later
// start would only say it again, as after a restart.
func findSignInBursts(records []auth.AuditRecord, after int, within time.Duration, since time.Time, reported []signInBurst) []signInBurst {
	var bursts []signInBurst
	for first := 0; first < len(records); {
		end := first + 1
		for end < len(records) && records[end].OccurredAt.Sub(records[end-1].OccurredAt) < within {
			end++
		}
		run, oldest := records[first:end], first == 0
		first = end
		if oldest {
			if earlier, found := continuedBurst(run, within, reported); found {
				bursts = append(bursts, newSignInBurst(earlier.start, run))
				continue
			}
		}
		dense := denseFrom(run, after, within)
		if dense < 0 || (oldest && run[dense].OccurredAt.Sub(since) < within) {
			continue
		}
		bursts = append(bursts, newSignInBurst(run[dense].OccurredAt, run))
	}
	return bursts
}

// continuedBurst finds the reported burst that a run carries on: one whose last
// failure is in the run, or came less than a window before it began.
func continuedBurst(run []auth.AuditRecord, within time.Duration, reported []signInBurst) (signInBurst, bool) {
	first, last := run[0].OccurredAt, run[len(run)-1].OccurredAt
	for _, burst := range reported {
		if !last.Before(burst.last) && first.Sub(burst.last) < within {
			return burst, true
		}
	}
	return signInBurst{}, false
}

// denseFrom returns where a run of failures first holds after of them inside
// within, or -1 when it never does.
func denseFrom(run []auth.AuditRecord, after int, within time.Duration) int {
	for index := 0; index+after <= len(run); index++ {
		if run[index+after-1].OccurredAt.Sub(run[index].OccurredAt) < within {
			return index
		}
	}
	return -1
}

// newSignInBurst sums up the failures of a run from start on.
func newSignInBurst(start time.Time, run []auth.AuditRecord) signInBurst {
	burst := signInBurst{start: start, last: run[len(run)-1].OccurredAt}
	usernames, addresses := make(map[string]int), make(map[string]int)
	for _, record := range run {
		if record.OccurredAt.Before(start) {
			continue
		}
		burst.failures++
		if record.Action == auth.ActionLoginLocked {
			burst.lockouts++
		}
		if username := signInUsername(record); username != "" {
			usernames[username]++
		}
		if record.ClientIP != "" {
			addresses[record.ClientIP]++
		}
	}
	burst.usernames, burst.addresses = mostOftenFirst(usernames), mostOftenFirst(addresses)
	return burst
}

// signInUsername is the username a failed sign-in tried. A password sign-in
// records the username typed; a single sign-on identity turned away names the
// account it matched, if any. A passkey that did not verify names nobody.
func signInUsername(record auth.AuditRecord) string {
	switch record.Action {
	case auth.ActionLoginFailed, auth.ActionLoginLocked:
		return auth.AttemptedUsername(record.Details)
	case auth.ActionFederatedDenied:
		return record.Username
	default:
		return ""
	}
}

// mostOftenFirst lists counted names by how often they came up, then by name.
func mostOftenFirst(counts map[string]int) []string {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	slices.SortFunc(names, func(left, right string) int {
		return cmp.Or(cmp.Compare(counts[right], counts[left]), strings.Compare(left, right))
	})
	return names
}

// listSome names up to signInListLimit things in a sentence, then says how
// many more there are: "a and b", or "a, b, c, d, e, and 3 more".
func listSome(names []string) string {
	switch {
	case len(names) > signInListLimit:
		return strings.Join(names[:signInListLimit], ", ") + ", and " + strconv.Itoa(len(names)-signInListLimit) + " more"
	case len(names) > 2:
		return strings.Join(names[:len(names)-1], ", ") + ", and " + names[len(names)-1]
	default:
		return strings.Join(names, " and ")
	}
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
