package app

import (
	"cmp"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/backup"
	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/trustanchor"
)

var alertTestNow = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func alertTestNode(clustered bool) func() alertNode {
	return func() alertNode { return alertNode{ID: "node-1", Name: "ns1", Clustered: clustered} }
}

// wantAlert is what a test checks of an alert: the fields that route and
// identify it, and any wording a case cares about.
type wantAlert struct {
	id, group, kind, title, subject, path string
	problem                               bool
	tone                                  alerts.Tone
	summary                               string
	reasons                               []string
	observedAt                            time.Time
}

func checkAlerts(t *testing.T, got []alerts.Alert, want []wantAlert) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d alerts, want %d: %+v", len(got), len(want), got)
	}
	for index, alert := range got {
		expected := want[index]
		if alert.ID != expected.id || alert.Group != expected.group || alert.Kind != expected.kind ||
			alert.Title != expected.title || alert.Subject != expected.subject || alert.Path != expected.path ||
			alert.Problem != expected.problem || alert.Tone != expected.tone {
			t.Errorf("alert %d = %+v, want %+v", index, alert, expected)
		}
		if alert.Headline == "" || alert.Summary == "" || alert.PathLabel == "" {
			t.Errorf("alert %d has no headline, summary, or button label: %+v", index, alert)
		}
		if expected.summary != "" && alert.Summary != expected.summary {
			t.Errorf("alert %d summary = %q, want %q", index, alert.Summary, expected.summary)
		}
		if expected.reasons != nil && !slices.Equal(alert.Reasons, expected.reasons) {
			t.Errorf("alert %d reasons = %q, want %q", index, alert.Reasons, expected.reasons)
		}
		if !expected.observedAt.IsZero() && !alert.ObservedAt.Equal(expected.observedAt) {
			t.Errorf("alert %d observed at %s, want %s", index, alert.ObservedAt, expected.observedAt)
		}
	}
}

func TestCertificateAlertsWhenRenewalKeepsFailingOrExpiryIsNear(t *testing.T) {
	t.Parallel()

	renewal := func(summary string, reasons ...string) wantAlert {
		return wantAlert{
			id: "server.certificate-renewal:node-1", group: config.AlertGroupServer, kind: "server.certificate-renewal",
			title: "Certificate renewal failing", subject: "ns1", path: "/settings?tab=protocols#public-certificates",
			problem: true, tone: alerts.ToneAttention, summary: summary, reasons: reasons,
		}
	}
	for _, testCase := range []struct {
		name   string
		mode   string
		status certificates.Status
		want   []wantAlert
	}{
		{
			name: "a certificate installed by hand is left out", mode: "manual",
			status: certificates.Status{ConsecutiveFailures: 5, LastError: "no credentials", NotAfter: alertTestNow.Add(time.Hour)},
		},
		{
			name: "a renewal that worked is quiet", mode: "acme",
			status: certificates.Status{NotAfter: alertTestNow.Add(5 * 24 * time.Hour)},
		},
		{
			name: "one failure long before expiry waits", mode: "acme",
			status: certificates.Status{ConsecutiveFailures: 1, LastError: "rate limited", NotAfter: alertTestNow.Add(30 * 24 * time.Hour)},
		},
		{
			name: "one failure within two weeks of expiry", mode: "acme",
			status: certificates.Status{
				Domains: []string{"dns.example.com"}, ConsecutiveFailures: 1, LastError: "rate limited",
				NotAfter: alertTestNow.Add(9 * 24 * time.Hour), LastAttempt: alertTestNow.Add(-time.Hour),
			},
			want: []wantAlert{renewal(
				"Sable could not renew the certificate for dns.example.com on ns1. It expires in 9 days.",
				"Expires in 9 days", "Failed once", "Last error: rate limited",
			)},
		},
		{
			name: "three failures in a row long before expiry", mode: "acme",
			status: certificates.Status{ConsecutiveFailures: 3, LastError: "rate limited", NotAfter: alertTestNow.Add(60 * 24 * time.Hour)},
			want: []wantAlert{renewal(
				"Sable could not renew its certificate on ns1. It expires in 60 days.",
				"Expires in 60 days", "Failed 3 times in a row", "Last error: rate limited",
			)},
		},
		{
			name: "an expired certificate", mode: "acme",
			status: certificates.Status{ConsecutiveFailures: 2, LastError: "rate limited", NotAfter: alertTestNow.Add(-2 * 24 * time.Hour)},
			want: []wantAlert{renewal(
				"Sable could not renew its certificate on ns1. It expired 2 days ago, so browsers and encrypted DNS clients refuse it.",
				"Expired 2 days ago", "Failed 2 times in a row", "Last error: rate limited",
			)},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			source := certificateAlertSource{
				node: alertTestNode(false),
				configuration: func() config.Config {
					configuration := config.Defaults()
					configuration.EncryptedDNS.CertificateMode = testCase.mode
					return configuration
				},
				status: func(context.Context, config.EncryptedDNS) certificates.Status { return testCase.status },
			}
			got, err := source.Alerts(context.Background(), alertTestNow)
			if err != nil {
				t.Fatal(err)
			}
			checkAlerts(t, got, testCase.want)
		})
	}
}

func TestZoneRefreshAlertsWhenRefreshesKeepFailingOrTheZoneExpires(t *testing.T) {
	t.Parallel()

	failingSince := alertTestNow.Add(-3 * time.Hour)
	zoneAlert := func(zone, title, subject, summary string, reasons ...string) wantAlert {
		return wantAlert{
			id: "server.zone-refresh:node-1:" + zone, group: config.AlertGroupServer, kind: "server.zone-refresh",
			title: title, subject: subject, path: "/zones/" + zone, problem: true, tone: alerts.ToneAttention,
			summary: summary, reasons: reasons,
		}
	}
	for _, testCase := range []struct {
		name      string
		clustered bool
		zones     []zoneRefreshStatus
		want      []wantAlert
	}{
		{name: "no managed zones"},
		{
			name: "two failures wait",
			zones: []zoneRefreshStatus{{
				Zone: "a.example", Failures: 2, FailingSince: failingSince, LastError: "timeout", ExpiresAt: alertTestNow.Add(6 * 24 * time.Hour),
			}},
		},
		{
			name: "three failures alert once per zone",
			zones: []zoneRefreshStatus{
				{Zone: "a.example", Failures: 3, FailingSince: failingSince, LastError: "timeout", ExpiresAt: alertTestNow.Add(6 * 24 * time.Hour)},
				{Zone: "b.example", ExpiresAt: alertTestNow.Add(time.Hour)},
				{Zone: "c.example", Failures: 4, FailingSince: failingSince, LastError: "refused", ExpiresAt: alertTestNow.Add(time.Hour)},
			},
			want: []wantAlert{
				zoneAlert("a.example", "Zone refresh failing", "a.example",
					"ns1 could not refresh a.example from its primary. It keeps answering from its last copy, which expires in 6 days.",
					"Expires in 6 days", "Failed 3 times in a row", "First failed 3 hours ago", "Last error: timeout"),
				zoneAlert("c.example", "Zone refresh failing", "c.example",
					"ns1 could not refresh c.example from its primary. It keeps answering from its last copy, which expires in 1 hour.",
					"Expires in 1 hour", "Failed 4 times in a row", "First failed 3 hours ago", "Last error: refused"),
			},
		},
		{
			name: "an expired zone alerts however few refreshes failed",
			zones: []zoneRefreshStatus{{
				Zone: "a.example", Failures: 1, FailingSince: failingSince, LastError: "timeout", ExpiresAt: alertTestNow.Add(-time.Hour),
			}},
			want: []wantAlert{zoneAlert("a.example", "Zone expired", "a.example",
				"ns1 could not refresh a.example from its primary, so the zone expired. Queries for it fail until a refresh works.",
				"Expired 1 hour ago", "Failed once", "First failed 3 hours ago", "Last error: timeout")},
		},
		{
			name:  "a catalog member that never transferred",
			zones: []zoneRefreshStatus{{Zone: "member.example", Failures: 3, FailingSince: failingSince, LastError: "timeout"}},
			want: []wantAlert{zoneAlert("member.example", "Zone refresh failing", "member.example",
				"ns1 could not transfer member.example from its primary. The zone has no records to answer with until a transfer works.",
				"Failed 3 times in a row", "First failed 3 hours ago", "Last error: timeout")},
		},
		{
			name: "a node in a cluster names itself in the subject", clustered: true,
			zones: []zoneRefreshStatus{{
				Zone: "a.example", Failures: 3, FailingSince: failingSince, LastError: "timeout", ExpiresAt: alertTestNow.Add(6 * 24 * time.Hour),
			}},
			want: []wantAlert{zoneAlert("a.example", "Zone refresh failing", "a.example on ns1", "")},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			source := zoneRefreshAlertSource{
				node:   alertTestNode(testCase.clustered),
				status: func() []zoneRefreshStatus { return testCase.zones },
			}
			got, err := source.Alerts(context.Background(), alertTestNow)
			if err != nil {
				t.Fatal(err)
			}
			checkAlerts(t, got, testCase.want)
		})
	}
}

func TestTrustAnchorAlertsOnlyOnceUpdatesStayBroken(t *testing.T) {
	t.Parallel()

	// With a day between refreshes, an update is overdue after two days.
	const interval = 24 * time.Hour
	keysAlert := func(summary string, reasons ...string) wantAlert {
		return wantAlert{
			id: "server.dnssec-trust-anchors:node-1", group: config.AlertGroupServer, kind: "server.dnssec-trust-anchors",
			title: "DNSSEC key updates failing", subject: "ns1", path: "/settings?tab=recursion",
			problem: true, tone: alerts.ToneAttention, summary: summary, reasons: reasons,
		}
	}
	for _, testCase := range []struct {
		name     string
		disabled bool
		status   trustanchor.Status
		want     []wantAlert
	}{
		{
			name: "updates switched off keep an old error to themselves", disabled: true,
			status: trustanchor.Status{LastError: "timeout", LastSuccess: alertTestNow.Add(-10 * 24 * time.Hour)},
		},
		{name: "updates that work are quiet", status: trustanchor.Status{LastSuccess: alertTestNow.Add(-10 * 24 * time.Hour)}},
		{
			name:   "a failure soon after the last update waits",
			status: trustanchor.Status{LastError: "timeout", LastSuccess: alertTestNow.Add(-47 * time.Hour)},
		},
		{
			name: "no update for two intervals",
			status: trustanchor.Status{
				LastError: "timeout", LastSuccess: alertTestNow.Add(-49 * time.Hour), NextRefresh: alertTestNow.Add(4 * time.Hour),
			},
			want: []wantAlert{keysAlert(
				"ns1 has not been able to check the root zone's DNSSEC keys for 2 days. It keeps validating with the keys it has, but could miss a change to them.",
				"Last worked 2 days ago", "Next try in 4 hours", "Last error: timeout",
			)},
		},
		{
			name:   "no update ever",
			status: trustanchor.Status{LastError: "no signatures"},
			want: []wantAlert{keysAlert(
				"ns1 has never been able to check the root zone's DNSSEC keys. It validates with the keys Sable ships with, but could miss a change to them.",
				"Has never worked", "Last error: no signatures",
			)},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			source := trustAnchorAlertSource{
				node:     alertTestNode(false),
				enabled:  func() bool { return !testCase.disabled },
				status:   func() trustanchor.Status { return testCase.status },
				interval: func() time.Duration { return interval },
			}
			got, err := source.Alerts(context.Background(), alertTestNow)
			if err != nil {
				t.Fatal(err)
			}
			checkAlerts(t, got, testCase.want)
		})
	}
}

func TestBackupAlertsWhenTheLatestBackupFailedOrOneFinished(t *testing.T) {
	t.Parallel()

	finishedAt := alertTestNow.Add(-2 * time.Hour)
	failed := func(summary string, reasons ...string) wantAlert {
		return wantAlert{
			id: "backups.failed:node-1", group: config.AlertGroupBackups, kind: "backups.failed", title: "Backup failed",
			subject: "ns1", path: "/settings?tab=backup", problem: true, tone: alerts.ToneAttention,
			summary: summary, reasons: reasons, observedAt: alertTestNow.Add(-time.Minute),
		}
	}
	finished := func(reasons ...string) wantAlert {
		return wantAlert{
			id:    "backups.finished:node-1:" + strconv.FormatInt(finishedAt.Unix(), 10),
			group: config.AlertGroupBackups, kind: "backups.finished", title: "Backup finished", subject: "ns1",
			path: "/settings?tab=backup", tone: alerts.TonePositive,
			summary: "The scheduled backup on ns1 finished and was saved in /srv/backups.", reasons: reasons,
			observedAt: finishedAt,
		}
	}
	for _, testCase := range []struct {
		name     string
		schedule backup.Schedule
		want     []wantAlert
	}{
		{name: "never switched on"},
		{
			name:     "a failure stops mattering once backups are switched off",
			schedule: backup.Schedule{LastError: "disk full", LastErrorAt: alertTestNow.Add(-time.Minute)},
		},
		{
			name: "a failure before any backup worked",
			schedule: backup.Schedule{
				Enabled: true, LastError: "disk full", LastErrorAt: alertTestNow.Add(-time.Minute), NextRun: alertTestNow.Add(4 * time.Minute),
			},
			want: []wantAlert{failed(
				"The scheduled backup on ns1 failed, and none has worked there yet.",
				"Last error: disk full", "No good backup yet", "Next try in 4 minutes",
			)},
		},
		{
			name: "a failure after an older backup",
			schedule: backup.Schedule{
				Enabled: true, LastError: "disk full", LastErrorAt: alertTestNow.Add(-time.Minute), LastSuccess: alertTestNow.Add(-50 * time.Hour),
			},
			want: []wantAlert{failed(
				"The scheduled backup on ns1 failed. Its last good backup is 2 days old.",
				"Last error: disk full", "Last good backup 2 days ago",
			)},
		},
		{
			name: "a backup that finished today",
			schedule: backup.Schedule{
				Enabled: true, ResolvedDirectory: "/srv/backups", LastSuccess: finishedAt, NextRun: alertTestNow.Add(22 * time.Hour),
			},
			want: []wantAlert{finished("Saved in /srv/backups", "Next backup in 22 hours")},
		},
		{
			name:     "a backup from yesterday is no longer news",
			schedule: backup.Schedule{Enabled: true, ResolvedDirectory: "/srv/backups", LastSuccess: alertTestNow.Add(-25 * time.Hour)},
		},
		{
			name: "a failure after a backup that finished today",
			schedule: backup.Schedule{
				Enabled: true, ResolvedDirectory: "/srv/backups", LastSuccess: finishedAt, NextRun: alertTestNow.Add(4 * time.Minute),
				LastError: "disk full", LastErrorAt: alertTestNow.Add(-time.Minute),
			},
			want: []wantAlert{
				failed("The scheduled backup on ns1 failed. Its last good backup is 2 hours old.",
					"Last error: disk full", "Last good backup 2 hours ago", "Next try in 4 minutes"),
				finished("Saved in /srv/backups", "Next backup in 4 minutes"),
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			source := backupAlertSource{node: alertTestNode(false), schedule: func() backup.Schedule { return testCase.schedule }}
			got, err := source.Alerts(context.Background(), alertTestNow)
			if err != nil {
				t.Fatal(err)
			}
			checkAlerts(t, got, testCase.want)
		})
	}
}

// fakeAuditLog answers the way the store does: the records of the actions
// asked for since a time, newest first, up to a limit.
type fakeAuditLog struct {
	records []auth.AuditRecord
	// until hides the records after it, which a test that moves the clock
	// has not reached yet. Zero shows them all.
	until time.Time
}

func (log *fakeAuditLog) ListAuditRecordsSince(_ context.Context, actions []string, since time.Time, limit int) ([]auth.AuditRecord, error) {
	var found []auth.AuditRecord
	for _, record := range log.records {
		written := log.until.IsZero() || !record.OccurredAt.After(log.until)
		if written && slices.Contains(actions, record.Action) && !record.OccurredAt.Before(since) {
			found = append(found, record)
		}
	}
	slices.SortFunc(found, func(left, right auth.AuditRecord) int {
		return cmp.Or(right.OccurredAt.Compare(left.OccurredAt), cmp.Compare(right.ID, left.ID))
	})
	return found[:min(len(found), limit)], nil
}

// add records one audit event, numbered in the order it was added.
func (log *fakeAuditLog) add(at time.Time, action, username, address string) {
	record := auth.AuditRecord{ID: int64(len(log.records) + 1), OccurredAt: at, Action: action, ClientIP: address}
	switch action {
	case auth.ActionLoginFailed:
		record.Details = "invalid credentials; username=" + username
	case auth.ActionLoginLocked:
		record.Details = "too many failed sign-ins; username=" + username
	default:
		record.Username = username
	}
	log.records = append(log.records, record)
}

// failures records count password failures a step apart, the first at start.
func (log *fakeAuditLog) failures(start time.Time, step time.Duration, count int, username, address string) {
	for index := range count {
		log.add(start.Add(time.Duration(index)*step), auth.ActionLoginFailed, username, address)
	}
}

func newSignInTestSource(log *fakeAuditLog, after int, within time.Duration) *signInAlertSource {
	return &signInAlertSource{
		node:     alertTestNode(false),
		auditLog: log,
		settings: func() config.AlertSignIns {
			return config.AlertSignIns{After: after, Within: config.Duration{Duration: within}}
		},
	}
}

func signInAlertID(start time.Time) string {
	return "sign_ins.failed:node-1:" + strconv.FormatInt(start.Unix(), 10)
}

func TestSignInAlertsOnceEnoughFailuresFallInsideTheWindow(t *testing.T) {
	t.Parallel()

	burstStart := alertTestNow.Add(-5 * time.Minute)
	burst := func(summary string, reasons ...string) wantAlert {
		return wantAlert{
			id: signInAlertID(burstStart), group: config.AlertGroupSignIns, kind: "sign_ins.failed",
			title: "Failed sign-ins", subject: "ns1", path: "/administration?tab=sessions", tone: alerts.ToneNotice,
			summary: summary, reasons: reasons, observedAt: burstStart,
		}
	}
	for _, testCase := range []struct {
		name   string
		after  int
		within time.Duration
		log    func(*fakeAuditLog)
		want   []wantAlert
	}{
		{name: "no failures"},
		{
			name: "fewer failures than the limit",
			log:  func(log *fakeAuditLog) { log.failures(burstStart, time.Minute, 4, "admin", "203.0.113.9") },
		},
		{
			name: "enough failures inside the window",
			log: func(log *fakeAuditLog) {
				log.failures(burstStart, time.Minute, 3, "admin", "203.0.113.9")
				log.failures(burstStart.Add(3*time.Minute), time.Minute, 2, "root", "203.0.113.9")
			},
			want: []wantAlert{burst(
				"5 sign-ins failed on ns1 in 4 minutes. They tried admin and root from 203.0.113.9.",
				"Tried admin and root", "From 203.0.113.9", "Last failure 1 minute ago",
			)},
		},
		{
			// Each failure comes within the window of the one before, but no
			// five of them fit inside one window.
			name: "failures too spread out",
			log: func(log *fakeAuditLog) {
				log.failures(alertTestNow.Add(-time.Hour), 3*time.Minute, 5, "admin", "203.0.113.9")
			},
		},
		{
			name: "every kind of failure counts",
			log: func(log *fakeAuditLog) {
				log.add(burstStart, auth.ActionLoginFailed, "admin", "203.0.113.9")
				log.add(burstStart.Add(time.Minute), auth.ActionPasskeyLoginFailed, "", "203.0.113.9")
				log.add(burstStart.Add(2*time.Minute), auth.ActionFederatedDenied, "casey", "198.51.100.4")
				log.add(burstStart.Add(3*time.Minute), auth.ActionLoginLocked, "admin", "203.0.113.9")
				// A sign-in that worked is no failure.
				log.add(burstStart.Add(3*time.Minute), "auth.login", "casey", "198.51.100.4")
				log.add(burstStart.Add(4*time.Minute), auth.ActionFederatedDenied, "", "198.51.100.4")
			},
			want: []wantAlert{burst(
				"5 sign-ins failed on ns1 in 4 minutes. They tried admin and casey from 203.0.113.9 and 198.51.100.4.",
				"Tried admin and casey", "From 203.0.113.9 and 198.51.100.4", "1 lockout", "Last failure 1 minute ago",
			)},
		},
		{
			name: "long lists name five and count the rest",
			log: func(log *fakeAuditLog) {
				for index := range 8 {
					log.add(burstStart.Add(time.Duration(index)*10*time.Second), auth.ActionLoginFailed,
						fmt.Sprintf("user%d", index), fmt.Sprintf("192.0.2.%d", index%7))
				}
			},
			want: []wantAlert{burst(
				"8 sign-ins failed on ns1 in 1 minute. They tried user0, user1, user2, user3, user4, and 3 more from 192.0.2.0, 192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4, and 2 more.",
				"Tried user0, user1, user2, user3, user4, and 3 more", "From 192.0.2.0, 192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4, and 2 more",
				"Last failure 3 minutes ago",
			)},
		},
		{
			name: "two bursts apart are two alerts",
			log: func(log *fakeAuditLog) {
				log.failures(alertTestNow.Add(-5*time.Hour), time.Minute, 5, "admin", "203.0.113.9")
				log.failures(burstStart, time.Minute, 5, "root", "198.51.100.4")
			},
			want: []wantAlert{
				{
					id: signInAlertID(alertTestNow.Add(-5 * time.Hour)), group: config.AlertGroupSignIns, kind: "sign_ins.failed",
					title: "Failed sign-ins", subject: "ns1", path: "/administration?tab=sessions", tone: alerts.ToneNotice,
				},
				burst("5 sign-ins failed on ns1 in 4 minutes. They tried root from 198.51.100.4."),
			},
		},
		{
			name:   "the limit comes from the configuration",
			after:  2,
			within: time.Minute,
			log: func(log *fakeAuditLog) {
				log.failures(burstStart, 30*time.Second, 2, "admin", "203.0.113.9")
			},
			want: []wantAlert{burst("2 sign-ins failed on ns1 in under a minute. They tried admin from 203.0.113.9.")},
		},
		{
			// Its start is out of sight, so it was reported a day ago, when
			// it began.
			name: "a burst that began a day ago",
			log: func(log *fakeAuditLog) {
				log.failures(alertTestNow.Add(-24*time.Hour+time.Minute), time.Minute, 5, "admin", "203.0.113.9")
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			log := &fakeAuditLog{}
			if testCase.log != nil {
				testCase.log(log)
			}
			source := newSignInTestSource(log, cmp.Or(testCase.after, 5), cmp.Or(testCase.within, 10*time.Minute))
			got, err := source.Alerts(context.Background(), alertTestNow)
			if err != nil {
				t.Fatal(err)
			}
			checkAlerts(t, got, testCase.want)
		})
	}
}

func TestSignInAlertKeepsOneIDWhileTheBurstGoesOn(t *testing.T) {
	t.Parallel()

	// Someone tries a password every minute for thirty hours, longer than
	// the day of history each look reads, then stops. Three hours later a
	// second burst begins.
	started := alertTestNow.Add(-30 * time.Hour)
	log := &fakeAuditLog{}
	log.failures(started, time.Minute, 30*60, "admin", "203.0.113.9")
	stopped := log.records[len(log.records)-1].OccurredAt
	again := stopped.Add(3 * time.Hour)
	log.failures(again, time.Minute, 5, "root", "198.51.100.4")
	source := newSignInTestSource(log, 5, 10*time.Minute)
	look := func(source *signInAlertSource, at time.Time) []string {
		t.Helper()
		log.until = at
		got, err := source.Alerts(context.Background(), at)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(got))
		for _, alert := range got {
			ids = append(ids, alert.ID)
		}
		return ids
	}

	// The dispatcher looks every minute. Once an hour is enough to follow the
	// burst, since each look overlaps the one before.
	for at := started.Add(5 * time.Minute); at.Before(stopped.Add(2 * time.Hour)); at = at.Add(time.Hour) {
		if got, want := look(source, at), []string{signInAlertID(started)}; !slices.Equal(got, want) {
			t.Fatalf("look at %s = %v, want %v", at, got, want)
		}
	}
	if got, want := look(source, again.Add(5*time.Minute)), []string{signInAlertID(started), signInAlertID(again)}; !slices.Equal(got, want) {
		t.Fatalf("after the second burst began = %v, want %v", got, want)
	}
	// A day after its last failure, the first burst is no longer news.
	if got, want := look(source, stopped.Add(24*time.Hour+time.Minute)), []string{signInAlertID(again)}; !slices.Equal(got, want) {
		t.Fatalf("a day after the first burst = %v, want %v", got, want)
	}

	// A restart forgets what was reported. A burst whose start is out of sight
	// began a day ago and was reported then, so it is not reported again.
	restarted := newSignInTestSource(log, 5, 10*time.Minute)
	if got := look(restarted, stopped.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("after a restart = %v, want nothing", got)
	}
}

func TestSignInAlertKeepsAQuietRunApartFromALaterBurst(t *testing.T) {
	t.Parallel()

	// A lone failure in the morning, then a burst in the afternoon. The lone
	// failure is the oldest run each look reads, and must not pass for the
	// burst it came before.
	log := &fakeAuditLog{}
	log.add(alertTestNow.Add(-20*time.Hour), auth.ActionLoginFailed, "casey", "192.0.2.50")
	burstStart := alertTestNow.Add(-2 * time.Hour)
	log.failures(burstStart, time.Minute, 5, "admin", "203.0.113.9")
	source := newSignInTestSource(log, 5, 10*time.Minute)
	for _, at := range []time.Time{alertTestNow, alertTestNow.Add(time.Minute)} {
		got, err := source.Alerts(context.Background(), at)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].ID != signInAlertID(burstStart) || !strings.HasPrefix(got[0].Summary, "5 sign-ins failed") {
			t.Fatalf("look at %s = %+v, want the afternoon burst alone", at, got)
		}
	}
}

func TestSignInAlertFollowsAFloodPastTheRecordLimit(t *testing.T) {
	t.Parallel()

	// More failures in a few minutes than one look reads.
	log := &fakeAuditLog{}
	started := alertTestNow.Add(-10 * time.Minute)
	log.failures(started, 100*time.Millisecond, signInRecordLimit+1000, "admin", "203.0.113.9")
	source := newSignInTestSource(log, 5, 10*time.Minute)

	first, err := source.Alerts(context.Background(), alertTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || !strings.HasPrefix(first[0].Summary, "5000 sign-ins failed") {
		t.Fatalf("first look = %+v, want one alert counting the failures it read", first)
	}
	// The flood goes on, so the oldest failures read move on too, but the
	// burst keeps the ID it was first reported with.
	log.failures(alertTestNow, 100*time.Millisecond, 600, "admin", "203.0.113.9")
	later, err := source.Alerts(context.Background(), alertTestNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(later) != 1 || later[0].ID != first[0].ID {
		t.Fatalf("later look = %+v, want the same alert %s", later, first[0].ID)
	}
}

func TestNodeHealthPlacesEverySourceOnEachNode(t *testing.T) {
	t.Parallel()

	// With security switched off nobody signs in, so there is no sign-in
	// source.
	if sources, withSignIns := len(nodeHealth{}.alertSources()), len(nodeHealth{signIns: true}.alertSources()); withSignIns != sources+1 {
		t.Fatalf("sources = %d without sign-ins and %d with them, want one more with them", sources, withSignIns)
	}
	for _, source := range (nodeHealth{signIns: true}).alertSources() {
		placed, ok := source.(alerts.Placed)
		if !ok || placed.Placement() != alerts.OnEachNode {
			t.Errorf("%T is not placed on each node", source)
		}
	}
}

func TestClusterAlertNodeNamesTheNodeAloneAndInACluster(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	initial := config.Defaults()
	initial.Cluster.NodeName = "configured-name"
	configuration := config.NewManager(filepath.Join(directory, "sable.toml"), initial,
		func(context.Context, config.Config, config.Config) error { return nil })
	service, err := cluster.Open(cluster.Options{DataDirectory: filepath.Join(directory, "cluster"), NodeName: "ns1"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close(context.Background()) })
	node := clusterAlertNode(service, configuration)

	alone := node()
	if alone.ID == "" || alone.ID != service.Snapshot().NodeID || alone.Name != "configured-name" || alone.Clustered {
		t.Fatalf("alone = %+v, want the node ID, the configured name, and no cluster", alone)
	}
	if err := service.Initialize(context.Background(), "cluster.example", []string{"192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	clustered := node()
	if clustered.ID != alone.ID || clustered.Name != "ns1" || !clustered.Clustered {
		t.Fatalf("clustered = %+v, want the same ID, the cluster's name for it, and a cluster", clustered)
	}
	if subject := clustered.on("a.example"); !strings.HasSuffix(subject, " on ns1") {
		t.Fatalf("subject in a cluster = %q, want it to name the node", subject)
	}
}
