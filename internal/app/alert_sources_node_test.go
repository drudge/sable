package app

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/alerts"
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

func TestNodeHealthPlacesEverySourceOnEachNode(t *testing.T) {
	t.Parallel()

	sources := nodeHealth{}.alertSources()
	if len(sources) == 0 {
		t.Fatal("no node alert sources")
	}
	for _, source := range sources {
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
