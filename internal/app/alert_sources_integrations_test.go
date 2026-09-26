package app

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dynamicdns"
	"github.com/drudge/sable/internal/unifi"
	"github.com/drudge/sable/internal/update"
)

type integrationAlertTestConfiguration struct{ configuration config.Config }

func (configuration integrationAlertTestConfiguration) Current() config.Snapshot {
	return config.Snapshot{Config: configuration.configuration}
}

type fakeUniFiStatus unifi.Status

func (status fakeUniFiStatus) Status() unifi.Status { return unifi.Status(status) }

type fakeDynamicDNSStatus dynamicdns.Status

func (status fakeDynamicDNSStatus) Status(context.Context) dynamicdns.Status {
	return dynamicdns.Status(status)
}

type fakeUpdateStatus update.Status

func (status fakeUpdateStatus) Status() update.Status { return update.Status(status) }

// integrationAlertTestNow is the injected clock every source test reads.
var integrationAlertTestNow = time.Date(2026, 9, 25, 14, 0, 0, 0, time.UTC)

func TestUniFiAlertSourceReportsASyncThatKeepsFailing(t *testing.T) {
	t.Parallel()
	now := integrationAlertTestNow
	lastAttempt := now.Add(-2 * time.Minute)
	lastSuccess := time.Date(2026, 9, 25, 9, 30, 0, 0, time.UTC)
	failing := alerts.Alert{
		ID: "integrations.unifi-failing", Group: config.AlertGroupIntegrations, Kind: "integrations.unifi-failing",
		Problem: true, Tone: alerts.ToneAttention,
		Title: "UniFi sync failing", Subject: "192.168.1.1",
		Headline: "UniFi sync failed 3 times in a row.",
		Summary:  "The last 3 tries to sync with the UniFi controller failed. Records from UniFi stay as they were until one works.",
		Reasons:  []string{"Last error: controller unreachable", "Last success: Sep 25, 2026 09:30 UTC"},
		Path:     "/integrations", PathLabel: "Open Integrations", ObservedAt: lastAttempt,
	}
	neverWorked := failing
	neverWorked.Reasons = []string{"Last error: controller unreachable", "No sync has worked since Sable started"}
	unnamed := failing
	unnamed.Subject = "UniFi controller"
	for _, test := range []struct {
		name          string
		controllerURL string
		status        unifi.Status
		want          []alerts.Alert
	}{
		{
			name:   "two failures in a row stay quiet",
			status: unifi.Status{Enabled: true, ConsecutiveFailures: 2, LastError: "controller unreachable", LastAttempt: lastAttempt, LastSuccess: lastSuccess},
		},
		{
			name:   "three failures in a row alert with the last error and success",
			status: unifi.Status{Enabled: true, ConsecutiveFailures: 3, LastError: "controller unreachable", LastAttempt: lastAttempt, LastSuccess: lastSuccess},
			want:   []alerts.Alert{failing},
		},
		{
			name:   "a controller that never answered says so",
			status: unifi.Status{Enabled: true, ConsecutiveFailures: 3, LastError: "controller unreachable", LastAttempt: lastAttempt},
			want:   []alerts.Alert{neverWorked},
		},
		{
			name:          "a controller address without a host is named plainly",
			controllerURL: "not a URL",
			status:        unifi.Status{Enabled: true, ConsecutiveFailures: 3, LastError: "controller unreachable", LastAttempt: lastAttempt, LastSuccess: lastSuccess},
			want:          []alerts.Alert{unnamed},
		},
		{
			name:   "a paused integration stays quiet",
			status: unifi.Status{ConsecutiveFailures: 5, LastError: "controller unreachable", LastAttempt: lastAttempt},
		},
		{
			name:   "a sync that works again clears the alert",
			status: unifi.Status{Enabled: true, LastAttempt: lastAttempt, LastSuccess: lastAttempt},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			settings := config.UniFi{ControllerURL: "https://192.168.1.1"}
			if test.controllerURL != "" {
				settings.ControllerURL = test.controllerURL
			}
			source := newUniFiAlertSource(fakeUniFiStatus(test.status), integrationAlertTestConfiguration{config.Config{UniFi: settings}})

			got, err := source.Alerts(t.Context(), now)

			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("alerts = %+v\nwant %+v", got, test.want)
			}
		})
	}
}

func TestDynamicDNSAlertSourceReportsFailuresAndAddressChanges(t *testing.T) {
	t.Parallel()
	now := integrationAlertTestNow
	lastAttempt := now.Add(-time.Minute)
	lastSuccess := time.Date(2026, 9, 25, 11, 0, 0, 0, time.UTC)
	changedAt := now.Add(-time.Hour)
	twoNames := config.DynamicDNS{Enabled: true, Publishers: []config.DynamicDNSPublisher{{
		Provider: "cloudflare",
		Records: []config.DynamicDNSRecord{
			{Zone: "example.com", Name: "home.example.com", IPv4: true, IPv6: true, TTL: 600},
			{Zone: "example.com", Name: "vpn.example.com", IPv4: true, TTL: 600},
		},
	}}}
	ipv4Only := config.DynamicDNS{Enabled: true, Publishers: []config.DynamicDNSPublisher{{
		Provider: "cloudflare",
		Records:  []config.DynamicDNSRecord{{Zone: "example.com", Name: "home.example.com", IPv4: true, TTL: 600}},
	}}}
	failing := alerts.Alert{
		ID: "integrations.ddns-failing", Group: config.AlertGroupIntegrations, Kind: "integrations.ddns-failing",
		Problem: true, Tone: alerts.ToneAttention,
		Title: "Dynamic DNS failing", Subject: "home.example.com and 1 more",
		Headline: "Dynamic DNS failed 3 times in a row.",
		Summary: "The last 3 tries to publish this network's public address failed. " +
			"The records keep the last address Sable published until one works.",
		Reasons: []string{
			"Last error: cloudflare: publish home.example.com A: unexpected EOF; cloudflare: publish vpn.example.com A: unexpected EOF",
			"Last success: Sep 25, 2026 11:00 UTC",
		},
		Path: "/integrations", PathLabel: "Open Integrations", ObservedAt: lastAttempt,
	}
	ipv4Changed := alerts.Alert{
		ID: "integrations.ddns-ip-changed:198.51.100.4", Group: config.AlertGroupIntegrations, Kind: "integrations.ddns-ip-changed",
		Tone:  alerts.ToneNotice,
		Title: "Public IP changed", Subject: "home.example.com and 1 more",
		Headline: "The public IPv4 address changed from 203.0.113.7 to 198.51.100.4.",
		Summary: "The public IPv4 address changed from 203.0.113.7 to 198.51.100.4. " +
			"Dynamic DNS moved home.example.com and 1 more to the new address.",
		Reasons: []string{"Old address: 203.0.113.7", "New address: 198.51.100.4", "Names: home.example.com, vpn.example.com"},
		Path:    "/integrations", PathLabel: "Open Integrations", ObservedAt: changedAt,
	}
	ipv4NotYetPublished := ipv4Changed
	ipv4NotYetPublished.Summary = "The public IPv4 address changed from 203.0.113.7 to 198.51.100.4. " +
		"Dynamic DNS is still trying to move home.example.com and 1 more to it."
	ipv6Changed := alerts.Alert{
		ID: "integrations.ddns-ip-changed:2001:db8::2", Group: config.AlertGroupIntegrations, Kind: "integrations.ddns-ip-changed",
		Tone:  alerts.ToneNotice,
		Title: "Public IP changed", Subject: "home.example.com",
		Headline: "The public IPv6 address changed from 2001:db8::1 to 2001:db8::2.",
		Summary: "The public IPv6 address changed from 2001:db8::1 to 2001:db8::2. " +
			"Dynamic DNS moved home.example.com to the new address.",
		Reasons: []string{"Old address: 2001:db8::1", "New address: 2001:db8::2"},
		Path:    "/integrations", PathLabel: "Open Integrations", ObservedAt: changedAt,
	}
	providerErrors := "cloudflare: publish home.example.com A: unexpected EOF\ncloudflare: publish vpn.example.com A: unexpected EOF"
	for _, test := range []struct {
		name     string
		settings config.DynamicDNS
		status   dynamicdns.Status
		want     []alerts.Alert
	}{
		{
			name:     "two failed publishes stay quiet",
			settings: twoNames,
			status:   dynamicdns.Status{Enabled: true, ConsecutiveFailures: 2, LastError: providerErrors, LastAttempt: lastAttempt, LastSuccess: lastSuccess},
		},
		{
			name:     "three failed publishes alert with every provider's error",
			settings: twoNames,
			status:   dynamicdns.Status{Enabled: true, ConsecutiveFailures: 3, LastError: providerErrors, LastAttempt: lastAttempt, LastSuccess: lastSuccess},
			want:     []alerts.Alert{failing},
		},
		{
			name:     "a new IPv4 address is news for every name that publishes it",
			settings: twoNames,
			status: dynamicdns.Status{
				Enabled: true, IPv4: "198.51.100.4", PreviousIPv4: "203.0.113.7", IPv4ChangedAt: changedAt,
				LastAttempt: changedAt, LastSuccess: changedAt,
			},
			want: []alerts.Alert{ipv4Changed},
		},
		{
			name:     "a new IPv6 address names only what publishes IPv6",
			settings: twoNames,
			status: dynamicdns.Status{
				Enabled: true, IPv6: "2001:db8::2", PreviousIPv6: "2001:db8::1", IPv6ChangedAt: changedAt,
				LastAttempt: now.Add(-5 * time.Minute), LastSuccess: now.Add(-5 * time.Minute),
			},
			want: []alerts.Alert{ipv6Changed},
		},
		{
			name:     "a change stays news for just under a day",
			settings: twoNames,
			status: dynamicdns.Status{
				Enabled: true, IPv4: "198.51.100.4", PreviousIPv4: "203.0.113.7", IPv4ChangedAt: now.Add(-publicAddressNews + time.Minute),
				LastSuccess: now.Add(-publicAddressNews + time.Minute),
			},
			want: []alerts.Alert{func() alerts.Alert {
				stillNews := ipv4Changed
				stillNews.ObservedAt = now.Add(-publicAddressNews + time.Minute)
				return stillNews
			}()},
		},
		{
			name:     "a change a day old is no longer news",
			settings: twoNames,
			status: dynamicdns.Status{
				Enabled: true, IPv4: "198.51.100.4", PreviousIPv4: "203.0.113.7", IPv4ChangedAt: now.Add(-publicAddressNews),
				LastSuccess: now.Add(-publicAddressNews),
			},
		},
		{
			name:     "a change not published yet says so beside the failures",
			settings: twoNames,
			status: dynamicdns.Status{
				Enabled: true, ConsecutiveFailures: 3, LastError: providerErrors, LastAttempt: lastAttempt, LastSuccess: lastSuccess,
				IPv4: "198.51.100.4", PreviousIPv4: "203.0.113.7", IPv4ChangedAt: changedAt,
			},
			want: []alerts.Alert{failing, ipv4NotYetPublished},
		},
		{
			name:     "the first address found is not a change",
			settings: twoNames,
			status:   dynamicdns.Status{Enabled: true, IPv4: "198.51.100.4", LastAttempt: lastAttempt, LastSuccess: lastAttempt},
		},
		{
			name:     "a family nothing publishes any more stays quiet",
			settings: ipv4Only,
			status: dynamicdns.Status{
				Enabled: true, IPv6: "2001:db8::2", PreviousIPv6: "2001:db8::1", IPv6ChangedAt: changedAt, LastSuccess: changedAt,
			},
		},
		{
			name:     "a paused integration stays quiet",
			settings: twoNames,
			status: dynamicdns.Status{
				ConsecutiveFailures: 4, LastError: providerErrors, LastAttempt: lastAttempt,
				IPv4: "198.51.100.4", PreviousIPv4: "203.0.113.7", IPv4ChangedAt: changedAt,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			source := newDynamicDNSAlertSource(fakeDynamicDNSStatus(test.status), integrationAlertTestConfiguration{config.Config{DynamicDNS: test.settings}})

			got, err := source.Alerts(t.Context(), now)

			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("alerts = %+v\nwant %+v", got, test.want)
			}
		})
	}
}

func TestUpdateAlertSourceReportsANewerReleaseUntilSableRunsIt(t *testing.T) {
	t.Parallel()
	now := integrationAlertTestNow
	checkedAt := now.Add(-3 * time.Hour)
	available := alerts.Alert{
		ID: "updates.available:1.6.0", Group: config.AlertGroupUpdates, Kind: "updates.available", Tone: alerts.ToneNotice,
		Title: "Update available", Subject: "Sable v1.6.0",
		Headline: "Sable v1.6.0 is available.",
		Summary: "Sable v1.6.0 is out, and this server runs v1.5.2. " +
			"Read what changed and install it from the About page when you're ready.",
		Reasons: []string{"Running v1.5.2", "Newest v1.6.0"},
		Path:    "/about", PathLabel: "Open About", ObservedAt: checkedAt,
	}
	preRelease := alerts.Alert{
		ID: "updates.available:1.6.0-rc.1", Group: config.AlertGroupUpdates, Kind: "updates.available", Tone: alerts.ToneNotice,
		Title: "Update available", Subject: "Sable v1.6.0-rc.1",
		Headline: "Sable v1.6.0-rc.1 is available as a pre-release.",
		Summary: "Sable v1.6.0-rc.1 is out as a pre-release, and this server runs v1.5.2. " +
			"Read what changed and install it from the About page when you're ready.",
		Reasons: []string{"Running v1.5.2", "Newest v1.6.0-rc.1, a pre-release"},
		Path:    "/about", PathLabel: "Open About", ObservedAt: checkedAt,
	}
	installed := available
	installed.Summary = "Sable v1.6.0 is out, and this server runs v1.5.2. It is installed and starts when Sable restarts."
	for _, test := range []struct {
		name   string
		status update.Status
		want   []alerts.Alert
	}{
		{
			name:   "a newer release is news",
			status: update.Status{Phase: update.PhaseIdle, CurrentVersion: "1.5.2", LatestVersion: "1.6.0", Available: true, CheckedAt: checkedAt},
			want:   []alerts.Alert{available},
		},
		{
			name: "a newer pre-release says so",
			status: update.Status{
				Phase: update.PhaseIdle, CurrentVersion: "1.5.2", LatestVersion: "1.6.0-rc.1", PreRelease: true, IncludePreRelease: true,
				Available: true, CheckedAt: checkedAt,
			},
			want: []alerts.Alert{preRelease},
		},
		{
			name: "a later check that failed keeps the news",
			status: update.Status{
				Phase: update.PhaseFailed, Error: "GitHub is unreachable", CurrentVersion: "1.5.2", LatestVersion: "1.6.0", CheckedAt: checkedAt,
			},
			want: []alerts.Alert{available},
		},
		{
			name: "an installed release is news until the restart",
			status: update.Status{
				Phase: update.PhaseInstalled, CurrentVersion: "1.5.2", LatestVersion: "1.6.0", Available: true, Installed: true, CheckedAt: checkedAt,
			},
			want: []alerts.Alert{installed},
		},
		{
			name:   "the running release is not news",
			status: update.Status{Phase: update.PhaseIdle, CurrentVersion: "1.6.0", LatestVersion: "1.6.0", CheckedAt: checkedAt},
		},
		{
			name:   "a development build is never told",
			status: update.Status{Phase: update.PhaseIdle, CurrentVersion: "dev", Development: true, LatestVersion: "1.6.0", CheckedAt: checkedAt},
		},
		{
			name:   "no check yet has no news",
			status: update.Status{Phase: update.PhaseIdle, CurrentVersion: "1.5.2"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			source := newUpdateAlertSource(fakeUpdateStatus(test.status))

			got, err := source.Alerts(t.Context(), now)

			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("alerts = %+v\nwant %+v", got, test.want)
			}
		})
	}
}
