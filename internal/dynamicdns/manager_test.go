package dynamicdns

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsprovider"
)

type testConfiguration struct {
	settings config.DynamicDNS
}

func (configuration testConfiguration) Current() config.Snapshot {
	return config.Snapshot{Config: config.Config{DynamicDNS: configuration.settings}}
}

type testCredentialStore struct {
	credentials dnsprovider.Credentials
	byProvider  map[string]dnsprovider.Credentials
	found       bool
}

func (store *testCredentialStore) Get(_ context.Context, provider string) (dnsprovider.Credentials, bool) {
	if credentials, found := store.byProvider[provider]; found {
		return credentials, true
	}
	return store.credentials, store.found
}

func (store *testCredentialStore) Put(_ context.Context, _ string, credentials dnsprovider.Credentials) error {
	store.credentials, store.found = credentials, true
	return nil
}

type testProvider struct {
	records []dnsprovider.Record
	changed bool
	err     error
}

type testStateStore struct {
	state PersistentState
	saves int
}

func (store *testStateStore) LoadDynamicDNSState(context.Context) (PersistentState, error) {
	return store.state, nil
}

func (store *testStateStore) SaveDynamicDNSState(_ context.Context, state PersistentState) error {
	store.state = state
	store.saves++
	return nil
}

func (provider *testProvider) EnsureRecord(_ context.Context, record dnsprovider.Record) (bool, error) {
	provider.records = append(provider.records, record)
	return provider.changed, provider.err
}

func TestPublicationHistorySurvivesManagerRestart(t *testing.T) {
	ctx := context.Background()
	durable := &testStateStore{}
	manager := newTestManager(testDynamicDNSSettings(), &testProvider{changed: true})
	manager.state = durable
	manager.discover = func(context.Context, string, string) (netip.Addr, error) {
		return netip.MustParseAddr("8.8.8.8"), nil
	}
	manager.runOnce(ctx)
	if durable.saves != 1 || durable.state.LastPublished.IsZero() {
		t.Fatalf("saved state = %+v after %d saves", durable.state, durable.saves)
	}

	restarted := newTestManager(testDynamicDNSSettings(), &testProvider{})
	restarted.state = durable
	restarted.restoreStatus(ctx)
	status := restarted.Status(ctx)
	if status.IPv4 != "8.8.8.8" || status.LastSuccess != durable.state.LastSuccess || status.LastPublished != durable.state.LastPublished {
		t.Fatalf("restored status = %+v, want %+v", status, durable.state)
	}
}

// addressHistory is the part of the status an address-change alert reads.
type addressHistory struct {
	IPv4, IPv6, PreviousIPv4, PreviousIPv6 string
	IPv4ChangedAt, IPv6ChangedAt           time.Time
}

func historyOf(status Status) addressHistory {
	return addressHistory{
		IPv4: status.IPv4, IPv6: status.IPv6, PreviousIPv4: status.PreviousIPv4, PreviousIPv6: status.PreviousIPv6,
		IPv4ChangedAt: status.IPv4ChangedAt, IPv6ChangedAt: status.IPv6ChangedAt,
	}
}

// A changed address stays news for a while, so what it changed from and when
// must survive a restart, including one straight after an upgrade from a
// release that saved no history.
func TestAddressChangesAreRememberedAcrossARestart(t *testing.T) {
	t.Parallel()
	run := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	earlier := run.Add(-3 * time.Hour)
	for _, test := range []struct {
		name string
		// saved is what an earlier run left in the database.
		saved PersistentState
		// ipv4 and ipv6 are what this run discovers; empty fails discovery.
		ipv4, ipv6 string
		want       addressHistory
	}{
		{
			name: "the first address found is not a change",
			ipv4: "8.8.8.8", ipv6: "2001:4860:4860::8888",
			want: addressHistory{IPv4: "8.8.8.8", IPv6: "2001:4860:4860::8888"},
		},
		{
			name:  "the same address again is not a change",
			saved: PersistentState{IPv4: "8.8.8.8", IPv6: "2001:4860:4860::8888", LastSuccess: earlier},
			ipv4:  "8.8.8.8", ipv6: "2001:4860:4860::8888",
			want: addressHistory{IPv4: "8.8.8.8", IPv6: "2001:4860:4860::8888"},
		},
		{
			name:  "a new IPv4 address after state an older release saved",
			saved: PersistentState{IPv4: "8.8.4.4", IPv6: "2001:4860:4860::8888", LastSuccess: earlier},
			ipv4:  "8.8.8.8", ipv6: "2001:4860:4860::8888",
			want: addressHistory{IPv4: "8.8.8.8", IPv6: "2001:4860:4860::8888", PreviousIPv4: "8.8.4.4", IPv4ChangedAt: run},
		},
		{
			name:  "a new IPv6 address leaves the IPv4 history alone",
			saved: PersistentState{IPv4: "8.8.8.8", IPv6: "2001:4860:4860::8844", PreviousIPv4: "8.8.4.4", IPv4ChangedAt: earlier},
			ipv4:  "8.8.8.8", ipv6: "2001:4860:4860::8888",
			want: addressHistory{
				IPv4: "8.8.8.8", IPv6: "2001:4860:4860::8888", PreviousIPv4: "8.8.4.4", PreviousIPv6: "2001:4860:4860::8844",
				IPv4ChangedAt: earlier, IPv6ChangedAt: run,
			},
		},
		{
			name:  "a later change replaces the earlier one",
			saved: PersistentState{IPv4: "8.8.4.4", IPv6: "2001:4860:4860::8888", PreviousIPv4: "1.1.1.1", IPv4ChangedAt: earlier},
			ipv4:  "8.8.8.8", ipv6: "2001:4860:4860::8888",
			want: addressHistory{IPv4: "8.8.8.8", IPv6: "2001:4860:4860::8888", PreviousIPv4: "8.8.4.4", IPv4ChangedAt: run},
		},
		{
			name:  "a failed discovery keeps the history",
			saved: PersistentState{IPv4: "8.8.8.8", IPv6: "2001:4860:4860::8888", PreviousIPv4: "8.8.4.4", IPv4ChangedAt: earlier},
			want:  addressHistory{IPv4: "8.8.8.8", IPv6: "2001:4860:4860::8888", PreviousIPv4: "8.8.4.4", IPv4ChangedAt: earlier},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			settings := testDynamicDNSSettings()
			settings.Records[0].IPv6 = true
			durable := &testStateStore{state: test.saved}
			manager := newTestManager(settings, &testProvider{changed: true})
			manager.state = durable
			manager.now = func() time.Time { return run }
			manager.discover = func(_ context.Context, _ string, recordType string) (netip.Addr, error) {
				address := test.ipv4
				if recordType == dnsprovider.TypeAAAA {
					address = test.ipv6
				}
				if address == "" {
					return netip.Addr{}, io.ErrUnexpectedEOF
				}
				return netip.MustParseAddr(address), nil
			}
			manager.restoreStatus(ctx)
			manager.runOnce(ctx)

			restarted := newTestManager(settings, &testProvider{})
			restarted.state = durable
			restarted.restoreStatus(ctx)
			if got := historyOf(restarted.Status(ctx)); got != test.want {
				t.Fatalf("address history after a restart = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestReconcileDiscoversEachFamilyOnceAndPublishesEveryRecord(t *testing.T) {
	settings := config.DynamicDNS{
		Enabled: true, Provider: "cloudflare", Interval: config.Duration{Duration: 5 * time.Minute},
		IPv4URL: "https://ipv4.test", IPv6URL: "https://ipv6.test",
		Records: []config.DynamicDNSRecord{
			{Zone: "example.com", Name: "home.example.com", IPv4: true, IPv6: true, TTL: 300},
			{Zone: "example.com", Name: "vpn.example.com", IPv4: true, IPv6: true, TTL: 300},
		},
	}
	publisher := &testProvider{changed: true}
	discoveries := 0
	manager := newTestManager(settings, publisher)
	manager.discover = func(_ context.Context, endpoint, recordType string) (netip.Addr, error) {
		discoveries++
		if endpoint == settings.IPv4URL && recordType == dnsprovider.TypeA {
			return netip.MustParseAddr("8.8.8.8"), nil
		}
		return netip.MustParseAddr("2001:4860:4860::8888"), nil
	}
	manager.runOnce(context.Background())
	if discoveries != 2 {
		t.Fatalf("discoveries = %d, want 2", discoveries)
	}
	if len(publisher.records) != 4 {
		t.Fatalf("published records = %d, want 4", len(publisher.records))
	}
	status := manager.Status(context.Background())
	if status.Changed != 4 || status.IPv4 != "8.8.8.8" || status.IPv6 != "2001:4860:4860::8888" || status.LastSuccess.IsZero() || status.LastPublished.IsZero() {
		t.Fatalf("status = %+v", status)
	}
}

func TestReconcilePublishesMultipleProvidersAndZonesInOneRun(t *testing.T) {
	settings := config.DynamicDNS{
		Enabled: true, Interval: config.Duration{Duration: 5 * time.Minute},
		IPv4URL: "https://ipv4.test", IPv6URL: "https://ipv6.test",
		Publishers: []config.DynamicDNSPublisher{
			{Provider: "cloudflare", Records: []config.DynamicDNSRecord{
				{Zone: "example.com", Name: "home.example.com", IPv4: true, TTL: 300},
				{Zone: "example.net", Name: "vpn.example.net", IPv6: true, TTL: 600},
			}},
			{Provider: "route53", Records: []config.DynamicDNSRecord{
				{Zone: "example.org", Name: "edge.example.org", IPv4: true, IPv6: true, TTL: 300},
			}},
		},
	}
	providers := map[string]*testProvider{
		"cloudflare": {changed: true},
		"route53":    {changed: true},
	}
	manager := newTestManager(settings, providers["cloudflare"])
	manager.credentials = &testCredentialStore{byProvider: map[string]dnsprovider.Credentials{
		"cloudflare": {APIToken: "cloudflare-token", ZoneID: "single-zone-shortcut"},
		"route53":    {AccessKeyID: "access", SecretAccessKey: "secret"},
	}}
	var initialized []string
	manager.newProvider = func(name string, credentials dnsprovider.Credentials) (provider, error) {
		initialized = append(initialized, name)
		if name == "cloudflare" && credentials.ZoneID != "" {
			t.Errorf("multi-zone provider retained single-zone ID %q", credentials.ZoneID)
		}
		if name == "route53" && credentials.AccessKeyID != "access" {
			t.Errorf("Route 53 received the wrong credentials: %+v", credentials)
		}
		return providers[name], nil
	}
	discoveries := 0
	manager.discover = func(_ context.Context, _ string, recordType string) (netip.Addr, error) {
		discoveries++
		if recordType == dnsprovider.TypeA {
			return netip.MustParseAddr("8.8.8.8"), nil
		}
		return netip.MustParseAddr("2001:4860:4860::8888"), nil
	}

	manager.runOnce(context.Background())

	if discoveries != 2 || len(initialized) != 2 || len(providers["cloudflare"].records) != 2 || len(providers["route53"].records) != 2 {
		t.Fatalf("discoveries = %d, providers = %v, Cloudflare = %v, Route 53 = %v", discoveries, initialized, providers["cloudflare"].records, providers["route53"].records)
	}
	if status := manager.Status(context.Background()); status.Changed != 4 || status.Records != 4 || status.LastPublished.IsZero() {
		t.Fatalf("status = %+v", status)
	}
}

func TestReconcileContinuesAfterOneProviderFails(t *testing.T) {
	settings := config.DynamicDNS{
		Enabled: true, Interval: config.Duration{Duration: 5 * time.Minute},
		IPv4URL: "https://ipv4.test", IPv6URL: "https://ipv6.test",
		Publishers: []config.DynamicDNSPublisher{
			{Provider: "cloudflare", Records: []config.DynamicDNSRecord{{Zone: "example.com", Name: "home.example.com", IPv4: true, TTL: 300}}},
			{Provider: "route53", Records: []config.DynamicDNSRecord{{Zone: "example.net", Name: "vpn.example.net", IPv4: true, TTL: 300}}},
		},
	}
	providers := map[string]*testProvider{
		"cloudflare": {err: io.ErrUnexpectedEOF},
		"route53":    {changed: true},
	}
	manager := newTestManager(settings, providers["cloudflare"])
	manager.newProvider = func(name string, _ dnsprovider.Credentials) (provider, error) { return providers[name], nil }
	manager.discover = func(context.Context, string, string) (netip.Addr, error) {
		return netip.MustParseAddr("8.8.8.8"), nil
	}

	manager.runOnce(context.Background())

	if len(providers["route53"].records) != 1 {
		t.Fatalf("Route 53 publication attempts = %d, want 1", len(providers["route53"].records))
	}
	status := manager.Status(context.Background())
	if status.Changed != 1 || status.LastPublished.IsZero() || !strings.Contains(status.LastError, "cloudflare") {
		t.Fatalf("status after partial publication = %+v", status)
	}
}

func TestReconcileDoesNotClaimPublicationWhenRecordsAreUnchanged(t *testing.T) {
	manager := newTestManager(testDynamicDNSSettings(), &testProvider{})
	manager.discover = func(context.Context, string, string) (netip.Addr, error) {
		return netip.MustParseAddr("8.8.8.8"), nil
	}

	manager.runOnce(context.Background())

	status := manager.Status(context.Background())
	if status.LastSuccess.IsZero() || !status.LastPublished.IsZero() {
		t.Fatalf("status = %+v", status)
	}
}

func TestReconcileDoesNotPublishWhenDiscoveryFails(t *testing.T) {
	settings := testDynamicDNSSettings()
	publisher := &testProvider{changed: true}
	manager := newTestManager(settings, publisher)
	manager.discover = func(context.Context, string, string) (netip.Addr, error) {
		return netip.Addr{}, io.ErrUnexpectedEOF
	}
	manager.runOnce(context.Background())
	if len(publisher.records) != 0 {
		t.Fatalf("published records = %d, want none", len(publisher.records))
	}
	status := manager.Status(context.Background())
	if status.LastError == "" || status.NextAttempt.IsZero() {
		t.Fatalf("status = %+v", status)
	}
}

func TestFailedDiscoveryRetainsLastKnownAddress(t *testing.T) {
	manager := newTestManager(testDynamicDNSSettings(), &testProvider{})
	manager.status.IPv4 = "8.8.4.4"
	manager.discover = func(context.Context, string, string) (netip.Addr, error) {
		return netip.Addr{}, io.ErrUnexpectedEOF
	}
	manager.runOnce(context.Background())
	if status := manager.Status(context.Background()); status.IPv4 != "8.8.4.4" {
		t.Fatalf("last known IPv4 address = %q", status.IPv4)
	}
}

func TestReplicaDoesNotDiscoverOrPublish(t *testing.T) {
	settings := testDynamicDNSSettings()
	publisher := &testProvider{changed: true}
	manager := newTestManager(settings, publisher)
	manager.writable = func() bool { return false }
	discovered := false
	manager.discover = func(context.Context, string, string) (netip.Addr, error) {
		discovered = true
		return netip.MustParseAddr("8.8.8.8"), nil
	}
	manager.runOnce(context.Background())
	if discovered || len(publisher.records) != 0 {
		t.Fatal("replica attempted dynamic DNS publication")
	}
}

func TestValidatePublicAddressRejectsPrivateAndWrongFamily(t *testing.T) {
	for _, test := range []struct {
		address    string
		recordType string
	}{
		{"192.168.1.1", dnsprovider.TypeA},
		{"100.64.0.1", dnsprovider.TypeA},
		{"198.51.100.1", dnsprovider.TypeA},
		{"8.8.8.8", dnsprovider.TypeAAAA},
		{"2001:4860:4860::8888", dnsprovider.TypeA},
		{"2001:db8::1", dnsprovider.TypeAAAA},
		{"fd00::1", dnsprovider.TypeAAAA},
	} {
		if err := validatePublicAddress(netip.MustParseAddr(test.address), test.recordType); err == nil {
			t.Fatalf("accepted %s as %s", test.address, test.recordType)
		}
	}
	if err := validatePublicAddress(netip.MustParseAddr("8.8.8.8"), dnsprovider.TypeA); err != nil {
		t.Fatal(err)
	}
}

// Alerts wait for several failed publishes in a row, and retries back off by
// the same count, so it must reset the moment a publish works.
func TestConsecutiveFailuresAddUpAndResetOnSuccess(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		outcomes  []error
		want      int
		wantRetry time.Duration
	}{
		{name: "each failed publish adds one", outcomes: []error{io.ErrUnexpectedEOF, io.ErrUnexpectedEOF, io.ErrUnexpectedEOF}, want: 3, wantRetry: 2 * time.Minute},
		{name: "a publish that works starts the count over", outcomes: []error{io.ErrUnexpectedEOF, io.ErrUnexpectedEOF, nil}, want: 0, wantRetry: 5 * time.Minute},
		{name: "failures after a success count from one", outcomes: []error{io.ErrUnexpectedEOF, nil, io.ErrUnexpectedEOF}, want: 1, wantRetry: 30 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			publisher := &testProvider{changed: true}
			manager := newTestManager(testDynamicDNSSettings(), publisher)
			manager.discover = func(context.Context, string, string) (netip.Addr, error) {
				return netip.MustParseAddr("8.8.8.8"), nil
			}
			for _, outcome := range test.outcomes {
				publisher.err = outcome
				manager.runOnce(context.Background())
			}
			status := manager.Status(context.Background())
			if status.ConsecutiveFailures != test.want {
				t.Fatalf("consecutive failures = %d, want %d", status.ConsecutiveFailures, test.want)
			}
			if retry := status.NextAttempt.Sub(status.LastAttempt); retry != test.wantRetry {
				t.Fatalf("next attempt in %s, want %s", retry, test.wantRetry)
			}
		})
	}
}

func TestRetryDelayBacksOffAndRespectsInterval(t *testing.T) {
	if got := retryDelay(1, 5*time.Minute); got != 30*time.Second {
		t.Fatalf("first retry = %s", got)
	}
	if got := retryDelay(8, time.Minute); got != time.Minute {
		t.Fatalf("capped retry = %s", got)
	}
}

func TestSyncNowCoalescesWhilePublicationIsQueued(t *testing.T) {
	manager := newTestManager(testDynamicDNSSettings(), &testProvider{})
	manager.SyncNow()
	manager.SyncNow()
	if !manager.Status(context.Background()).Running {
		t.Error("queued publication did not immediately report running")
	}
	if queued := len(manager.wake); queued != 1 {
		t.Fatalf("queued publications = %d, want 1", queued)
	}
}

func newTestManager(settings config.DynamicDNS, publisher *testProvider) *Manager {
	manager := &Manager{
		configuration: testConfiguration{settings: settings},
		credentials: &testCredentialStore{
			credentials: dnsprovider.Credentials{APIToken: "token"}, found: true,
		},
		writable: func() bool { return true },
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC) },
		wake:     make(chan struct{}, 1),
	}
	manager.newProvider = func(string, dnsprovider.Credentials) (provider, error) { return publisher, nil }
	return manager
}

func testDynamicDNSSettings() config.DynamicDNS {
	return config.DynamicDNS{
		Enabled: true, Provider: "cloudflare", Interval: config.Duration{Duration: 5 * time.Minute},
		IPv4URL: "https://ipv4.test", IPv6URL: "https://ipv6.test",
		Records: []config.DynamicDNSRecord{{
			Zone: "example.com", Name: "home.example.com", IPv4: true, TTL: 300,
		}},
	}
}
