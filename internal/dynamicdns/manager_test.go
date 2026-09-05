package dynamicdns

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
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
	found       bool
}

func (store *testCredentialStore) Get(context.Context, string) (dnsprovider.Credentials, bool) {
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

func (provider *testProvider) EnsureRecord(_ context.Context, record dnsprovider.Record) (bool, error) {
	provider.records = append(provider.records, record)
	return provider.changed, provider.err
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
	if status.Changed != 4 || status.IPv4 != "8.8.8.8" || status.IPv6 != "2001:4860:4860::8888" || status.LastSuccess.IsZero() {
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
