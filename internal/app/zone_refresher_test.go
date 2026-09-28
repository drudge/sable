package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/drudge/sable/internal/dnsserver"
	zonemodel "github.com/drudge/sable/internal/zone"
)

type refreshTestConfiguration struct {
	snapshot zonemodel.Snapshot
	updates  int
}

func (configuration *refreshTestConfiguration) Current() zonemodel.Snapshot {
	return configuration.snapshot
}

func (configuration *refreshTestConfiguration) UpdateZones(_ context.Context, mutate func(*[]zonemodel.Zone) error) error {
	zones := configuration.snapshot.Zones
	if err := mutate(&zones); err != nil {
		return err
	}
	configuration.snapshot.Zones = zones
	configuration.updates++
	return nil
}

type refreshTestDNS struct {
	updated       []dnsserver.ZoneRecord
	changed       bool
	err           error
	calls         int
	expired       map[string]bool
	notifications chan dnsserver.ZoneNotification
}

func (service *refreshTestDNS) FetchZone(
	context.Context, string, string, []string, string, string,
) ([]dnsserver.ZoneRecord, error) {
	return service.updated, service.err
}

func (service *refreshTestDNS) RefreshZone(
	context.Context, string, string, []string, string, string, []dnsserver.ZoneRecord,
) ([]dnsserver.ZoneRecord, bool, error) {
	service.calls++
	return service.updated, service.changed, service.err
}

func (service *refreshTestDNS) SetZoneExpired(name string, expired bool) {
	service.expired[name] = expired
}

func (service *refreshTestDNS) Notifications() <-chan dnsserver.ZoneNotification {
	return service.notifications
}

func TestZoneRefresherUsesSOARefreshAndStoresChangedRecords(t *testing.T) {
	t.Parallel()

	zone := managedTestZone()
	configuration := &refreshTestConfiguration{snapshot: zonemodel.Snapshot{Zones: []zonemodel.Zone{zone}}}
	dnsService := &refreshTestDNS{
		changed: true, expired: make(map[string]bool),
		updated: []dnsserver.ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.secondary.test. hostmaster.secondary.test. 2 10 3 20 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.secondary.test."},
		},
	}
	refresher := newZoneRefresher(configuration, dnsService, slog.New(slog.NewTextHandler(io.Discard, nil)))
	started := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	refresher.step(context.Background(), started)
	if dnsService.calls != 0 {
		t.Fatalf("initial refresh calls = %d, want 0", dnsService.calls)
	}
	refresher.step(context.Background(), started.Add(9*time.Second))
	if dnsService.calls != 0 {
		t.Fatalf("early refresh calls = %d, want 0", dnsService.calls)
	}
	refresher.step(context.Background(), started.Add(10*time.Second))
	if dnsService.calls != 1 || configuration.updates != 1 {
		t.Fatalf("due refresh calls=%d updates=%d", dnsService.calls, configuration.updates)
	}
	soa, _, err := configuredZoneSOA(configuration.snapshot.Zones[0])
	if err != nil || soa.Serial != 2 {
		t.Fatalf("stored SOA = %+v, %v", soa, err)
	}
	state := refresher.states[zone.Name]
	if !state.nextAttempt.Equal(started.Add(20*time.Second)) || !state.expiresAt.Equal(started.Add(30*time.Second)) {
		t.Fatalf("refreshed state = %+v", state)
	}
	if dnsService.expired[zone.Name] {
		t.Fatal("successfully refreshed zone is expired")
	}
}

func TestZoneRefresherRetriesAndExpiresFailedZone(t *testing.T) {
	t.Parallel()

	zone := managedTestZone()
	configuration := &refreshTestConfiguration{snapshot: zonemodel.Snapshot{Zones: []zonemodel.Zone{zone}}}
	dnsService := &refreshTestDNS{err: errors.New("primary unavailable"), expired: make(map[string]bool)}
	refresher := newZoneRefresher(configuration, dnsService, slog.New(slog.NewTextHandler(io.Discard, nil)))
	started := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	refresher.step(context.Background(), started)
	refresher.step(context.Background(), started.Add(10*time.Second))
	if dnsService.calls != 1 || !refresher.states[zone.Name].nextAttempt.Equal(started.Add(13*time.Second)) {
		t.Fatalf("first failure calls=%d state=%+v", dnsService.calls, refresher.states[zone.Name])
	}
	refresher.step(context.Background(), started.Add(13*time.Second))
	if dnsService.calls != 2 {
		t.Fatalf("retry calls = %d, want 2", dnsService.calls)
	}
	refresher.step(context.Background(), started.Add(20*time.Second))
	if !dnsService.expired[zone.Name] {
		t.Fatal("zone did not expire after the SOA expire interval")
	}
}

func TestZoneRefresherImmediatelyHandlesAndCoalescesNotify(t *testing.T) {
	t.Parallel()

	zone := managedTestZone()
	configuration := &refreshTestConfiguration{snapshot: zonemodel.Snapshot{Zones: []zonemodel.Zone{zone}}}
	dnsService := &refreshTestDNS{expired: make(map[string]bool)}
	refresher := newZoneRefresher(configuration, dnsService, slog.New(slog.NewTextHandler(io.Discard, nil)))
	started := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	refresher.step(context.Background(), started)
	refresher.handleNotification(context.Background(), dnsserver.ZoneNotification{
		Zone: zone.Name, Source: "192.0.2.53", ReceivedAt: started.Add(time.Second),
	})
	if dnsService.calls != 1 {
		t.Fatalf("NOTIFY refresh calls = %d, want 1", dnsService.calls)
	}
	refresher.handleNotification(context.Background(), dnsserver.ZoneNotification{
		Zone: zone.Name, Source: "192.0.2.53", ReceivedAt: started.Add(1500 * time.Millisecond),
	})
	if dnsService.calls != 1 {
		t.Fatalf("duplicate NOTIFY refresh calls = %d, want 1", dnsService.calls)
	}
	refresher.handleNotification(context.Background(), dnsserver.ZoneNotification{
		Zone: zone.Name, Source: "192.0.2.53", ReceivedAt: started.Add(4 * time.Second),
	})
	if dnsService.calls != 2 {
		t.Fatalf("later NOTIFY refresh calls = %d, want 2", dnsService.calls)
	}
}

func managedTestZone() zonemodel.Zone {
	return zonemodel.Zone{
		Name: "secondary.test", Type: "secondary", DefaultTTL: 300,
		PrimaryServers: []string{"192.0.2.53:53"}, PrimaryProtocol: "tcp",
		Records: []zonemodel.Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.secondary.test. hostmaster.secondary.test. 1 10 3 20 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.secondary.test."},
		},
	}
}

func catalogTestZone() zonemodel.Zone {
	return zonemodel.Zone{
		Name: "catalog.example", Type: "catalog", DefaultTTL: 300,
		PrimaryServers: []string{"192.0.2.53:53"}, PrimaryProtocol: "tcp",
		Records: []zonemodel.Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "invalid. hostmaster.catalog.example. 1 10 3 20 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "invalid."},
			{Name: "version", Type: "TXT", TTL: 300, Value: `"2"`},
		},
	}
}

func TestZoneRefresherRefreshesSubscribedCatalogs(t *testing.T) {
	t.Parallel()

	configuration := &refreshTestConfiguration{
		snapshot: zonemodel.Snapshot{Zones: []zonemodel.Zone{catalogTestZone()}},
	}
	dnsService := &refreshTestDNS{changed: true, expired: make(map[string]bool)}
	refresher := newZoneRefresher(configuration, dnsService, slog.New(slog.NewTextHandler(io.Discard, nil)))

	start := time.Now()
	refresher.step(context.Background(), start)
	// The first pass only schedules the zone from its SOA refresh timer.
	refresher.step(context.Background(), start.Add(11*time.Second))

	if dnsService.calls == 0 {
		t.Fatal("a subscribed catalog zone was never refreshed")
	}
}

func TestZoneRefresherFetchesCatalogMemberFirstTransfer(t *testing.T) {
	t.Parallel()

	member := zonemodel.Zone{
		Name: "member.example", Type: "secondary", DefaultTTL: 300,
		PrimaryServers: []string{"192.0.2.53:53"}, PrimaryProtocol: "tcp",
		CatalogZone: "catalog.example", CatalogMemberID: "aaa",
	}
	configuration := &refreshTestConfiguration{
		snapshot: zonemodel.Snapshot{Zones: []zonemodel.Zone{member}},
	}
	dnsService := &refreshTestDNS{
		expired: make(map[string]bool),
		updated: []dnsserver.ZoneRecord{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.member.example. hostmaster.member.example. 4 10 3 20 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.member.example."},
		},
	}
	refresher := newZoneRefresher(configuration, dnsService, slog.New(slog.NewTextHandler(io.Discard, nil)))
	refresher.step(context.Background(), time.Now())

	stored := configuration.snapshot.Zones[0]
	if len(stored.Records) != 2 {
		t.Fatalf("expected the member to receive its first transfer, got %d records", len(stored.Records))
	}
	if zonemodel.AwaitingFirstTransfer(stored) {
		t.Fatal("the member should no longer be awaiting its first transfer")
	}
}

func TestZoneRefresherPacesFailedFirstTransfers(t *testing.T) {
	t.Parallel()

	member := zonemodel.Zone{
		Name: "member.example", Type: "secondary", DefaultTTL: 300,
		PrimaryServers: []string{"192.0.2.53:53"}, PrimaryProtocol: "tcp",
		CatalogZone: "catalog.example", CatalogMemberID: "aaa",
	}
	configuration := &refreshTestConfiguration{
		snapshot: zonemodel.Snapshot{Zones: []zonemodel.Zone{member}},
	}
	dnsService := &refreshTestDNS{expired: make(map[string]bool), err: errors.New("primary unreachable")}
	refresher := newZoneRefresher(configuration, dnsService, slog.New(slog.NewTextHandler(io.Discard, nil)))

	start := time.Now()
	refresher.step(context.Background(), start)
	refresher.step(context.Background(), start.Add(time.Second))
	refresher.step(context.Background(), start.Add(2*time.Second))
	if configuration.updates != 0 {
		t.Fatal("a failed first transfer must not store records")
	}
	state, tracked := refresher.states["member.example"]
	if !tracked || !state.nextAttempt.After(start.Add(30*time.Second)) {
		t.Fatalf("a failed first transfer was not paced: %+v", state)
	}
}

func TestZoneRefresherStatusCountsFailuresInARowUntilOneWorks(t *testing.T) {
	t.Parallel()

	started := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	transferred := []dnsserver.ZoneRecord{
		{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.member.example. hostmaster.member.example. 4 10 3 20 300"},
		{Name: "@", Type: "NS", TTL: 300, Value: "ns1.member.example."},
	}
	for _, testCase := range []struct {
		name string
		zone zonemodel.Zone
		// failing lists when the refresher runs while the primary is down, and
		// working when it runs once the primary answers again.
		failing []time.Duration
		working time.Duration
		want    zoneRefreshStatus
	}{
		{
			name: "secondary refresh",
			zone: managedTestZone(),
			// The first run only schedules the zone. Its SOA refreshes after 10
			// seconds, retries after 3, and expires after 20.
			failing: []time.Duration{0, 10 * time.Second, 13 * time.Second},
			working: 16 * time.Second,
			want: zoneRefreshStatus{
				Zone: "secondary.test", Failures: 2, FailingSince: started.Add(10 * time.Second),
				LastError: "primary unavailable", ExpiresAt: started.Add(20 * time.Second),
			},
		},
		{
			name: "catalog member first transfer",
			zone: zonemodel.Zone{
				Name: "member.example", Type: "secondary", DefaultTTL: 300,
				PrimaryServers: []string{"192.0.2.53:53"}, PrimaryProtocol: "tcp",
				CatalogZone: "catalog.example", CatalogMemberID: "aaa",
			},
			failing: []time.Duration{0, firstTransferRetry},
			working: 2 * firstTransferRetry,
			// A zone that has never transferred has no expiry to report.
			want: zoneRefreshStatus{Zone: "member.example", Failures: 2, FailingSince: started, LastError: "primary unavailable"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			configuration := &refreshTestConfiguration{snapshot: zonemodel.Snapshot{Zones: []zonemodel.Zone{testCase.zone}}}
			dnsService := &refreshTestDNS{err: errors.New("primary unavailable"), expired: make(map[string]bool), updated: transferred}
			refresher := newZoneRefresher(configuration, dnsService, slog.New(slog.NewTextHandler(io.Discard, nil)))
			for _, offset := range testCase.failing {
				refresher.step(context.Background(), started.Add(offset))
			}
			if got := refresher.Status(); len(got) != 1 || got[0] != testCase.want {
				t.Fatalf("Status() while failing = %+v, want [%+v]", got, testCase.want)
			}

			dnsService.err = nil
			refresher.step(context.Background(), started.Add(testCase.working))
			refresher.step(context.Background(), started.Add(testCase.working+time.Second))
			if got := refresher.Status(); len(got) != 1 || got[0].Failures != 0 || got[0].LastError != "" || !got[0].FailingSince.IsZero() {
				t.Fatalf("Status() after a refresh worked = %+v, want one zone with no failures", got)
			}
		})
	}
}

func TestLateTransferCannotOverwriteConvertedPrimary(t *testing.T) {
	current := managedTestZone()
	if err := zonemodel.ConvertToPrimary(&current, time.Now()); err != nil {
		t.Fatal(err)
	}
	configuration := &refreshTestConfiguration{snapshot: zonemodel.Snapshot{Zones: []zonemodel.Zone{current}}}
	dnsService := &refreshTestDNS{expired: map[string]bool{current.Name: true}}
	refresher := newZoneRefresher(configuration, dnsService, slog.New(slog.NewTextHandler(io.Discard, nil)))
	refresher.states[current.Name] = zoneRefreshState{serial: 1}
	if err := refresher.storeRecords(context.Background(), current.Name, nil); err == nil {
		t.Fatal("late transfer replaced primary records")
	}
	refresher.step(context.Background(), time.Now())
	if len(configuration.snapshot.Zones[0].Records) == 0 || configuration.updates != 0 {
		t.Fatal("primary records changed")
	}
	if len(refresher.states) != 0 || dnsService.expired[current.Name] || dnsService.calls != 0 {
		t.Fatal("primary still tracked for refresh or expiry")
	}
}

func TestSecondaryForwarderRefreshNotifyExpiryAndPromotion(t *testing.T) {
	current := managedTestZone()
	current.Type = zonemodel.TypeSecondaryForwarder
	current.Records = []zonemodel.Record{
		{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.secondary.test. hostmaster.secondary.test. 1 10 3 20 300"},
		{Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 this-server"},
		{Name: "old", Type: "A", TTL: 300, Value: "192.0.2.1"},
	}
	configuration := &refreshTestConfiguration{snapshot: zonemodel.Snapshot{Zones: []zonemodel.Zone{current}}}
	service := &refreshTestDNS{changed: true, expired: make(map[string]bool), updated: []dnsserver.ZoneRecord{
		{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.secondary.test. hostmaster.secondary.test. 2 10 3 20 300"},
		{Name: "@", Type: "TYPE65281", TTL: 300, Value: `\# 16 000b746869732d736572766572000000`},
		{Name: "new", Type: "TXT", TTL: 300, Value: `"refreshed override"`},
	}}
	refresher := newZoneRefresher(configuration, service, slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	refresher.step(context.Background(), now)
	refresher.handleNotification(context.Background(), dnsserver.ZoneNotification{Zone: current.Name, ReceivedAt: now.Add(time.Second)})
	stored := configuration.snapshot.Zones[0]
	if service.calls != 1 || stored.Type != zonemodel.TypeSecondaryForwarder || !stored.DNSSECValidationDisabled || len(stored.Records) != 3 || stored.Records[1].Value != "udp 0 this-server" || stored.Records[2].Name != "new" || stored.PrimaryServers[0] != current.PrimaryServers[0] {
		t.Fatalf("refresh lost settings or replacements: %+v", stored)
	}
	service.updated[1].Value = `\# 16 030b746869732d736572766572000000`
	refresher.step(context.Background(), now.Add(11*time.Second))
	if configuration.updates != 1 || configuration.snapshot.Zones[0].Records[1].Value != "udp 0 this-server" {
		t.Fatal("invalid refresh replaced the last good snapshot")
	}
	if !refresher.states[current.Name].nextAttempt.Equal(now.Add(14 * time.Second)) {
		t.Fatal("retry timer not scheduled")
	}
	service.err = errors.New("source offline")
	refresher.step(context.Background(), now.Add(22*time.Second))
	if !service.expired[current.Name] {
		t.Fatal("unreachable secondary forwarder did not expire")
	}
	if err := zonemodel.ConvertToPrimary(&configuration.snapshot.Zones[0], now.Add(23*time.Second)); err != nil {
		t.Fatal(err)
	}
	calls := service.calls
	refresher.step(context.Background(), now.Add(24*time.Second))
	if service.calls != calls || service.expired[current.Name] || len(refresher.states) != 0 || configuration.snapshot.Zones[0].Type != "forwarder" {
		t.Fatal("promoted forwarder continued synchronizing or remained expired")
	}
}
