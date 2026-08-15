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
