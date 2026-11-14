package app

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/zone"
)

var namesTestTime = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

// namesTestDHCP is one scope on lan.example.com with a named reservation for
// printer at .10 and PTR records on.
func namesTestDHCP() config.DHCP {
	return config.DHCP{Enabled: true, Scopes: []config.DHCPScope{{
		ID: "lan", Name: "LAN", Subnet: "10.9.0.0/24", Domain: "lan.example.com",
		Ranges:       []config.DHCPRange{{Start: "10.9.0.100", End: "10.9.0.199"}},
		Reservations: []config.DHCPReservation{{MAC: "02:00:00:00:00:10", Address: "10.9.0.10", Name: "Printer"}},
	}}}
}

func namesTestLease(address, mac, hostname string, bound time.Time) store.DHCPLease {
	return store.DHCPLease{
		NodeID: "n1", Address: netip.MustParseAddr(address), ScopeID: "lan", ClientKey: "01" + mac, MAC: mac,
		Hostname: hostname, State: store.DHCPLeaseActive, BoundAt: bound, ExpiresAt: namesTestTime.Add(time.Hour),
	}
}

type namesHarness struct {
	editor *stubZoneEditor
	config *stubConfiguration
	namer  *dhcpNamer
	mutex  sync.Mutex
	leases []store.DHCPLease
}

func newNamesHarness(t *testing.T, zones ...zone.Zone) *namesHarness {
	t.Helper()
	harness := &namesHarness{editor: &stubZoneEditor{zones: zones}, config: &stubConfiguration{dhcp: namesTestDHCP()}}
	harness.namer = newDHCPNamer(harness.config, harness.editor, harness.read, func() bool { return true },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	harness.namer.now = func() time.Time { return namesTestTime }
	return harness
}

func (harness *namesHarness) read(context.Context) ([]store.DHCPLease, error) {
	harness.mutex.Lock()
	defer harness.mutex.Unlock()
	return slices.Clone(harness.leases), nil
}

func (harness *namesHarness) set(leases ...store.DHCPLease) {
	harness.mutex.Lock()
	defer harness.mutex.Unlock()
	harness.leases = leases
}

// records lists a zone's records as owner type value source, or nil when
// the zone doesn't exist.
func (harness *namesHarness) records(name string) []string {
	var listed []string
	for _, candidate := range harness.editor.Current().Zones {
		if candidate.Name != name {
			continue
		}
		for _, record := range candidate.Records {
			if record.Type == "SOA" || record.Type == "NS" {
				continue
			}
			listed = append(listed, record.Name+" "+record.Type+" "+record.Value+" "+record.Source)
		}
	}
	slices.Sort(listed)
	return listed
}

func (harness *namesHarness) serial(t *testing.T, name string) uint32 {
	t.Helper()
	for _, candidate := range harness.editor.Current().Zones {
		if serial, ok := zone.Serial(candidate); ok && candidate.Name == name {
			return serial
		}
	}
	t.Fatalf("no zone %s", name)
	return 0
}

func primaryWith(t *testing.T, name string, records ...zone.Record) zone.Zone {
	t.Helper()
	created, err := zone.NewPrimary(name, 300, "", "", namesTestTime.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	created.Records = append(created.Records, records...)
	zones := []zone.Zone{created}
	zone.NormalizeAll(zones)
	return zones[0]
}

func assertRecords(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("records\n got %q\nwant %q", got, want)
	}
}

func TestDHCPNamesPublishReservationAndLease(t *testing.T) {
	harness := newNamesHarness(t)
	harness.set(namesTestLease("10.9.0.100", "02:00:00:00:00:01", "Nick's Laptop", namesTestTime))
	harness.namer.reconcile(context.Background())
	assertRecords(t, harness.records("lan.example.com"),
		"nicks-laptop A 10.9.0.100 dhcp", "printer A 10.9.0.10 dhcp")
	assertRecords(t, harness.records("0.9.10.in-addr.arpa"),
		"10 PTR printer.lan.example.com. dhcp", "100 PTR nicks-laptop.lan.example.com. dhcp")
}

func TestDHCPNamesWithoutReverse(t *testing.T) {
	harness := newNamesHarness(t)
	off := false
	harness.config.dhcp.Scopes[0].Reverse = &off
	harness.namer.reconcile(context.Background())
	assertRecords(t, harness.records("lan.example.com"), "printer A 10.9.0.10 dhcp")
	if records := harness.records("0.9.10.in-addr.arpa"); records != nil {
		t.Fatalf("reverse zone written with reverse = false: %q", records)
	}
}

// One test per collision pair, in the order hand-authored record,
// reservation, UniFi record, lease.
func TestDHCPNamesCollisionOrder(t *testing.T) {
	handAuthored := func(owner string) zone.Record {
		return zone.Record{Name: owner, Type: "A", Value: "10.9.0.2", TTL: 300}
	}
	fromUniFi := func(owner string) zone.Record {
		return zone.Record{Name: owner, Type: "A", Value: "10.9.0.3", TTL: 300, Source: zone.SourceUniFi}
	}
	for _, test := range []struct {
		name   string
		zone   []zone.Record
		leases []store.DHCPLease
		want   []string
	}{
		{"hand-authored beats reservation", []zone.Record{handAuthored("printer")}, nil,
			[]string{"printer A 10.9.0.2 "}},
		{"hand-authored beats lease", []zone.Record{handAuthored("laptop")},
			[]store.DHCPLease{namesTestLease("10.9.0.100", "02:00:00:00:00:01", "laptop", namesTestTime)},
			[]string{"laptop A 10.9.0.2 ", "printer A 10.9.0.10 dhcp"}},
		{"reservation beats UniFi", []zone.Record{fromUniFi("printer")}, nil,
			[]string{"printer A 10.9.0.10 dhcp", "printer A 10.9.0.3 unifi"}},
		{"UniFi beats lease", []zone.Record{fromUniFi("laptop")},
			[]store.DHCPLease{namesTestLease("10.9.0.100", "02:00:00:00:00:01", "laptop", namesTestTime)},
			[]string{"laptop A 10.9.0.3 unifi", "printer A 10.9.0.10 dhcp"}},
		{"reservation beats lease", nil,
			[]store.DHCPLease{namesTestLease("10.9.0.100", "02:00:00:00:00:01", "printer", namesTestTime)},
			[]string{"printer A 10.9.0.10 dhcp"}},
		{"newest binding beats older lease", nil, []store.DHCPLease{
			namesTestLease("10.9.0.100", "02:00:00:00:00:01", "phone", namesTestTime.Add(-time.Hour)),
			namesTestLease("10.9.0.101", "02:00:00:00:00:02", "phone", namesTestTime.Add(-time.Minute)),
		}, []string{"phone A 10.9.0.101 dhcp", "printer A 10.9.0.10 dhcp"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newNamesHarness(t, primaryWith(t, "lan.example.com", test.zone...))
			harness.set(test.leases...)
			harness.namer.reconcile(context.Background())
			assertRecords(t, harness.records("lan.example.com"), test.want...)
		})
	}
}

// A renewal moves the expiry, not the binding, so the device that bound
// last keeps the name, and the loser is told who holds it.
func TestDHCPNamesNewestBindingNotNewestRenewal(t *testing.T) {
	older := namesTestLease("10.9.0.100", "02:00:00:00:00:01", "phone", namesTestTime.Add(-2*time.Hour))
	older.ExpiresAt = namesTestTime.Add(3 * time.Hour)
	newer := namesTestLease("10.9.0.101", "02:00:00:00:00:02", "phone", namesTestTime.Add(-time.Hour))
	plan := desiredDHCPRecords(namesTestDHCP(), []store.DHCPLease{older, newer}, namesTestTime)
	if got := plan.inUseBy[older.Address]; got != newer.Address {
		t.Fatalf("name in use by %v, want %v", got, newer.Address)
	}
	if _, lost := plan.inUseBy[newer.Address]; lost {
		t.Fatal("the newest binding lost its name")
	}
}

// Release, expiry, and decline each remove the lease's A and PTR records on
// the next reconcile.
func TestDHCPNamesRemoval(t *testing.T) {
	for _, test := range []struct {
		name string
		end  func(*store.DHCPLease)
	}{
		{"release", func(lease *store.DHCPLease) { lease.State = store.DHCPLeaseReleased }},
		{"expiry", func(lease *store.DHCPLease) { lease.ExpiresAt = namesTestTime }},
		{"decline", func(lease *store.DHCPLease) { lease.State = store.DHCPLeaseDeclined }},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newNamesHarness(t)
			lease := namesTestLease("10.9.0.100", "02:00:00:00:00:01", "laptop", namesTestTime)
			harness.set(lease)
			harness.namer.reconcile(context.Background())
			serial := harness.serial(t, "lan.example.com")
			test.end(&lease)
			harness.set(lease)
			harness.namer.reconcile(context.Background())
			assertRecords(t, harness.records("lan.example.com"), "printer A 10.9.0.10 dhcp")
			assertRecords(t, harness.records("0.9.10.in-addr.arpa"), "10 PTR printer.lan.example.com. dhcp")
			if harness.serial(t, "lan.example.com") == serial {
				t.Fatal("serial didn't advance on removal")
			}
		})
	}
}

// 1,000 renewals leave the wanted set as it was, so no zone is written and
// no serial advances.
func TestDHCPNamesRenewalsPublishNoRevision(t *testing.T) {
	harness := newNamesHarness(t)
	lease := namesTestLease("10.9.0.100", "02:00:00:00:00:01", "laptop", namesTestTime)
	harness.set(lease)
	harness.namer.reconcile(context.Background())
	forward, reverse := harness.serial(t, "lan.example.com"), harness.serial(t, "0.9.10.in-addr.arpa")
	before := harness.editor.Current().Zones
	for renewal := range 1000 {
		lease.ExpiresAt = namesTestTime.Add(time.Hour + time.Duration(renewal)*time.Second)
		harness.set(lease)
		harness.namer.reconcile(context.Background())
	}
	if harness.serial(t, "lan.example.com") != forward || harness.serial(t, "0.9.10.in-addr.arpa") != reverse {
		t.Fatal("a renewal advanced a serial")
	}
	if after := harness.editor.Current().Zones; !slices.EqualFunc(before, after, zonesEqual) {
		t.Fatal("a renewal changed a zone")
	}
}

func zonesEqual(left, right zone.Zone) bool {
	return left.Name == right.Name && slices.Equal(left.Records, right.Records)
}

// Turning DHCP off removes every DHCP record and leaves the operator's.
func TestDHCPNamesOffRemovesEveryRecord(t *testing.T) {
	own := zone.Record{Name: "nas", Type: "A", Value: "10.9.0.5", TTL: 300}
	harness := newNamesHarness(t, primaryWith(t, "lan.example.com", own))
	harness.set(namesTestLease("10.9.0.100", "02:00:00:00:00:01", "laptop", namesTestTime))
	harness.namer.reconcile(context.Background())
	harness.config.dhcp.Enabled = false
	harness.namer.reconcile(context.Background())
	assertRecords(t, harness.records("lan.example.com"), "nas A 10.9.0.5 ")
	assertRecords(t, harness.records("0.9.10.in-addr.arpa"))
}

// A UniFi sync leaves a name a DHCP reservation publishes to it.
func TestUniFiSyncLeavesDHCPReservations(t *testing.T) {
	desired := map[string]*desiredZone{"lan.example.com": {name: "lan.example.com", records: []zone.Record{
		{Name: "printer", Type: "A", Value: "10.9.0.3", Source: zone.SourceUniFi},
		{Name: "tv", Type: "A", Value: "10.9.0.4", Source: zone.SourceUniFi},
	}}}
	skipped := leaveDHCPReservations(desired, dhcpReservedNames(namesTestDHCP()))
	if len(desired["lan.example.com"].records) != 1 || desired["lan.example.com"].records[0].Name != "tv" {
		t.Fatalf("records left %v", desired["lan.example.com"].records)
	}
	if !slices.Equal(skipped, []string{"printer.lan.example.com is a DHCP reservation"}) {
		t.Fatalf("skipped %q", skipped)
	}
}

// A lease saved or new settings applied wake the reconciler, which commits
// once after the burst settles.
func TestDHCPNamerFollowsChanges(t *testing.T) {
	harness := newNamesHarness(t)
	harness.namer.now = time.Now
	harness.namer.settle, harness.namer.spacing = 10*time.Millisecond, 10*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); harness.namer.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { return len(harness.records("lan.example.com")) == 1 })
	lease := namesTestLease("10.9.0.100", "02:00:00:00:00:01", "laptop", time.Now())
	lease.ExpiresAt = time.Now().Add(time.Hour)
	harness.set(lease)
	harness.namer.Changed()
	waitFor(t, func() bool { return len(harness.records("lan.example.com")) == 2 })
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
