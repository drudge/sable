package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/unifi"
	"github.com/drudge/sable/internal/zone"
)

var syncTestTime = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

type stubConfiguration struct {
	settings config.UniFi
}

func (stub *stubConfiguration) Current() config.Snapshot {
	return config.Snapshot{Config: config.Config{UniFi: stub.settings}}
}

type stubZoneEditor struct {
	mu      sync.Mutex
	zones   []zone.Zone
	updates int
	err     error
}

func (stub *stubZoneEditor) Current() zone.Snapshot {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return zone.Snapshot{Zones: zone.Clone(stub.zones)}
}

func (stub *stubZoneEditor) UpdateZones(_ context.Context, mutate func(*[]zone.Zone) error) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.err != nil {
		return stub.err
	}
	candidate := zone.Clone(stub.zones)
	if err := mutate(&candidate); err != nil {
		return err
	}
	zone.NormalizeAll(candidate)
	stub.updates++
	stub.zones = candidate
	return nil
}

func (stub *stubZoneEditor) zone(t *testing.T, name string) zone.Zone {
	t.Helper()
	stub.mu.Lock()
	defer stub.mu.Unlock()
	index := slices.IndexFunc(stub.zones, func(candidate zone.Zone) bool { return candidate.Name == name })
	if index < 0 {
		t.Fatalf("zone %q was not created; have %v", name, zoneNames(stub.zones))
	}
	return stub.zones[index]
}

func zoneNames(zones []zone.Zone) []string {
	names := make([]string, 0, len(zones))
	for _, current := range zones {
		names = append(names, current.Name)
	}
	return names
}

type stubCredentials struct {
	credentials unifi.Credentials
	found       bool
}

func (stub *stubCredentials) Get(context.Context) (unifi.Credentials, bool) {
	return stub.credentials, stub.found
}

func (stub *stubCredentials) Replace(_ context.Context, credentials unifi.Credentials) error {
	stub.credentials, stub.found = credentials, true
	return nil
}

func (stub *stubCredentials) Clear(context.Context) error {
	stub.credentials, stub.found = unifi.Credentials{}, false
	return nil
}

type stubReader struct {
	inventory unifi.Inventory
	err       error
	calls     int
}

func (stub *stubReader) Inventory(context.Context) (unifi.Inventory, error) {
	stub.calls++
	if stub.err != nil {
		return unifi.Inventory{}, stub.err
	}
	return stub.inventory, nil
}

func testInventory() unifi.Inventory {
	return unifi.Inventory{
		Networks: []unifi.Network{
			{ID: "net-lan", Name: "Default", Slug: "default", Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}},
			{ID: "net-iot", Name: "IoT", Slug: "iot", Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.30.0/24")}},
		},
		Hosts: []unifi.Host{
			{MAC: "aa:01", Hostname: "Printer", Address: netip.MustParseAddr("192.168.1.10"), NetworkID: "net-lan", Reserved: true},
			{MAC: "aa:02", Hostname: "Laptop", Address: netip.MustParseAddr("192.168.30.50"), NetworkID: "net-iot"},
		},
	}
}

func testSettings(networks ...config.UniFiNetwork) config.UniFi {
	return config.UniFi{
		Enabled:       true,
		ControllerURL: "https://unifi.example",
		Site:          "default",
		Interval:      config.Duration{Duration: 2 * time.Minute},
		Sources:       []string{"active", "reservations"},
		Networks:      networks,
	}
}

func mapping(id, name, zoneName string) config.UniFiNetwork {
	return config.UniFiNetwork{
		ID: id, Name: name, Zone: zoneName,
		HostnameTemplate: unifi.DefaultHostnameTemplate,
		TTL:              300, Reverse: true, Enabled: true,
	}
}

func newTestSyncer(t *testing.T, settings config.UniFi, editor *stubZoneEditor, reader *stubReader) *unifiSyncer {
	t.Helper()
	syncer := newUniFiSyncer(
		&stubConfiguration{settings: settings},
		editor,
		&stubCredentials{credentials: unifi.Credentials{APIKey: "key"}, found: true},
		func() bool { return true },
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	syncer.now = func() time.Time { return syncTestTime }
	syncer.newReader = func(unifi.Options) (unifiInventoryReader, error) { return reader, nil }
	return syncer
}

func recordValue(t *testing.T, target zone.Zone, name, recordType string) string {
	t.Helper()
	for _, record := range target.Records {
		if record.Name == name && record.Type == recordType {
			return record.Value
		}
	}
	t.Fatalf("zone %s has no %s record named %q; have %v", target.Name, recordType, name, target.Records)
	return ""
}

func TestUniFiSyncCreatesZonesAndRecords(t *testing.T) {
	editor := &stubZoneEditor{}
	settings := testSettings(
		mapping("net-lan", "Default", "clients.example.net"),
		mapping("net-iot", "IoT", "clients.example.net"),
	)
	syncer := newTestSyncer(t, settings, editor, &stubReader{inventory: testInventory()})

	syncer.runOnce(t.Context())

	if status := syncer.Status(); status.LastError != "" {
		t.Fatalf("sync reported %q", status.LastError)
	}
	forward := editor.zone(t, "clients.example.net")
	if got := recordValue(t, forward, "printer.default", "A"); got != "192.168.1.10" {
		t.Fatalf("printer A = %q, want the reserved address", got)
	}
	if got := recordValue(t, forward, "laptop.iot", "A"); got != "192.168.30.50" {
		t.Fatalf("laptop A = %q", got)
	}
	reverse := editor.zone(t, "1.168.192.in-addr.arpa")
	if got := recordValue(t, reverse, "10", "PTR"); got != "printer.default.clients.example.net." {
		t.Fatalf("printer PTR = %q", got)
	}
	if _, err := zone.NewPrimary("x.example", 300, "", "", syncTestTime); err != nil {
		t.Fatalf("NewPrimary: %v", err)
	}
	if err := zone.ValidateAll(editor.Current().Zones, nil); err != nil {
		t.Fatalf("synchronized zones failed validation: %v", err)
	}
}

func TestUniFiSyncIsIdempotent(t *testing.T) {
	editor := &stubZoneEditor{}
	reader := &stubReader{inventory: testInventory()}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, reader)

	syncer.runOnce(t.Context())
	first := editor.zone(t, "clients.example.net")
	updatesAfterFirst := editor.updates
	syncer.runOnce(t.Context())
	second := editor.zone(t, "clients.example.net")

	if got, want := recordValue(t, second, "@", "SOA"), recordValue(t, first, "@", "SOA"); got != want {
		t.Fatalf("a second sync with unchanged input advanced the SOA: %q became %q", want, got)
	}
	if editor.updates != updatesAfterFirst+1 {
		t.Fatalf("zone updates = %d, want exactly one more attempt than the first sync", editor.updates)
	}
	if !reflect.DeepEqual(first.Records, second.Records) {
		t.Fatalf("records changed on an unchanged sync:\n%+v\n%+v", first.Records, second.Records)
	}
	if status := syncer.Status(); status.Added != 0 || status.Updated != 0 || status.Removed != 0 {
		t.Fatalf("second sync reported changes: %+v", status)
	}
}

func TestUniFiSyncLeavesHandAuthoredRecordsAlone(t *testing.T) {
	editor := &stubZoneEditor{}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, &stubReader{inventory: testInventory()})
	syncer.runOnce(t.Context())

	manual := zone.Record{Name: "nas", Type: "A", Value: "192.168.1.250", TTL: 300}
	if err := editor.UpdateZones(t.Context(), func(zones *[]zone.Zone) error {
		index := slices.IndexFunc(*zones, func(candidate zone.Zone) bool { return candidate.Name == "clients.example.net" })
		(*zones)[index].Records = append((*zones)[index].Records, manual)
		return nil
	}); err != nil {
		t.Fatalf("add manual record: %v", err)
	}

	// The printer leaves the network entirely, so its synchronized record must
	// be removed while the hand-authored record stays.
	reader := &stubReader{inventory: unifi.Inventory{Networks: testInventory().Networks}}
	syncer.newReader = func(unifi.Options) (unifiInventoryReader, error) { return reader, nil }
	syncer.runOnce(t.Context())

	forward := editor.zone(t, "clients.example.net")
	if got := recordValue(t, forward, "nas", "A"); got != "192.168.1.250" {
		t.Fatalf("hand-authored record = %q, want it untouched", got)
	}
	for _, record := range forward.Records {
		if record.Source == zone.SourceUniFi {
			t.Fatalf("stale synchronized record survived: %+v", record)
		}
	}
}

func TestUniFiSyncUpdatesChangedAddress(t *testing.T) {
	editor := &stubZoneEditor{}
	inventory := testInventory()
	reader := &stubReader{inventory: inventory}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, reader)
	syncer.runOnce(t.Context())

	moved := testInventory()
	moved.Hosts[0].Address = netip.MustParseAddr("192.168.1.11")
	reader.inventory = moved
	syncer.runOnce(t.Context())

	forward := editor.zone(t, "clients.example.net")
	if got := recordValue(t, forward, "printer.default", "A"); got != "192.168.1.11" {
		t.Fatalf("printer A = %q, want the new address", got)
	}
	reverse := editor.zone(t, "1.168.192.in-addr.arpa")
	for _, record := range reverse.Records {
		if record.Type == "PTR" && record.Name == "10" {
			t.Fatal("the PTR for the old address was not removed")
		}
	}
	if status := syncer.Status(); status.Updated == 0 {
		t.Fatalf("status did not report an update: %+v", status)
	}
}

func TestUniFiSyncHonorsSourceSelection(t *testing.T) {
	editor := &stubZoneEditor{}
	settings := testSettings(mapping("net-lan", "Default", "clients.example.net"), mapping("net-iot", "IoT", "clients.example.net"))
	settings.Sources = []string{"reservations"}
	syncer := newTestSyncer(t, settings, editor, &stubReader{inventory: testInventory()})

	syncer.runOnce(t.Context())

	forward := editor.zone(t, "clients.example.net")
	for _, record := range forward.Records {
		if record.Name == "laptop.iot" {
			t.Fatal("an active client was published while only reservations were selected")
		}
	}
	if got := recordValue(t, forward, "printer.default", "A"); got != "192.168.1.10" {
		t.Fatalf("printer A = %q", got)
	}
}

func TestUniFiSyncSkipsReverseWhenDisabled(t *testing.T) {
	editor := &stubZoneEditor{}
	network := mapping("net-lan", "Default", "clients.example.net")
	network.Reverse = false
	syncer := newTestSyncer(t, testSettings(network), editor, &stubReader{inventory: testInventory()})

	syncer.runOnce(t.Context())

	if slices.Contains(zoneNames(editor.Current().Zones), "1.168.192.in-addr.arpa") {
		t.Fatal("a reverse zone was created while reverse mapping was off")
	}
}

func TestUniFiSyncSkipsReplicaNodes(t *testing.T) {
	editor := &stubZoneEditor{}
	reader := &stubReader{inventory: testInventory()}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, reader)
	syncer.writable = func() bool { return false }

	syncer.runOnce(t.Context())

	if reader.calls != 0 {
		t.Fatal("a replica contacted the controller")
	}
	if len(editor.Current().Zones) != 0 {
		t.Fatal("a replica wrote zones")
	}
}

func TestUniFiSyncRefusesNonPrimaryZone(t *testing.T) {
	editor := &stubZoneEditor{zones: []zone.Zone{{
		Name: "clients.example.net", Type: "secondary", DefaultTTL: 300,
		PrimaryServers: []string{"192.0.2.1:53"}, PrimaryProtocol: "tcp",
	}}}
	network := mapping("net-lan", "Default", "clients.example.net")
	network.Reverse = false
	syncer := newTestSyncer(t, testSettings(network), editor, &stubReader{inventory: testInventory()})

	syncer.runOnce(t.Context())

	target := editor.zone(t, "clients.example.net")
	if len(target.Records) != 0 {
		t.Fatalf("records were written into a secondary zone: %+v", target.Records)
	}
}

// The console shows a host count beside every mapped network, which means the
// synchronizer has to record the per-network totals it saw, not just the sum.
func TestUniFiSyncRecordsHostsPerNetwork(t *testing.T) {
	editor := &stubZoneEditor{}
	reader := &stubReader{inventory: testInventory()}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, reader)

	syncer.runOnce(t.Context())

	status := syncer.Status()
	// Every network the controller reported is counted, including ones nothing
	// is mapped to yet, so mapping one later shows a count straight away.
	if status.HostsByNetwork["net-lan"] != 1 || status.HostsByNetwork["net-iot"] != 1 {
		t.Fatalf("per-network host counts = %v", status.HostsByNetwork)
	}
	// The counts handed to the console are a copy, or a later sync would rewrite
	// a snapshot the console is still rendering.
	status.HostsByNetwork["net-lan"] = 99
	if syncer.Status().HostsByNetwork["net-lan"] != 1 {
		t.Fatal("the status handed out the synchronizer's own count map")
	}
}

// The console prints the summary total above a row per mapped network, so the
// total has to be the sum of those rows and not everything the controller
// happens to know about.
func TestUniFiSyncCountsOnlyMappedHosts(t *testing.T) {
	editor := &stubZoneEditor{}
	reader := &stubReader{inventory: testInventory()}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, reader)

	syncer.runOnce(t.Context())

	status := syncer.Status()
	if status.Hosts != status.HostsByNetwork["net-lan"] {
		t.Fatalf("summary total = %d, want the %d hosts on the one mapped network (per-network: %v)",
			status.Hosts, status.HostsByNetwork["net-lan"], status.HostsByNetwork)
	}
	if status.HostsByNetwork["net-iot"] == 0 {
		t.Fatal("the unmapped network lost its count, so mapping it later would show nothing")
	}
}

func TestUniFiSyncReportsControllerFailure(t *testing.T) {
	editor := &stubZoneEditor{}
	reader := &stubReader{err: errors.New("controller unreachable")}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, reader)

	syncer.runOnce(t.Context())

	status := syncer.Status()
	if !strings.Contains(status.LastError, "controller unreachable") {
		t.Fatalf("status error = %q", status.LastError)
	}
	if !status.LastSuccess.IsZero() {
		t.Fatal("a failed sync recorded a success")
	}
	if status.NextAttempt.IsZero() {
		t.Fatal("a failed sync did not schedule a retry")
	}
}

func TestUniFiSyncRequiresCredentials(t *testing.T) {
	editor := &stubZoneEditor{}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, &stubReader{inventory: testInventory()})
	syncer.credentials = &stubCredentials{}

	syncer.runOnce(t.Context())

	if status := syncer.Status(); !strings.Contains(status.LastError, "credentials are not configured") {
		t.Fatalf("status error = %q", status.LastError)
	}
}

// The wizard's review screen must describe exactly what enabling would do.
func TestUniFiPreviewMatchesApply(t *testing.T) {
	settings := testSettings(mapping("net-lan", "Default", "clients.example.net"))
	previewEditor := &stubZoneEditor{}
	previewSyncer := newTestSyncer(t, settings, previewEditor, &stubReader{inventory: testInventory()})

	plan, err := previewSyncer.Preview(t.Context(), settings)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if previewEditor.updates != 0 {
		t.Fatal("Preview wrote zones")
	}
	if plan.Empty() {
		t.Fatal("Preview reported no changes for an unconfigured server")
	}

	applyEditor := &stubZoneEditor{}
	applySyncer := newTestSyncer(t, settings, applyEditor, &stubReader{inventory: testInventory()})
	applySyncer.runOnce(t.Context())

	status := applySyncer.Status()
	if status.Added != len(plan.Added) || status.Removed != len(plan.Removed) || status.ZonesCreated != len(plan.CreatedZones) {
		t.Fatalf("apply (%d added, %d removed, %d zones) did not match preview (%d, %d, %d)",
			status.Added, status.Removed, status.ZonesCreated, len(plan.Added), len(plan.Removed), len(plan.CreatedZones))
	}
}

func TestUniFiSyncReportsSkippedEntries(t *testing.T) {
	editor := &stubZoneEditor{}
	inventory := testInventory()
	inventory.Hosts = append(inventory.Hosts, unifi.Host{
		MAC: "aa:03", Hostname: "***", Address: netip.MustParseAddr("192.168.1.77"), NetworkID: "net-lan",
	})
	settings := testSettings(mapping("net-lan", "Default", "clients.example.net"), mapping("net-gone", "Removed", "old.example.net"))
	syncer := newTestSyncer(t, settings, editor, &stubReader{inventory: inventory})

	plan, err := syncer.Preview(t.Context(), settings)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	joined := strings.Join(plan.Skipped, "\n")
	if !strings.Contains(joined, "no usable DNS characters") {
		t.Fatalf("skipped entries did not mention the unusable hostname: %v", plan.Skipped)
	}
	if !strings.Contains(joined, "no longer reports it") {
		t.Fatalf("skipped entries did not mention the missing network: %v", plan.Skipped)
	}
}

// Two devices with the same sanitized name on one network must not produce a
// round-robin the operator never asked for.
func TestUniFiSyncCollapsesDuplicateNames(t *testing.T) {
	editor := &stubZoneEditor{}
	inventory := testInventory()
	inventory.Hosts = []unifi.Host{
		{MAC: "aa:01", Hostname: "Printer", Address: netip.MustParseAddr("192.168.1.10"), NetworkID: "net-lan"},
		{MAC: "aa:02", Hostname: "printer!", Address: netip.MustParseAddr("192.168.1.11"), NetworkID: "net-lan"},
	}
	syncer := newTestSyncer(t, testSettings(mapping("net-lan", "Default", "clients.example.net")), editor, &stubReader{inventory: inventory})

	syncer.runOnce(t.Context())

	forward := editor.zone(t, "clients.example.net")
	matches := 0
	for _, record := range forward.Records {
		if record.Name == "printer.default" && record.Type == "A" {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("found %d A records for the colliding name, want exactly 1", matches)
	}
}

// Clients hold rotating SLAAC addresses on prefixes the controller never
// declares, so the reverse mapping derives each /64 zone from the addresses in
// use and publishes one PTR per address without inventing forward records.
func TestUniFiSyncPublishesIPv6Reverse(t *testing.T) {
	editor := &stubZoneEditor{}
	inventory := testInventory()
	inventory.Hosts[1].IPv6 = []netip.Addr{
		netip.MustParseAddr("2001:db8:0:1:aaaa::5"),
		netip.MustParseAddr("2001:db8:0:1:bbbb::6"),
	}
	syncer := newTestSyncer(t, testSettings(mapping("net-iot", "IoT", "clients.example.net")), editor, &stubReader{inventory: inventory})

	syncer.runOnce(t.Context())

	if status := syncer.Status(); status.LastError != "" {
		t.Fatalf("sync reported %q", status.LastError)
	}
	reverse := editor.zone(t, "1.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
	for _, owner := range []string{"5.0.0.0.0.0.0.0.0.0.0.0.a.a.a.a", "6.0.0.0.0.0.0.0.0.0.0.0.b.b.b.b"} {
		if got := recordValue(t, reverse, owner, "PTR"); got != "laptop.iot.clients.example.net." {
			t.Fatalf("PTR %s = %q, want the laptop's forward name", owner, got)
		}
	}
	v4 := editor.zone(t, "30.168.192.in-addr.arpa")
	if got := recordValue(t, v4, "50", "PTR"); got != "laptop.iot.clients.example.net." {
		t.Fatalf("IPv4 PTR = %q", got)
	}
	forward := editor.zone(t, "clients.example.net")
	for _, record := range forward.Records {
		if record.Type == "AAAA" {
			t.Fatalf("observed IPv6 addresses must stay out of the forward zone: %+v", record)
		}
	}
	if err := zone.ValidateAll(editor.Current().Zones, nil); err != nil {
		t.Fatalf("synchronized zones failed validation: %v", err)
	}
}

// A delegated prefix that rotates away must not strand its PTR records: the
// next sync retires them and publishes the replacement prefix's zone.
func TestUniFiSyncRetiresReverseRecordsForVanishedPrefixes(t *testing.T) {
	editor := &stubZoneEditor{}
	inventory := testInventory()
	inventory.Hosts[1].IPv6 = []netip.Addr{netip.MustParseAddr("2001:db8:0:1:aaaa::5")}
	reader := &stubReader{inventory: inventory}
	syncer := newTestSyncer(t, testSettings(mapping("net-iot", "IoT", "clients.example.net")), editor, reader)
	syncer.runOnce(t.Context())

	rotated := testInventory()
	rotated.Hosts[1].IPv6 = []netip.Addr{netip.MustParseAddr("2001:db8:0:2:aaaa::5")}
	reader.inventory = rotated
	syncer.runOnce(t.Context())

	stale := editor.zone(t, "1.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
	for _, record := range stale.Records {
		if record.Source == zone.SourceUniFi {
			t.Fatalf("stale PTR survived the prefix rotation: %+v", record)
		}
	}
	replacement := editor.zone(t, "2.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
	if got := recordValue(t, replacement, "5.0.0.0.0.0.0.0.0.0.0.0.a.a.a.a", "PTR"); got != "laptop.iot.clients.example.net." {
		t.Fatalf("replacement PTR = %q", got)
	}
	if status := syncer.Status(); status.Removed == 0 {
		t.Fatalf("status did not report the retired records: %+v", status)
	}
}

// Reviewing an already-synchronized setup must still show what the mapping
// produces, or the wizard's review step looks empty.
func TestUniFiPreviewReportsPublishedRecordsWhenNothingChanges(t *testing.T) {
	editor := &stubZoneEditor{}
	settings := testSettings(mapping("net-lan", "Default", "clients.example.net"))
	syncer := newTestSyncer(t, settings, editor, &stubReader{inventory: testInventory()})
	syncer.runOnce(t.Context())

	plan, err := syncer.Preview(t.Context(), settings)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !plan.Empty() {
		t.Fatalf("a second preview reported changes: %+v", plan)
	}
	if len(plan.Publishing) == 0 {
		t.Fatal("preview reported nothing published for a synchronized mapping")
	}
	var names []string
	for _, record := range plan.Publishing {
		names = append(names, record.Name+" "+record.Type)
	}
	if !slices.Contains(names, "printer.default A") {
		t.Fatalf("published set = %v, want the printer A record", names)
	}
}
