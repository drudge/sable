package devices

import (
	"slices"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/querylog"
)

var testNow = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

func TestBuildMergesAddressesOfOneDeviceAndChoosesTheBestName(t *testing.T) {
	t.Parallel()
	day := 24 * time.Hour
	devices := Build(Input{
		Activity: querylog.ClientActivityReport{Clients: []querylog.ClientActivity{
			{Client: "10.0.0.5", Queries: 100, Blocked: 4, FirstSeen: testNow.Add(-9 * day), LastSeen: testNow},
			{Client: "fd00::5", Queries: 40, Blocked: 1, FirstSeen: testNow.Add(-3 * day), LastSeen: testNow.Add(-time.Hour)},
			{Client: "10.0.0.77", Queries: 30},
			{Client: "10.20.40.9", Queries: 20},
			{Client: "10.0.0.8", Queries: 10},
			{Client: "10.0.0.99", Queries: 5},
		}},
		Identities: []querylog.ClientIdentity{
			{Address: "10.0.0.5", MAC: "3c:22:fb:01:02:03", Source: "neighbor", LastSeen: testNow},
			{Address: "10.0.0.5", MAC: "3c:22:fb:01:02:03", Source: "unifi", Hostname: "george-laptop", LastSeen: testNow},
			{Address: "fd00::5", MAC: "3c:22:fb:01:02:03", Source: "neighbor", LastSeen: testNow},
			{Address: "10.0.0.77", MAC: "da:a1:19:00:00:01", Source: "neighbor", LastSeen: testNow},
			// An old owner of the same address loses to the newest sighting.
			{Address: "10.0.0.77", MAC: "aa:aa:aa:00:00:01", Source: "neighbor", LastSeen: testNow.Add(-2 * day)},
		},
		Clients: []config.Client{
			{Name: "Kids iPad", MAC: "da:a1:19:00:00:01"},
			{Name: "Guest Wi-Fi", Address: "10.20.40.0/24"},
		},
		Names: map[string]DiscoveredName{
			"10.0.0.8":  {Name: "printer.lan", Source: SourceReverse},
			"10.0.0.77": {Name: "ignored.lan", Source: SourceReverse},
		},
	})
	if len(devices) != 5 {
		t.Fatalf("devices = %+v", devices)
	}
	laptop := devices[0]
	if laptop.Key != "mac:3c:22:fb:01:02:03" || laptop.Name != "george-laptop" || laptop.NameSource != SourceUniFi {
		t.Fatalf("laptop = %+v", laptop)
	}
	if laptop.Queries != 140 || laptop.Blocked != 5 || len(laptop.Addresses) != 2 || laptop.Addresses[0].Address != "10.0.0.5" {
		t.Fatalf("laptop traffic = %+v", laptop)
	}
	if !laptop.FirstSeen.Equal(testNow.Add(-9*day)) || !laptop.Identified() || laptop.PrivateMAC {
		t.Fatalf("laptop identity = %+v", laptop)
	}
	byKey := map[string]Device{}
	for _, device := range devices {
		byKey[device.Key] = device
	}
	if ipad := byKey["mac:da:a1:19:00:00:01"]; ipad.Name != "Kids iPad" || ipad.NameSource != SourceOperator || !ipad.PrivateMAC || !ipad.Named {
		t.Fatalf("iPad = %+v", ipad)
	}
	if guest := byKey["ip:10.20.40.9"]; guest.Name != "Guest Wi-Fi" || !guest.Identified() {
		t.Fatalf("guest = %+v", guest)
	}
	if printer := byKey["ip:10.0.0.8"]; printer.Name != "printer.lan" || printer.NameSource != SourceReverse || printer.Identified() {
		t.Fatalf("printer = %+v", printer)
	}
	if unknown := byKey["ip:10.0.0.99"]; unknown.Name != "" || Label(unknown) != "10.0.0.99" {
		t.Fatalf("unknown = %+v", unknown)
	}
}

func TestChangesReportNewDevicesHonestly(t *testing.T) {
	t.Parallel()
	windowStart := testNow.Add(-30 * 24 * time.Hour)
	findings := Changes(ChangesInput{
		Now: testNow, WindowStart: windowStart, SeenSince: testNow.Add(-60 * 24 * time.Hour),
		Devices: []Device{
			{Key: "mac:da:a1:19:00:00:01", MAC: "da:a1:19:00:00:01", Name: "Kids iPad", Queries: 1_240, FirstSeen: testNow.Add(-2 * 24 * time.Hour), Addresses: []Address{{Address: "10.0.0.77"}}},
			{Key: "ip:10.0.0.99", Queries: 12, FirstSeen: testNow.Add(-3 * time.Hour), Addresses: []Address{{Address: "10.0.0.99"}}},
			{Key: "ip:10.0.0.5", Queries: 900, FirstSeen: testNow.Add(-45 * 24 * time.Hour)},
		},
	})
	if len(findings) != 2 {
		t.Fatalf("findings = %+v", findings)
	}
	address, device := findings[0], findings[1]
	if address.Title != "New address on the network" || address.Subject.Label != "10.0.0.99" || !slices.Contains(address.Explanations, "A known device came back at a new address") {
		t.Fatalf("address finding = %+v", address)
	}
	if device.Title != "New device on the network" || device.Summary != "First seen 2 days ago and has sent 1,240 queries since." || device.Subject.Device != "mac:da:a1:19:00:00:01" {
		t.Fatalf("device finding = %+v", device)
	}

	// Right after tracking starts, everything looks new; nothing is claimed.
	fresh := Changes(ChangesInput{Now: testNow, WindowStart: windowStart, SeenSince: testNow.Add(-2 * time.Hour),
		Devices: []Device{{Key: "ip:10.0.0.99", Queries: 12, FirstSeen: testNow.Add(-2 * time.Hour)}}})
	if len(fresh) != 0 {
		t.Fatalf("findings right after tracking began = %+v", fresh)
	}
}

func TestChangesReportNewDestinationsWithTheirNames(t *testing.T) {
	t.Parallel()
	windowStart := testNow.Add(-7 * 24 * time.Hour)
	device := Device{Key: "mac:3c:22:fb:01:02:03", MAC: "3c:22:fb:01:02:03", Name: "george-laptop", Queries: 5_000, NewDomains: 48, FirstSeen: testNow.Add(-40 * 24 * time.Hour)}
	quietChange := Device{Key: "ip:10.0.0.8", Queries: 900, NewDomains: 3, FirstSeen: testNow.Add(-40 * 24 * time.Hour)}
	findings := Changes(ChangesInput{
		Now: testNow, WindowStart: windowStart, SeenSince: testNow.Add(-60 * 24 * time.Hour),
		Devices: []Device{device, quietChange},
		NewDomains: func(Device) []insights.DomainEvidence {
			return []insights.DomainEvidence{{Name: "telemetry.vendor.example", FirstSeen: testNow.Add(-time.Hour)}}
		},
	})
	if len(findings) != 1 || findings[0].Kind != KindNewDestinations || findings[0].Summary != "Queried 48 domains for the first time during the selected period." {
		t.Fatalf("findings = %+v", findings)
	}
	if len(findings[0].Domains) != 1 || findings[0].Domains[0].Name != "telemetry.vendor.example" {
		t.Fatalf("domains = %+v", findings[0].Domains)
	}
}

func TestChangesCompareDevicesWithTheirOwnWeek(t *testing.T) {
	t.Parallel()
	old := testNow.Add(-30 * 24 * time.Hour)
	findings := Changes(ChangesInput{
		Now: testNow, WindowStart: testNow.Add(-24 * time.Hour), SeenSince: testNow.Add(-60 * 24 * time.Hour),
		Devices: []Device{
			{Key: "mac:aa:00:00:00:00:01", MAC: "aa:00:00:00:00:01", Name: "tv", FirstSeen: old, Recent: 12_480, Baseline: 7 * 2_970},
			{Key: "mac:aa:00:00:00:00:02", MAC: "aa:00:00:00:00:02", Name: "camera", FirstSeen: old, Recent: 0, Baseline: 7 * 1_240},
			// Doubling is normal variation, not a spike.
			{Key: "mac:aa:00:00:00:00:03", MAC: "aa:00:00:00:00:03", Name: "laptop", FirstSeen: old, Recent: 2_000, Baseline: 7 * 1_000},
			// Too new for its week to be a baseline.
			{Key: "mac:aa:00:00:00:00:04", MAC: "aa:00:00:00:00:04", Name: "new", FirstSeen: testNow.Add(-3 * 24 * time.Hour), Recent: 0, Baseline: 7 * 1_000},
			// Too quiet for a ratio to mean anything.
			{Key: "mac:aa:00:00:00:00:05", MAC: "aa:00:00:00:00:05", Name: "sensor", FirstSeen: old, Recent: 0, Baseline: 70},
		},
	})
	if len(findings) != 2 {
		t.Fatalf("findings = %+v", findings)
	}
	if findings[0].Kind != KindWentQuiet || findings[0].Subject.Label != "camera" || findings[0].Summary != "No queries in the last 24 hours. It averaged 1,240 a day over the week before." {
		t.Fatalf("quiet finding = %+v", findings[0])
	}
	if findings[1].Kind != KindTrafficSpike || findings[1].Summary != "Sent 12,480 queries in the last 24 hours, 4.2× its daily average over the week before." {
		t.Fatalf("spike finding = %+v", findings[1])
	}
}
