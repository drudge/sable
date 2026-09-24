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

// The neighbor table is sampled more often than the UniFi controller and
// carries no name, so an address's newest sighting is usually a nameless one.
// A given name must hold anyway, and reverse DNS names only what nothing else
// does.
func TestGivenNamesOutrankReverseDNSWhicheverSightingIsNewest(t *testing.T) {
	t.Parallel()
	identities := []querylog.ClientIdentity{
		{Address: "10.0.0.5", MAC: "3c:22:fb:01:02:03", Source: "unifi", Hostname: "George's MacBook", LastSeen: testNow.Add(-2 * time.Minute)},
		{Address: "10.0.0.5", MAC: "3c:22:fb:01:02:03", Source: "neighbor", LastSeen: testNow},
		{Address: "10.0.0.6", MAC: "da:a1:19:00:00:01", Source: "unifi", Hostname: "iPad", LastSeen: testNow.Add(-2 * time.Minute)},
		{Address: "10.0.0.6", MAC: "da:a1:19:00:00:01", Source: "neighbor", LastSeen: testNow},
		// A device renamed in UniFi goes by its newest name, whichever
		// address it was reported at.
		{Address: "10.0.0.7", MAC: "aa:00:00:00:00:07", Source: "unifi", Hostname: "old-name", LastSeen: testNow.Add(-time.Hour)},
		{Address: "fd00::7", MAC: "aa:00:00:00:00:07", Source: "unifi", Hostname: "new-name", LastSeen: testNow},
		// UniFi's name for an address's previous owner is not this device's.
		{Address: "10.0.0.9", MAC: "aa:00:00:00:00:08", Source: "unifi", Hostname: "previous-owner", LastSeen: testNow.Add(-time.Hour)},
		{Address: "10.0.0.9", MAC: "aa:00:00:00:00:09", Source: "neighbor", LastSeen: testNow},
	}
	clients := []config.Client{{Name: "Kids iPad", MAC: "da:a1:19:00:00:01"}}
	built := Build(Input{
		Activity: querylog.ClientActivityReport{Clients: []querylog.ClientActivity{
			{Client: "10.0.0.5", Queries: 50}, {Client: "10.0.0.6", Queries: 40}, {Client: "10.0.0.7", Queries: 30},
			{Client: "10.0.0.8", Queries: 20}, {Client: "10.0.0.9", Queries: 10},
		}},
		Identities: identities,
		Clients:    clients,
		Names: map[string]DiscoveredName{
			"10.0.0.5": {Name: "georges-macbook.default.home.arpa", Source: SourceReverse},
			"10.0.0.6": {Name: "ipad.default.home.arpa", Source: SourceReverse},
			"10.0.0.8": {Name: "printer.default.home.arpa", Source: SourceReverse},
			"10.0.0.9": {Name: "camera.default.home.arpa", Source: SourceReverse},
		},
	})
	want := map[string][2]string{
		"mac:3c:22:fb:01:02:03": {"George's MacBook", SourceUniFi},
		"mac:da:a1:19:00:00:01": {"Kids iPad", SourceOperator},
		"mac:aa:00:00:00:00:07": {"new-name", SourceUniFi},
		"ip:10.0.0.8":           {"printer.default.home.arpa", SourceReverse},
		"mac:aa:00:00:00:00:09": {"camera.default.home.arpa", SourceReverse},
	}
	if len(built) != len(want) {
		t.Fatalf("devices = %+v", built)
	}
	for _, device := range built {
		if got := [2]string{device.Name, device.NameSource}; got != want[device.Key] {
			t.Errorf("%s is named %q from %q, want %q from %q", device.Key, got[0], got[1], want[device.Key][0], want[device.Key][1])
		}
	}

	// Lists that rank single addresses get the same given names.
	given := NewGivenNames(identities, clients)
	for address, want := range map[string]string{
		"10.0.0.5": "George's MacBook", "10.0.0.6": "Kids iPad", "fd00::7": "new-name", "10.0.0.8": "", "10.0.0.9": "",
	} {
		if got := given.Address(address); got != want {
			t.Errorf("given name for %s = %q, want %q", address, got, want)
		}
	}
	if got := (GivenNames{}).Address("10.0.0.5"); got != "" {
		t.Errorf("empty given names named an address %q", got)
	}
}

// Sable knows the machines it runs on: it marks them and counts running Sable
// as evidence of a server, without overruling stronger evidence.
func TestSableServersAreMarkedAndLookLikeServers(t *testing.T) {
	t.Parallel()
	built := Build(Input{
		Activity: querylog.ClientActivityReport{Clients: []querylog.ClientActivity{
			{Client: "10.0.7.12", Queries: 50}, {Client: "10.0.7.13", Queries: 40}, {Client: "10.0.7.20", Queries: 30},
		}},
		Servers: map[string]string{"10.0.7.12": "This server", "10.0.7.13": "Sable node"},
	})
	Identify(built, map[string][]string{"10.0.7.13": {"formulae.brew.sh", "marketplace.visualstudio.com"}})
	byKey := map[string]Device{}
	for _, device := range built {
		byKey[device.Key] = device
	}
	server := byKey["ip:10.0.7.12"]
	if server.Server != "This server" || server.Guess.Type != "server" || server.Guess.Confidence != ConfidenceMedium ||
		len(server.Guess.Reasons) != 1 || server.Guess.Reasons[0].Text != "Runs Sable" {
		t.Fatalf("this server = %+v", server)
	}
	// A developer's laptop that runs a Sable node is still a laptop.
	if laptop := byKey["ip:10.0.7.13"]; laptop.Server != "Sable node" || laptop.Guess.Type != "computer" {
		t.Fatalf("laptop running a node = %+v", laptop)
	}
	if other := byKey["ip:10.0.7.20"]; other.Server != "" || other.Guess.Type != "" {
		t.Fatalf("an ordinary device = %+v", other)
	}
}

func TestAddressesOfFollowsTheLatestSighting(t *testing.T) {
	t.Parallel()
	laptop := "3c:22:fb:01:02:03"
	identities := []querylog.ClientIdentity{
		{Address: "fd00::5", MAC: laptop, Source: "neighbor", LastSeen: testNow},
		{Address: "10.0.0.5", MAC: laptop, Source: "unifi", LastSeen: testNow.Add(-time.Hour)},
		// The laptop's old address now belongs to someone else.
		{Address: "10.0.0.6", MAC: laptop, Source: "neighbor", LastSeen: testNow.Add(-48 * time.Hour)},
		{Address: "10.0.0.6", MAC: "aa:00:00:00:00:06", Source: "neighbor", LastSeen: testNow},
	}
	if got := AddressesOf(identities, laptop); !slices.Equal(got, []string{"10.0.0.5", "fd00::5"}) {
		t.Fatalf("addresses = %v", got)
	}
	if got := AddressesOf(identities, "aa:00:00:00:00:99"); len(got) != 0 {
		t.Fatalf("an unseen device has addresses %v", got)
	}
}

// A name or type set for a whole network says so, and a device's own outranks
// its network's.
func TestNetworkNamesAndTypesSayWhereTheyComeFrom(t *testing.T) {
	t.Parallel()
	built := Build(Input{
		Activity: querylog.ClientActivityReport{Clients: []querylog.ClientActivity{{Client: "10.20.40.9", Queries: 20}, {Client: "10.20.40.10", Queries: 10}}},
		Clients: []config.Client{
			{Name: "Guest Wi-Fi", Address: "10.20.40.0/24", Type: "phone"},
			{Name: "Front Desk", Address: "10.20.40.10", Type: "computer"},
		},
	})
	Identify(built, nil)
	byKey := map[string]Device{}
	for _, device := range built {
		byKey[device.Key] = device
	}
	guest := byKey["ip:10.20.40.9"]
	if guest.Name != "Guest Wi-Fi" || guest.NameNetwork != "10.20.40.0/24" || !guest.Named || guest.Type != "" ||
		guest.Guess.Type != "phone" || guest.Guess.Reasons[0] != (insights.Reason{Text: "You set this type for", Code: "10.20.40.0/24"}) {
		t.Fatalf("guest = %+v", guest)
	}
	desk := byKey["ip:10.20.40.10"]
	if desk.Name != "Front Desk" || desk.NameNetwork != "" || desk.Type != "computer" || desk.NetworkType != "phone" ||
		desk.Guess.Type != "computer" || desk.Guess.Reasons[0].Text != "You set this type" {
		t.Fatalf("front desk = %+v", desk)
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
