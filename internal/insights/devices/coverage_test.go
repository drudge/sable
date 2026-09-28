package devices

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/unifi"
)

var coverageNow = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

// coverageStation is a station connected for two days whose counter grew
// every hour of the last day, with its hourly readings.
func coverageStation(mac, name, network, address string, ipv6 ...string) (unifi.Station, []unifi.TrafficSample) {
	station := unifi.Station{
		MAC: mac, Name: name, NetworkID: network, Address: netip.MustParseAddr(address),
		Uptime: 48 * time.Hour, Bytes: 500_000_000, LastSeen: coverageNow,
	}
	for _, value := range ipv6 {
		station.IPv6 = append(station.IPv6, netip.MustParseAddr(value))
	}
	connected := station.ConnectedAt(coverageNow)
	samples := make([]unifi.TrafficSample, 0, 26)
	for hour := 26; hour >= 1; hour-- {
		samples = append(samples, unifi.TrafficSample{
			ReadAt: coverageNow.Add(-time.Duration(hour) * time.Hour), ConnectedAt: connected,
			Bytes: station.Bytes - uint64(hour)*10_000_000,
		})
	}
	return station, samples
}

// coverageNetwork is a network whose DHCP hands out the given servers, or its
// gateway when there are none.
func coverageNetwork(id, name, gateway string, dns ...string) unifi.Network {
	network := unifi.Network{ID: id, Name: name, Gateway: netip.MustParseAddr(gateway), DHCP: true}
	for _, server := range dns {
		network.DHCPDNS = append(network.DHCPDNS, netip.MustParseAddr(server))
	}
	return network
}

type coverageCase struct {
	input CoverageInput
}

func newCoverageCase() *coverageCase {
	return &coverageCase{input: CoverageInput{
		Reading: unifi.Reading{
			ReadAt:  coverageNow.Add(-time.Minute),
			Traffic: map[string][]unifi.TrafficSample{},
			Networks: []unifi.Network{
				coverageNetwork("net-lan", "Default", "10.0.0.1", "10.0.0.53"),
				coverageNetwork("net-iot", "IoT", "10.0.30.1", "10.0.0.53"),
			},
		},
		Interval: 2 * time.Minute, Now: coverageNow,
		Lookups: map[string]time.Time{}, Nodes: []string{"ns1"},
		Servers: map[string]string{"10.0.0.53": "This server"},
	}}
}

func (test *coverageCase) add(station unifi.Station, samples []unifi.TrafficSample) {
	test.input.Reading.Stations = append(test.input.Reading.Stations, station)
	test.input.Reading.Traffic[station.MAC] = samples
}

func (test *coverageCase) silentKeys() []string {
	keys := make([]string, 0)
	for _, silent := range FindSilent(test.input).Silent {
		keys = append(keys, silent.Key)
	}
	return keys
}

func findingOf(findings []insights.Finding, kind string) (insights.Finding, bool) {
	for _, finding := range findings {
		if finding.Kind == kind {
			return finding, true
		}
	}
	return insights.Finding{}, false
}

// A device counts as not using Sable only when no address tied to it asked
// any node: the address UniFi lists, any IPv6 address it lists, one Sable has
// seen with its hardware, or one built from its hardware address.
func TestFindSilentChecksEveryAddressTiedToADevice(t *testing.T) {
	test := newCoverageCase()
	silentTV, samples := coverageStation("aa:00:00:00:00:01", "Living Room TV", "net-iot", "10.0.30.10")
	test.add(silentTV, samples)
	asksIPv4, samples := coverageStation("aa:00:00:00:00:02", "Laptop", "net-lan", "10.0.0.20")
	test.add(asksIPv4, samples)
	asksListedIPv6, samples := coverageStation("aa:00:00:00:00:03", "Phone", "net-lan", "10.0.0.30", "2001:db8::1234:5678:9abc:def0")
	test.add(asksListedIPv6, samples)
	asksBuiltIPv6, samples := coverageStation("aa:00:00:00:00:04", "Printer", "net-lan", "10.0.0.40")
	test.add(asksBuiltIPv6, samples)
	asksSeenAddress, samples := coverageStation("aa:00:00:00:00:05", "Tablet", "net-lan", "10.0.0.50")
	test.add(asksSeenAddress, samples)
	test.input.Lookups = map[string]time.Time{
		"10.0.0.20":                     coverageNow.Add(-time.Hour),
		"2001:DB8::1234:5678:9ABC:DEF0": coverageNow.Add(-2 * time.Hour),
		// a8:00:00 flips the universal/local bit of aa:00:00.
		"2001:db8::a800:ff:fe00:4": coverageNow.Add(-3 * time.Hour),
		"2001:db8::77":             coverageNow.Add(-4 * time.Hour),
		// A lookup from before the window proves nothing about it.
		"10.0.30.10": coverageNow.Add(-25 * time.Hour),
	}
	test.input.Identities = []querylog.ClientIdentity{
		{Address: "2001:db8::77", MAC: "aa:00:00:00:00:05", Source: "neighbor", LastSeen: coverageNow.Add(-time.Hour)},
	}

	if keys := test.silentKeys(); !slices.Equal(keys, []string{"mac:aa:00:00:00:00:01"}) {
		t.Fatalf("silent devices = %v, want only the TV", keys)
	}
	silent := FindSilent(test.input).Silent[0]
	if silent.Name != "Living Room TV" || silent.NameSource != SourceUniFi || silent.Network != "IoT" ||
		silent.Moved != 240_000_000 || silent.BusyHours != 24 || silent.Hours != 24 {
		t.Fatalf("silent TV = %+v, want its UniFi name, network, and a day of traffic measured from the reading 24 hours ago", silent)
	}
}

// UniFi must show the device connected for the whole window and moving real
// traffic in it, measured from a reading near the window's start rather than
// from when it connected.
func TestFindSilentNeedsAWholeWindowOfTraffic(t *testing.T) {
	test := newCoverageCase()
	justJoined, samples := coverageStation("aa:00:00:00:00:01", "New Phone", "net-lan", "10.0.0.10")
	justJoined.Uptime = 20 * time.Hour
	test.add(justJoined, samples)
	idle, samples := coverageStation("aa:00:00:00:00:02", "Sleeping Printer", "net-lan", "10.0.0.20")
	for index := range samples {
		samples[index].Bytes = idle.Bytes - 500_000
	}
	test.add(idle, samples)
	busyLastWeek, samples := coverageStation("aa:00:00:00:00:03", "Old Laptop", "net-lan", "10.0.0.30")
	for index := range samples {
		samples[index].Bytes = busyLastWeek.Bytes
	}
	test.add(busyLastWeek, samples)
	noHistory, _ := coverageStation("aa:00:00:00:00:04", "Unwatched TV", "net-lan", "10.0.0.40")
	test.add(noHistory, nil)
	freshConnection, _ := coverageStation("aa:00:00:00:00:05", "Fresh TV", "net-lan", "10.0.0.50")
	freshConnection.Uptime = 24*time.Hour + 30*time.Minute
	test.add(freshConnection, nil)
	reconnected, samples := coverageStation("aa:00:00:00:00:06", "Roaming Phone", "net-lan", "10.0.0.60")
	for index := range samples {
		samples[index].ConnectedAt = samples[index].ConnectedAt.Add(-time.Hour)
	}
	test.add(reconnected, samples)

	// The fresh connection has no readings, but its counter started at zero
	// about when the window did.
	if keys := test.silentKeys(); !slices.Equal(keys, []string{"mac:aa:00:00:00:00:05"}) {
		t.Fatalf("silent devices = %v, want only the one connected at the window's start", keys)
	}
}

// A network whose DHCP hands out a gateway that forwards to Sable hides its
// devices behind the gateway, so they are left out and the network is
// reported instead. A gateway that asks Sable nothing is a way around it.
func TestGatewayForwardingIsReportedInsteadOfItsDevices(t *testing.T) {
	test := newCoverageCase()
	test.input.Reading.Networks = []unifi.Network{
		coverageNetwork("net-lan", "Default", "10.0.0.1", "10.0.0.53", "10.0.0.1"),
		coverageNetwork("net-iot", "IoT", "10.0.30.1"),
	}
	behindGateway, samples := coverageStation("aa:00:00:00:00:01", "Camera", "net-iot", "10.0.30.10")
	test.add(behindGateway, samples)
	onLAN, samples := coverageStation("aa:00:00:00:00:02", "Chromecast", "net-lan", "10.0.0.20")
	test.add(onLAN, samples)
	test.input.Lookups = map[string]time.Time{"10.0.0.1": coverageNow.Add(-time.Minute)}

	coverage := FindSilent(test.input)
	if keys := test.silentKeys(); len(keys) != 0 {
		t.Fatalf("silent devices = %v, want none: both networks hand out a gateway that forwards to Sable", keys)
	}
	findings := CoverageFindings(test.input, coverage)
	var gateways []string
	for _, finding := range findings {
		if finding.Kind == KindNetworkViaGateway {
			gateways = append(gateways, finding.Subject.Label)
		}
	}
	if !slices.Equal(gateways, []string{"Default network", "IoT network"}) {
		t.Fatalf("gateway findings = %v, want both networks", gateways)
	}

	test.input.Lookups = map[string]time.Time{}
	findings = CoverageFindings(test.input, FindSilent(test.input))
	var titles []string
	for _, finding := range findings {
		if finding.Kind == KindNetworkOtherDNS {
			titles = append(titles, finding.Headline)
		}
	}
	if !slices.Equal(titles, []string{
		"Default network also gives out the gateway at 10.0.0.1 for DNS",
		"IoT network gives out the gateway at 10.0.30.1 for DNS",
	}) {
		t.Fatalf("network findings = %q, want both networks reported for a gateway that resolves elsewhere", titles)
	}
	rollup, found := findingOf(findings, KindNotUsingSable)
	if !found || rollup.Title != "Not using Sable" || rollup.Subject.Label != "2 devices" {
		t.Fatalf("rollup = %+v, want both devices once the gateway asks Sable nothing", rollup)
	}
}

// A network handing out a server that is not Sable is reported on its own,
// and named as the reason in the rolled-up finding.
func TestOtherDNSIsReportedWithTheDevicesItStrands(t *testing.T) {
	test := newCoverageCase()
	test.input.Reading.Networks = append(test.input.Reading.Networks, coverageNetwork("net-guest", "Guest", "10.0.50.1", "1.1.1.1", "1.0.0.1"))
	guest, samples := coverageStation("aa:00:00:00:00:01", "", "net-guest", "10.0.50.10")
	test.add(guest, samples)
	tv, samples := coverageStation("aa:00:00:00:00:02", "Living Room TV", "net-iot", "10.0.30.10")
	test.add(tv, samples)

	findings := CoverageFindings(test.input, FindSilent(test.input))
	other, found := findingOf(findings, KindNetworkOtherDNS)
	if !found || other.Summary != "Its DHCP gives devices 1.1.1.1 and 1.0.0.1 for DNS, so their lookups skip Sable. Change DHCP DNS in UniFi under Networks → Guest." ||
		other.Subject.Label != "Guest network" || other.Tone != insights.ToneAttention ||
		other.ID != "devices.network-other-dns/unifi-network:net-guest" {
		t.Fatalf("findings = %+v, want the guest network reported", findings)
	}
	rollup, found := findingOf(findings, KindNotUsingSable)
	if !found || rollup.ID != NotUsingSableID || rollup.Headline != "2 devices don't use Sable" {
		t.Fatalf("rollup = %+v", rollup)
	}
	if len(rollup.Members) != 2 || rollup.MemberID(rollup.Members[1]) != "devices.not-using-sable/device:mac:aa:00:00:00:00:02" ||
		NotUsingSableDeviceID("mac:aa:00:00:00:00:02") != rollup.MemberID(rollup.Members[1]) {
		t.Fatalf("rollup members = %+v, want each device by its key", rollup.Members)
	}
	if key, found := NotUsingSableDevice(rollup.MemberID(rollup.Members[1])); !found || key != "mac:aa:00:00:00:00:02" {
		t.Fatalf("member key = %q (%t)", key, found)
	}
	for _, id := range []string{NotUsingSableID, "devices.not-using-sable/device:", "devices.went-quiet/device:mac:aa:00:00:00:00:02"} {
		if _, found := NotUsingSableDevice(id); found {
			t.Errorf("%q read as a silent device", id)
		}
	}
	labels := make([]string, 0, len(rollup.Facts))
	for _, fact := range rollup.Facts {
		labels = append(labels, fact.Label)
	}
	if !slices.Equal(labels, []string{"aa:00:00:00:00:01", "Living Room TV"}) || !strings.HasPrefix(rollup.Facts[0].Value, "Guest, online 2 days") {
		t.Fatalf("rollup facts = %+v, want each device by network", rollup.Facts)
	}
	if !slices.ContainsFunc(rollup.Reasons, func(reason insights.Reason) bool {
		return reason.Text == "Guest network hands out 1.1.1.1 and 1.0.0.1 for DNS, not Sable"
	}) || rollup.Reasons[1].Text != "Sable got no lookup from any of their addresses in that time" {
		t.Fatalf("rollup reasons = %+v, want the guest network's DNS named", rollup.Reasons)
	}

	test.input.Nodes = []string{"ns1", "ns2"}
	if reason := CoverageFindings(test.input, FindSilent(test.input)); !slices.ContainsFunc(reason, func(finding insights.Finding) bool {
		return finding.Kind == KindNotUsingSable && finding.Reasons[1].Text == "No Sable node got a lookup from any of their addresses in that time"
	}) {
		t.Fatalf("findings = %+v, want the cluster's wording", reason)
	}
	test.input.Reading.Networks[0] = coverageNetwork("net-lan", "Default", "10.0.0.1", "10.0.0.53", "8.8.8.8")
	findings = CoverageFindings(test.input, FindSilent(test.input))
	if !slices.ContainsFunc(findings, func(finding insights.Finding) bool {
		return finding.Headline == "Default network also gives out 8.8.8.8 for DNS"
	}) {
		t.Fatalf("findings = %+v, want the default network's public fallback reported", findings)
	}
}

// Silence means nothing until every node's lookups are counted, the reading
// is current, and the device is not one the operator expects to be silent or
// a Sable server itself.
func TestCoverageHoldsBackWhatItCannotStandBehind(t *testing.T) {
	test := newCoverageCase()
	test.input.Reading.Networks = append(test.input.Reading.Networks, coverageNetwork("net-guest", "Guest", "10.0.50.1", "1.1.1.1"))
	tv, samples := coverageStation("aa:00:00:00:00:01", "Living Room TV", "net-iot", "10.0.30.10")
	test.add(tv, samples)
	sable, samples := coverageStation("aa:00:00:00:00:02", "ns1", "net-lan", "10.0.0.53")
	test.add(sable, samples)

	if keys := test.silentKeys(); !slices.Equal(keys, []string{"mac:aa:00:00:00:00:01"}) {
		t.Fatalf("silent devices = %v, want the TV and not the Sable server", keys)
	}

	unheard := *test
	unheard.input.Unheard = []string{"ns2"}
	findings := CoverageFindings(unheard.input, FindSilent(unheard.input))
	if _, found := findingOf(findings, KindNotUsingSable); found {
		t.Fatal("a device was called silent while a node's lookups were not counted")
	}
	if _, found := findingOf(findings, KindNetworkOtherDNS); !found {
		t.Fatal("a public server handed out went unreported because a node was not heard")
	}

	stale := *test
	stale.input.Reading.ReadAt = coverageNow.Add(-time.Hour)
	if findings := CoverageFindings(stale.input, FindSilent(stale.input)); len(findings) != 0 {
		t.Fatalf("an hour-old reading produced %+v", findings)
	}

	expected := *test
	expected.input.Expected = map[string]bool{"mac:aa:00:00:00:00:01": true}
	coverage := FindSilent(expected.input)
	if len(coverage.Silent) != 1 || !coverage.Silent[0].Expected {
		t.Fatalf("silent = %+v, want the TV still listed as expected", coverage.Silent)
	}
	if _, found := findingOf(CoverageFindings(expected.input, coverage), KindNotUsingSable); found {
		t.Fatal("a device marked expected was reported")
	}

	window := *test
	window.input.Limits.SilentWindow = 72 * time.Hour
	if keys := window.silentKeys(); len(keys) != 0 {
		t.Fatalf("silent devices = %v over three days, want none from a device connected two days", keys)
	}
}

type staticCoverage struct{ input CoverageInput }

func (source staticCoverage) Coverage(context.Context) (CoverageInput, error) {
	return source.input, nil
}

// The analyzer reads nothing when every coverage kind is off, and passes its
// limits and switches through.
func TestCoverageAnalyzerHonorsItsSettings(t *testing.T) {
	test := newCoverageCase()
	tv, samples := coverageStation("aa:00:00:00:00:01", "Living Room TV", "net-iot", "10.0.30.10")
	test.add(tv, samples)
	analyzer := CoverageAnalyzer{Sources: staticCoverage{test.input}}
	findings, err := analyzer.Analyze(context.Background(), insights.Window{})
	if err != nil || len(findings) != 1 || findings[0].Headline != "Living Room TV doesn't use Sable" || findings[0].Subject.Device != "mac:aa:00:00:00:00:01" {
		t.Fatalf("findings = %+v, %v", findings, err)
	}
	analyzer.Off = map[string]bool{KindNotUsingSable: true}
	if findings, _ := analyzer.Analyze(context.Background(), insights.Window{}); len(findings) != 0 {
		t.Fatalf("a kind that is off produced %+v", findings)
	}
}

func TestWindowText(t *testing.T) {
	for window, want := range map[time.Duration]string{time.Hour: "1 hour", 24 * time.Hour: "24 hours", 36 * time.Hour: "36 hours", 72 * time.Hour: "3 days"} {
		if got := WindowText(window); got != want {
			t.Errorf("WindowText(%s) = %q, want %q", window, got, want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	for bytes, want := range map[uint64]string{0: "0 B", 999: "999 B", 1_500: "1.5 KB", 240_000_000: "240 MB", 2_100_000_000: "2.1 GB"} {
		if got := FormatBytes(bytes); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", bytes, got, want)
		}
	}
}
