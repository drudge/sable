package devices

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/insights/vendors"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/unifi"
)

// Finding kinds about devices and networks that go around Sable for DNS.
const (
	KindNotUsingSable     = "devices.not-using-sable"
	KindNetworkOtherDNS   = "devices.network-other-dns"
	KindNetworkViaGateway = "devices.network-via-gateway"
)

// Fixed rules for coverage findings. The window a device must stay silent
// for is in Limits.
const (
	// minimumSilentTraffic is how much a device must move during the window
	// for UniFi's word that it is online to mean it is in use, rather than
	// holding a lease while it sleeps.
	minimumSilentTraffic = 1_000_000
	// A controller reading older than a few syncs, and never less than
	// staleReadingFloor, may describe a network that has since changed.
	staleReadingIntervals = 3
	staleReadingFloor     = 15 * time.Minute
	// counterSlack is how long after the window starts the traffic counter
	// it is measured from may have been read, since the sync keeps one
	// reading an hour.
	counterSlack = time.Hour
	// maximumListedSilent is how many devices the rolled-up finding names.
	maximumListedSilent = 12
	// notUsingSableLabel is the rolled-up finding's subject, which keeps its
	// identifier stable whichever devices it lists.
	notUsingSableLabel = "Devices not using Sable"
)

// CoverageInput is what the coverage findings are read from.
type CoverageInput struct {
	// Reading is the UniFi sync's latest read of the controller, and
	// Interval how often the sync reads it.
	Reading  unifi.Reading
	Interval time.Duration
	Now      time.Time
	// Lookups holds, for each client address that asked any Sable node
	// lately, when it last did. Nodes names the nodes it counts, and Unheard
	// the ones whose lookups it cannot count yet, which holds back every
	// statement that rests on a device or gateway sending nothing.
	Lookups map[string]time.Time
	Nodes   []string
	Unheard []string
	// Identities tie client addresses to hardware, and Clients are the
	// operator's names, which name the devices found.
	Identities []querylog.ClientIdentity
	Clients    []config.Client
	// Servers marks the client addresses of Sable servers.
	Servers map[string]string
	// Expected lists the keys of devices the operator said are expected not
	// to use Sable.
	Expected map[string]bool
	Limits   Limits
	Off      map[string]bool
}

// SilentDevice is a device UniFi shows online and busy for the whole window
// that sent no Sable node a lookup.
type SilentDevice struct {
	Device
	Network   string
	NetworkID string
	// ConnectedSince is when it connected, Moved what it sent and received
	// over the window, and BusyHours how many of the Hours its traffic
	// counter was read in it grew.
	ConnectedSince time.Time
	Moved          uint64
	BusyHours      int
	Hours          int
	// OtherDNS lists the DNS servers its network hands out that are not
	// Sable, when there are any.
	OtherDNS []string
	// Expected marks a device the operator said is expected not to use
	// Sable, which no finding lists.
	Expected bool
}

// NetworkDNS is what one network's DHCP tells devices to use for DNS.
type NetworkDNS struct {
	Network unifi.Network
	// Servers are the DNS servers handed out, described for a sentence, and
	// Bypass the ones among them that are not Sable: other servers, and the
	// gateway when it does not send its lookups to Sable.
	Servers []string
	Bypass  []string
	// Sable is set when at least one server handed out is a Sable node.
	Sable bool
	// ViaGateway is set when the gateway is handed out and sends its lookups
	// to Sable, which then sees every device's lookups as the gateway's.
	ViaGateway  bool
	Gateway     netip.Addr
	GatewayLast time.Time
	// Devices counts the connected devices on the network.
	Devices int
}

// Coverage is what Sable can tell about devices and networks going around it.
type Coverage struct {
	// Ready is set when the controller reading is current and every node's
	// lookups are counted, so a device's silence means something.
	Ready    bool
	Window   time.Duration
	Silent   []SilentDevice
	Networks []NetworkDNS
	Nodes    []string
	Unheard  []string
}

// FindSilent reports which connected UniFi devices sent Sable nothing over
// the window, and what each network's DHCP hands out for DNS.
func FindSilent(input CoverageInput) Coverage {
	limits := input.Limits.withDefaults()
	coverage := Coverage{Window: limits.SilentWindow, Nodes: input.Nodes, Unheard: input.Unheard}
	reading := input.Reading
	stale := max(staleReadingIntervals*input.Interval, staleReadingFloor)
	if reading.ReadAt.IsZero() || input.Now.Sub(reading.ReadAt) > stale {
		return coverage
	}
	heard := len(input.Unheard) == 0
	windowStart := input.Now.Add(-limits.SilentWindow)
	lookups := make(map[string]time.Time, len(input.Lookups))
	built := make(map[string]time.Time)
	for address, last := range input.Lookups {
		key := addressKey(address)
		lookups[key] = later(lookups[key], last)
		if mac, found := hardwareFromAddress(key); found {
			built[mac] = later(built[mac], last)
		}
	}
	servers := make(map[string]bool, len(input.Servers))
	for address := range input.Servers {
		servers[addressKey(address)] = true
	}
	gateways := make(map[netip.Addr]bool)
	for _, network := range reading.Networks {
		if network.Gateway.IsValid() {
			gateways[network.Gateway] = true
		}
	}
	var gatewayLast time.Time
	for gateway := range gateways {
		gatewayLast = later(gatewayLast, lookups[gateway.String()])
	}
	gatewayAsks := !gatewayLast.Before(windowStart)

	byNetwork := make(map[string]*NetworkDNS, len(reading.Networks))
	for _, network := range reading.Networks {
		handed, known := network.HandedOutDNS()
		if !known {
			continue
		}
		dns := NetworkDNS{Network: network, Gateway: network.Gateway, GatewayLast: gatewayLast}
		for _, server := range handed {
			switch {
			case servers[server.String()]:
				dns.Sable = true
				dns.Servers = append(dns.Servers, server.String())
			case gateways[server]:
				dns.Servers = append(dns.Servers, "the gateway at "+server.String())
				// Whether the gateway reaches Sable rests on its lookups,
				// which every node must have reported.
				switch {
				case !heard:
				case gatewayAsks:
					dns.ViaGateway = true
				default:
					dns.Bypass = append(dns.Bypass, "the gateway at "+server.String())
				}
			default:
				dns.Servers = append(dns.Servers, server.String())
				dns.Bypass = append(dns.Bypass, server.String())
			}
		}
		byNetwork[network.ID] = &dns
	}

	given := NewGivenNames(input.Identities, input.Clients)
	for _, station := range reading.Stations {
		network := byNetwork[station.NetworkID]
		if network != nil {
			network.Devices++
		}
		if !heard || (network != nil && network.ViaGateway) {
			continue
		}
		silent, ok := silentStation(station, reading, lookups, built, servers, input.Identities, windowStart)
		if !ok {
			continue
		}
		silent.Device = stationDevice(station, given)
		silent.Expected = input.Expected[silent.Key]
		if known, found := networkNamed(reading.Networks, station.NetworkID); found {
			silent.Network = known.Name
		}
		if network != nil {
			silent.OtherDNS = network.Bypass
		}
		coverage.Silent = append(coverage.Silent, silent)
	}
	slices.SortFunc(coverage.Silent, func(left, right SilentDevice) int {
		return cmp.Or(cmp.Compare(left.Network, right.Network), cmp.Compare(strings.ToLower(Label(left.Device)), strings.ToLower(Label(right.Device))), cmp.Compare(left.Key, right.Key))
	})
	for _, network := range reading.Networks {
		if dns := byNetwork[network.ID]; dns != nil {
			coverage.Networks = append(coverage.Networks, *dns)
		}
	}
	coverage.Ready = heard
	return coverage
}

// silentStation reports a station that was connected and moving traffic for
// the whole window without any of its addresses asking Sable anything.
func silentStation(station unifi.Station, reading unifi.Reading, lookups, built map[string]time.Time, servers map[string]bool,
	identities []querylog.ClientIdentity, windowStart time.Time) (SilentDevice, bool) {
	addresses := make([]string, 0, len(station.IPv6)+1)
	for _, address := range station.Addresses() {
		addresses = append(addresses, address.String())
	}
	for _, address := range addresses {
		if servers[address] {
			return SilentDevice{}, false
		}
	}
	connected := station.ConnectedAt(reading.ReadAt)
	if connected.After(windowStart) {
		return SilentDevice{}, false
	}
	// The counter runs from when the station connected, so the window is
	// measured from its last reading near the window's start, or from zero
	// when it connected about then.
	var samples []unifi.TrafficSample
	for _, sample := range reading.Traffic[station.MAC] {
		if sameConnection(sample.ConnectedAt, connected) {
			samples = append(samples, sample)
		}
	}
	base, found := counterBase(samples, connected, windowStart)
	if !found || station.Bytes < base.Bytes || station.Bytes-base.Bytes < minimumSilentTraffic {
		return SilentDevice{}, false
	}
	// Each hourly reading after the base, and the latest read, closes an hour
	// the counter either grew in or did not.
	readings := make([]unifi.TrafficSample, 0, len(samples)+1)
	for _, sample := range samples {
		if sample.ReadAt.After(base.ReadAt) && sample.ReadAt.Before(reading.ReadAt) {
			readings = append(readings, sample)
		}
	}
	readings = append(readings, unifi.TrafficSample{ReadAt: reading.ReadAt, Bytes: station.Bytes})
	busy, previous := 0, base.Bytes
	for _, sample := range readings {
		if sample.Bytes > previous {
			busy++
		}
		previous = max(previous, sample.Bytes)
	}
	hours := len(readings)
	if last := built[station.MAC]; !last.IsZero() && !last.Before(windowStart) {
		return SilentDevice{}, false
	}
	for _, address := range append(addresses, AddressesOf(identities, station.MAC)...) {
		if last, asked := lookups[addressKey(address)]; asked && !last.Before(windowStart) {
			return SilentDevice{}, false
		}
	}
	return SilentDevice{
		NetworkID: station.NetworkID, ConnectedSince: connected,
		Moved: station.Bytes - base.Bytes, BusyHours: busy, Hours: hours,
	}, true
}

// counterBase picks the reading a station's traffic over the window is
// measured from: the last one at or before the window's start, or else the
// first one soon after it, or else zero when the station connected about when
// the window started, since the counter starts there.
func counterBase(samples []unifi.TrafficSample, connected, windowStart time.Time) (unifi.TrafficSample, bool) {
	var base unifi.TrafficSample
	found := false
	for _, sample := range samples {
		if !sample.ReadAt.After(windowStart) {
			base, found = sample, true
		}
	}
	if found {
		return base, true
	}
	for _, sample := range samples {
		if !sample.ReadAt.After(windowStart.Add(counterSlack)) {
			return sample, true
		}
	}
	if !connected.Before(windowStart.Add(-counterSlack)) {
		return unifi.TrafficSample{ReadAt: connected, ConnectedAt: connected}, true
	}
	return unifi.TrafficSample{}, false
}

// stationDevice describes a connected station as a device, named the way the
// Devices tab names it.
func stationDevice(station unifi.Station, given GivenNames) Device {
	device := Device{Key: "mac:" + station.MAC, MAC: station.MAC}
	for _, address := range station.Addresses() {
		device.Addresses = append(device.Addresses, Address{Address: address.String()})
	}
	if parsed, err := net.ParseMAC(station.MAC); err == nil {
		device.PrivateMAC = len(parsed) > 0 && parsed[0]&0x02 != 0
	}
	device.Name, device.NameSource, device.NameNetwork = chooseName(device, given, nil)
	if device.Name == "" && station.Name != "" {
		device.Name, device.NameSource = station.Name, SourceUniFi
	}
	device.Named = device.NameSource == SourceOperator
	device.UniFiType = given.types[device.MAC]
	guess := given.guesses[device.MAC]
	device.UniFiGuess, device.UniFiConfidence, device.UniFiSet = guess.Kind, guess.KindConfidence, guess.KindSet
	device.Type = given.operator.own(device, clientType)
	device.NetworkType, device.TypeNetwork = given.operator.network(device, clientType)
	device.Vendor, _ = vendors.Lookup(device.MAC)
	return device
}

// CoverageFindings turns what Sable found about coverage into findings: one
// rolled up for every silent device, so a new one can alert, and one for
// each network whose DHCP sends devices around Sable or through its gateway.
func CoverageFindings(input CoverageInput, coverage Coverage) []insights.Finding {
	findings := make([]insights.Finding, 0)
	if !input.Off[KindNetworkOtherDNS] {
		for _, network := range coverage.Networks {
			if len(network.Bypass) > 0 {
				findings = append(findings, otherDNSFinding(input, coverage, network))
			}
		}
	}
	if !coverage.Ready {
		return findings
	}
	if !input.Off[KindNotUsingSable] {
		listed := make([]SilentDevice, 0, len(coverage.Silent))
		for _, silent := range coverage.Silent {
			if !silent.Expected {
				listed = append(listed, silent)
			}
		}
		if len(listed) > 0 {
			findings = append(findings, notUsingSableFinding(input, coverage, listed))
		}
	}
	if !input.Off[KindNetworkViaGateway] {
		for _, network := range coverage.Networks {
			if network.ViaGateway {
				findings = append(findings, viaGatewayFinding(input, coverage, network))
			}
		}
	}
	return findings
}

// NotUsingSableID is the rolled-up finding's identifier.
var NotUsingSableID = insights.NewID(KindNotUsingSable, insights.Subject{Label: notUsingSableLabel})

// NotUsingSableDeviceID identifies one device within the rolled-up finding,
// which an operator's word that the device is expected is kept by.
func NotUsingSableDeviceID(key string) string {
	return insights.Finding{Kind: KindNotUsingSable}.MemberID(insights.Subject{Device: key})
}

// NotUsingSableDevice reads the device key out of an identifier
// NotUsingSableDeviceID made, and reports whether it was one.
func NotUsingSableDevice(id string) (string, bool) {
	key, found := strings.CutPrefix(id, strings.TrimSuffix(NotUsingSableDeviceID("mac:"), "mac:"))
	return key, found && strings.HasPrefix(key, "mac:") && len(key) > len("mac:")
}

func notUsingSableFinding(input CoverageInput, coverage Coverage, listed []SilentDevice) insights.Finding {
	window := WindowText(coverage.Window)
	count := uint64(len(listed))
	// One device is named; several are counted, which reads the same at the
	// start of the finding and in the middle of the page's summary sentence.
	subject := insights.Subject{Label: fmt.Sprintf("%d devices", count)}
	headline := subject.Label + " don't use Sable"
	if count == 1 {
		subject = deviceSubject(listed[0].Device)
		headline = subject.Label + " doesn't use Sable"
	}
	nodes, received := "Sable", "Sable got no lookup from any of %s addresses in that time"
	if len(coverage.Nodes) > 1 {
		nodes, received = "any Sable node", "No Sable node got a lookup from any of %s addresses in that time"
	}
	reasons := []insights.Reason{
		{Text: fmt.Sprintf("UniFi says %s online and passing traffic for the last %s", insights.Plural(count, "it has been", "each one has been"), window)},
		{Text: fmt.Sprintf(received, insights.Plural(count, "its", "their"))},
	}
	for _, network := range coverage.Networks {
		if len(network.Bypass) == 0 || !slices.ContainsFunc(listed, func(silent SilentDevice) bool { return silent.NetworkID == network.Network.ID }) {
			continue
		}
		text := fmt.Sprintf("%s network hands out %s for DNS, not Sable", network.Network.Name, insights.JoinAnd(network.Bypass))
		if network.Sable {
			text = fmt.Sprintf("%s network also hands out %s for DNS", network.Network.Name, insights.JoinAnd(network.Bypass))
		}
		reasons = append(reasons, insights.Reason{Text: text})
	}
	facts := make([]insights.Fact, 0, min(len(listed), maximumListedSilent)+1)
	for _, silent := range listed[:min(len(listed), maximumListedSilent)] {
		facts = append(facts, insights.Fact{Label: Label(silent.Device), Value: silentFact(silent, input.Now)})
	}
	members := make([]insights.Subject, 0, len(listed))
	for _, silent := range listed {
		members = append(members, deviceSubject(silent.Device))
	}
	if more := len(listed) - maximumListedSilent; more > 0 {
		facts = append(facts, insights.Fact{Label: "And more", Value: fmt.Sprintf("%d more on the Devices tab", more)})
	}
	return insights.Finding{
		ID: NotUsingSableID, Kind: KindNotUsingSable, Tone: insights.ToneAttention, Title: "Not using Sable",
		Subject:  subject,
		Headline: headline,
		Summary: fmt.Sprintf("UniFi shows %s online and busy for the last %s, but no lookup from %s reached %s.",
			insights.Plural(count, "this device", "these devices"), window, insights.Plural(count, "it", "them"), nodes),
		Reasons: reasons,
		Facts:   facts,
		Explanations: []string{
			"DNS set by hand on the device, such as 8.8.8.8 on a TV",
			"A VPN or DNS over HTTPS on the device",
			"Its network handing out other DNS servers",
		},
		Method: "Sable lists devices UniFi shows connected for the whole period that moved at least 1 MB in it, " +
			"and that sent no lookup to " + nodes + " from any address tied to them: the addresses UniFi lists, " +
			"including every IPv6 address it has seen, any address Sable has seen with the device's hardware address, " +
			"and IPv6 addresses built from it. An IPv6 privacy address neither UniFi nor Sable tied to the device does not count. " +
			"UniFi's own gear and Sable's servers are left out, and so are networks whose DHCP hands out a gateway that forwards to Sable, " +
			"since their lookups reach Sable as the gateway's. It only claims no lookups at all, not a device that uses Sable some of the time.",
		Destination: "/insights?tab=devices&show=" + NotUsingSableShow, DestinationLabel: "Show These Devices",
		Members: members,
	}
}

// NotUsingSableShow is the Devices tab's filter for devices that don't use
// Sable.
const NotUsingSableShow = "not-using-sable"

// silentFact describes one silent device in a line: its network, how long it
// has been online, and what it moved.
func silentFact(silent SilentDevice, now time.Time) string {
	parts := make([]string, 0, 3)
	if silent.Network != "" {
		parts = append(parts, silent.Network)
	}
	parts = append(parts, "online "+insights.FormatDuration(now.Sub(silent.ConnectedSince)), FormatBytes(silent.Moved)+" moved", "0 lookups")
	return strings.Join(parts, ", ")
}

func otherDNSFinding(input CoverageInput, coverage Coverage, network NetworkDNS) insights.Finding {
	servers := insights.JoinAnd(network.Bypass)
	verb, skipped := "gives", "their lookups"
	if network.Sable || network.ViaGateway {
		verb, skipped = "also gives", "some lookups"
	}
	reasons := []insights.Reason{{Text: fmt.Sprintf("UniFi's DHCP for %s hands out %s", network.Network.Name, insights.JoinAnd(network.Servers))}}
	if network.Sable {
		reasons = append(reasons, insights.Reason{Text: "Devices may use any server they're given, so some lookups skip Sable"})
	} else {
		reasons = append(reasons, insights.Reason{Text: "None of them is a Sable node"})
	}
	if slices.ContainsFunc(network.Bypass, func(server string) bool { return strings.HasPrefix(server, "the gateway") }) {
		reasons = append(reasons, insights.Reason{Text: fmt.Sprintf("The gateway sent Sable no lookups in the last %s, so it resolves names somewhere else", WindowText(coverage.Window))})
	}
	facts := []insights.Fact{{Label: "DNS servers handed out", Value: strings.Join(dnsAddresses(network.Network), ", "), Monospace: true}}
	facts = append(facts, insights.Fact{Label: "Devices on it now", Value: insights.FormatCount(uint64(network.Devices))})
	return insights.Finding{
		ID:   KindNetworkOtherDNS + "/unifi-network:" + network.Network.ID,
		Kind: KindNetworkOtherDNS, Tone: insights.ToneAttention,
		Title:    "Network hands out other DNS",
		Subject:  insights.Subject{Label: network.Network.Name + " network"},
		Headline: fmt.Sprintf("%s network %s out %s for DNS", network.Network.Name, verb, servers),
		Summary:  fmt.Sprintf("Its DHCP %s devices %s for DNS, so %s skip Sable. Change DHCP DNS in UniFi under Networks → %s.", verb, servers, skipped, network.Network.Name),
		Reasons:  reasons,
		Facts:    facts,
		Method: "Sable reads the DNS servers each UniFi network's DHCP hands out and reports a network that hands out one that is not a Sable node. " +
			"A gateway handed out counts as Sable when it sends its own lookups to Sable, since it then forwards the network's.",
	}
}

func viaGatewayFinding(input CoverageInput, coverage Coverage, network NetworkDNS) insights.Finding {
	gateway := network.Gateway.String()
	return insights.Finding{
		ID:   KindNetworkViaGateway + "/unifi-network:" + network.Network.ID,
		Kind: KindNetworkViaGateway, Tone: insights.ToneNotice,
		Title:   "Network sends lookups through the gateway",
		Subject: insights.Subject{Label: network.Network.Name + " network"},
		Summary: fmt.Sprintf("Its DHCP gives devices the gateway at %s for DNS, and the gateway forwards to Sable, "+
			"so Sable sees those lookups as the gateway's and can't block or log them per device.", gateway),
		Reasons: []insights.Reason{
			{Text: fmt.Sprintf("UniFi's DHCP for %s hands out %s", network.Network.Name, insights.JoinAnd(network.Servers))},
			{Text: "The gateway sent Sable lookups " + insights.FormatDuration(input.Now.Sub(network.GatewayLast)) + " ago", Code: gateway},
			{Text: "Sable left this network's devices out of the check for devices that don't use it"},
		},
		Facts: []insights.Fact{
			{Label: "DNS servers handed out", Value: strings.Join(dnsAddresses(network.Network), ", "), Monospace: true},
			{Label: "Devices on it now", Value: insights.FormatCount(uint64(network.Devices))},
		},
		Explanations: []string{"UniFi's default when a network's DHCP names no DNS servers", "The gateway listed next to Sable as a backup"},
		Method: "Sable reports a network whose DHCP hands out its gateway when the gateway itself sends Sable lookups. " +
			"Lookups forwarded that way arrive from the gateway, so no device on the network can be told apart.",
	}
}

// dnsAddresses lists the addresses a network hands out for DNS.
func dnsAddresses(network unifi.Network) []string {
	servers, _ := network.HandedOutDNS()
	addresses := make([]string, 0, len(servers))
	for _, server := range servers {
		addresses = append(addresses, server.String())
	}
	return addresses
}

func networkNamed(networks []unifi.Network, id string) (unifi.Network, bool) {
	for _, network := range networks {
		if network.ID == id {
			return network, true
		}
	}
	return unifi.Network{}, false
}

// sameConnection reports whether two readings of when a station connected
// describe one connection. Each is rounded to the minute from a read that
// took a moment, so they may differ by one.
func sameConnection(left, right time.Time) bool {
	difference := left.Sub(right)
	return difference <= 2*time.Minute && difference >= -2*time.Minute
}

// addressKey writes a client address the way UniFi and the query log agree
// on: unmapped, without a zone, in canonical form.
func addressKey(address string) string {
	parsed, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return strings.ToLower(strings.TrimSpace(address))
	}
	return parsed.Unmap().WithZone("").String()
}

func later(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}

// WindowText writes how long a device must stay silent the way a sentence
// reads it: "24 hours", or whole days past two days, as in "3 days".
func WindowText(window time.Duration) string {
	hours := int(window / time.Hour)
	if hours >= 48 && hours%24 == 0 {
		return fmt.Sprintf("%d days", hours/24)
	}
	return fmt.Sprintf("%d %s", hours, insights.Plural(hours, "hour", "hours"))
}

// FormatBytes writes a traffic total in decimal units, as UniFi shows it.
func FormatBytes(bytes uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	value, unit := float64(bytes), 0
	for value >= 1000 && unit < len(units)-1 {
		value /= 1000
		unit++
	}
	if unit == 0 || value >= 100 {
		return strconv.FormatFloat(value, 'f', 0, 64) + " " + units[unit]
	}
	return strconv.FormatFloat(value, 'f', 1, 64) + " " + units[unit]
}

// CoverageSources is what the coverage analyzer reads. The console
// implements it over the UniFi sync's latest reading, the query log store,
// and the cluster.
type CoverageSources interface {
	Coverage(context.Context) (CoverageInput, error)
}

// CoverageAnalyzer reports devices and networks that go around Sable for DNS.
// It reads what the UniFi sync and the query log store already keep, so it
// runs outside the DNS request path like every analyzer.
type CoverageAnalyzer struct {
	Sources CoverageSources
	Limits  Limits
	Off     map[string]bool
}

// Analyze compares what UniFi says is online with what asked Sable.
func (analyzer CoverageAnalyzer) Analyze(ctx context.Context, _ insights.Window) ([]insights.Finding, error) {
	if analyzer.Off[KindNotUsingSable] && analyzer.Off[KindNetworkOtherDNS] && analyzer.Off[KindNetworkViaGateway] {
		return nil, nil
	}
	input, err := analyzer.Sources.Coverage(ctx)
	if err != nil {
		return nil, err
	}
	input.Limits, input.Off = analyzer.Limits, analyzer.Off
	return CoverageFindings(input, FindSilent(input)), nil
}
