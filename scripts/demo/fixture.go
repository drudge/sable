package main

import "github.com/drudge/sable/internal/querylog"

// The demo deployment belongs to Vandelay Industries, an importer and exporter
// of latex. Everything here is invented so the console can be photographed
// without borrowing anybody's real network.

const (
	corporateNetworkID = "6612a1f0c9d4e70b3a5f8801"
	warehouseNetworkID = "6612a1f0c9d4e70b3a5f8802"
	iotNetworkID       = "6612a1f0c9d4e70b3a5f8803"
	guestNetworkID     = "6612a1f0c9d4e70b3a5f8804"
)

// unifiNetwork is one network the mock controller reports.
type unifiNetwork struct {
	ID      string
	Name    string
	Purpose string
	Subnet  string
	// Zone is the Sable zone the network's hosts are published into. An empty
	// zone means the network is discovered but deliberately not published,
	// which is how the guest network behaves.
	Zone string
}

var unifiNetworks = []unifiNetwork{
	{ID: corporateNetworkID, Name: "Corporate", Purpose: "corporate", Subnet: "10.20.10.1/24", Zone: "corp.vandelay.com"},
	{ID: warehouseNetworkID, Name: "Warehouse", Purpose: "vlan-only", Subnet: "10.20.20.1/24", Zone: "warehouse.vandelay.com"},
	{ID: iotNetworkID, Name: "IoT", Purpose: "vlan-only", Subnet: "10.20.30.1/24", Zone: "iot.vandelay.com"},
	{ID: guestNetworkID, Name: "Guest", Purpose: "guest", Subnet: "10.20.40.1/24"},
}

// unifiHost is one device the mock controller reports. Reserved hosts appear
// as fixed-IP reservations; the rest appear as currently connected clients.
type unifiHost struct {
	MAC       string
	Name      string
	Address   string
	NetworkID string
	Reserved  bool
}

var unifiHosts = []unifiHost{
	{"00:08:74:11:04:a1", "art-workstation", "10.20.10.11", corporateNetworkID, true},
	{"10:c5:95:11:04:a2", "george-laptop", "10.20.10.12", corporateNetworkID, true},
	{"3c:22:fb:11:04:a3", "elaine-macbook", "10.20.10.13", corporateNetworkID, true},
	{"3c:22:fb:11:04:a4", "kramer-imac", "10.20.10.14", corporateNetworkID, true},
	{"00:08:74:11:04:a5", "newman-desktop", "10.20.10.15", corporateNetworkID, true},
	{"3c:22:fb:11:04:a6", "reception-imac", "10.20.10.16", corporateNetworkID, true},
	{"00:0b:db:11:04:a7", "payroll-server", "10.20.10.20", corporateNetworkID, true},
	{"00:11:32:11:04:a8", "backup-nas", "10.20.10.21", corporateNetworkID, true},
	{"00:01:e6:22:07:b1", "latex-press-01", "10.20.20.21", warehouseNetworkID, true},
	{"00:01:e6:22:07:b2", "latex-press-02", "10.20.20.22", warehouseNetworkID, true},
	{"00:05:12:22:07:b3", "shipping-scanner", "10.20.20.30", warehouseNetworkID, true},
	{"00:0d:56:22:07:b4", "loading-dock-pc", "10.20.20.31", warehouseNetworkID, true},
	{"00:07:4d:22:07:b5", "forklift-tablet", "10.20.20.32", warehouseNetworkID, true},
	{"44:61:32:33:0c:c1", "lobby-thermostat", "10.20.30.41", iotNetworkID, true},
	{"9c:8e:cd:33:0c:c2", "dock-camera-01", "10.20.30.42", iotNetworkID, true},
	{"9c:8e:cd:33:0c:c3", "dock-camera-02", "10.20.30.43", iotNetworkID, true},
	{"00:07:ab:33:0c:c4", "breakroom-display", "10.20.30.44", iotNetworkID, true},
	{"a4:cf:12:33:0c:c5", "espresso-machine", "10.20.30.45", iotNetworkID, true},
	// Installed two days ago; Insights reports it as a new device.
	{"34:3e:a4:33:0c:c6", "front-door-doorbell", "10.20.30.46", iotNetworkID, false},
	{"10:c5:95:55:11:d1", "jerry-thinkpad", "10.20.10.132", corporateNetworkID, false},
	{"00:0d:3a:55:11:d2", "morty-surface", "10.20.10.145", corporateNetworkID, false},
	{"3c:22:fb:55:11:d3", "helen-ipad", "10.20.10.151", corporateNetworkID, false},
	{"3c:22:fb:55:11:d4", "susan-laptop", "10.20.10.158", corporateNetworkID, false},
	{"00:1a:11:55:11:d5", "puddy-pixel", "10.20.10.164", corporateNetworkID, false},
	{"00:05:12:66:22:e1", "warehouse-handheld-04", "10.20.20.118", warehouseNetworkID, false},
	{"00:05:12:66:22:e2", "warehouse-handheld-07", "10.20.20.126", warehouseNetworkID, false},
	{"00:1b:a9:66:22:e3", "pallet-printer", "10.20.20.140", warehouseNetworkID, false},
	{"dc:a6:32:77:33:f1", "hallway-sensor-03", "10.20.30.112", iotNetworkID, false},
	{"dc:a6:32:77:33:f2", "roof-weather-station", "10.20.30.119", iotNetworkID, false},
	{"a4:cf:12:88:44:01", "vendor-laptop", "10.20.40.104", guestNetworkID, false},
	{"a4:cf:12:88:44:02", "kruger-visitor", "10.20.40.111", guestNetworkID, false},
}

// blockedDomains are the hand-written entries on the Blocked tab.
var blockedDomains = []string{
	"ads.kruger-industrial.com",
	"tracker.pendantpublishing.net",
	"metrics.kramerica.com",
	"pixel.bosco-analytics.com",
	"telemetry.jpeterman-catalog.com",
	"click.moviefone-ads.net",
	"beacon.h-e-pennypacker.com",
}

// allowedDomains override a block for something the business actually needs.
var allowedDomains = []string{
	"cdn.jpeterman-catalog.com",
	"login.kruger-industrial.com",
}

// clientWeight is one device's share of the sampled query traffic.
type clientWeight struct {
	address string
	weight  int
}

var queryClients = []clientWeight{
	{"10.20.10.12", 140}, {"10.20.10.13", 120}, {"10.20.10.11", 110}, {"10.20.10.14", 95},
	{"10.20.10.132", 88}, {"10.20.10.15", 70}, {"10.20.10.20", 65}, {"10.20.10.21", 52},
	{"10.20.10.16", 44}, {"10.20.10.145", 40}, {"10.20.10.151", 36}, {"10.20.10.158", 33},
	{"10.20.10.164", 30}, {"10.20.20.21", 48}, {"10.20.20.22", 45}, {"10.20.20.30", 38},
	{"10.20.20.31", 30}, {"10.20.20.32", 26}, {"10.20.20.118", 22}, {"10.20.20.126", 20},
	{"10.20.20.140", 14}, {"10.20.30.41", 26}, {"10.20.30.42", 24},
	{"10.20.30.44", 18}, {"10.20.30.45", 16}, {"10.20.30.112", 14}, {"10.20.30.119", 12},
	{"10.20.40.104", 20}, {"10.20.40.111", 15},
}

// queryDomain is one name in the sampled traffic, with the answer source that
// decides its response code, latency, and dashboard colour.
type queryDomain struct {
	name   string
	weight int
	source querylog.Source
}

var resolvedDomains = []queryDomain{
	{"vandelay.com", 90, querylog.SourceUpstream},
	{"www.vandelay.com", 78, querylog.SourceCache},
	{"mail.vandelay.com", 74, querylog.SourceCache},
	{"shipping.vandelay.com", 61, querylog.SourceCache},
	{"api.vandelay.com", 55, querylog.SourceUpstream},
	{"outlook.office365.com", 88, querylog.SourceCache},
	{"login.microsoftonline.com", 70, querylog.SourceCache},
	{"teams.microsoft.com", 52, querylog.SourceCache},
	{"slack.com", 46, querylog.SourceCache},
	{"github.com", 40, querylog.SourceUpstream},
	{"api.stripe.com", 34, querylog.SourceUpstream},
	{"s3.amazonaws.com", 44, querylog.SourceCache},
	{"cdn.jsdelivr.net", 30, querylog.SourceCache},
	{"portal.kruger-industrial.com", 38, querylog.SourceUpstream},
	{"edi.pendantpublishing.net", 27, querylog.SourceUpstream},
	{"orders.jpeterman-catalog.com", 33, querylog.SourceUpstream},
	{"tracking.usps.com", 42, querylog.SourceCache},
	{"api.dhl.com", 29, querylog.SourceUpstream},
	{"freight.maersk.com", 25, querylog.SourceUpstream},
	{"customs.cbp.gov", 18, querylog.SourceUpstream},
	{"ntp.ubnt.com", 36, querylog.SourceCache},
	{"time.apple.com", 30, querylog.SourceCache},
	{"updates.ui.com", 22, querylog.SourceCache},
}

var localDomains = []queryDomain{
	{"art-workstation.corp.vandelay.com", 34, querylog.SourceAuthoritative},
	{"george-laptop.corp.vandelay.com", 30, querylog.SourceAuthoritative},
	{"payroll-server.corp.vandelay.com", 46, querylog.SourceAuthoritative},
	{"backup-nas.corp.vandelay.com", 40, querylog.SourceAuthoritative},
	{"latex-press-01.warehouse.vandelay.com", 32, querylog.SourceAuthoritative},
	{"latex-press-02.warehouse.vandelay.com", 30, querylog.SourceAuthoritative},
	{"shipping-scanner.warehouse.vandelay.com", 26, querylog.SourceAuthoritative},
	{"dock-camera-01.iot.vandelay.com", 22, querylog.SourceAuthoritative},
	{"lobby-thermostat.iot.vandelay.com", 18, querylog.SourceAuthoritative},
}

var blockedTraffic = []queryDomain{
	{"pixel.bosco-analytics.com", 58, querylog.SourceBlocked},
	{"ads.kruger-industrial.com", 47, querylog.SourceBlocked},
	{"metrics.kramerica.com", 41, querylog.SourceBlocked},
	{"tracker.pendantpublishing.net", 36, querylog.SourceBlocked},
	{"telemetry.jpeterman-catalog.com", 31, querylog.SourceBlocked},
	{"click.moviefone-ads.net", 27, querylog.SourceBlocked},
	{"beacon.h-e-pennypacker.com", 22, querylog.SourceBlocked},
	{"adzone447.clickly.com", 34, querylog.SourceBlocked},
	{"track88.pixelnet.io", 29, querylog.SourceBlocked},
	{"beacon-admetric12.net", 24, querylog.SourceBlocked},
	{"stat.trackr-193.co", 19, querylog.SourceBlocked},
	{"imp2201.bidhub.cloud", 16, querylog.SourceBlocked},
}

// blockListSource is a real subscription URL paired with the number of entries
// the generated cache file should contain. Nothing is downloaded: the demo runs
// offline, so the cache files are synthesised at the real lists' sizes.
type blockListSource struct {
	Name   string
	URL    string
	Count  int
	Format string
	// Shared lists entries copied from lists generated before this one. Real
	// block lists draw on many of the same upstream feeds, and Insights has
	// nothing to say about overlap unless the demo lists overlap too.
	Shared []sharedEntries
	// Pinned entries are always in the list, so the blocked traffic the demo
	// seeds is attributed to real list contents rather than invented sources.
	Pinned []string
}

// sharedEntries is how many of a list's entries also appear in another list.
type sharedEntries struct {
	From  string
	Count int
}

var blockListSources = []blockListSource{
	{"OISD Big", "https://big.oisd.nl/", 182_000, "domains", nil,
		[]string{"adzone447.clickly.com", "track88.pixelnet.io", "beacon-admetric12.net", "stat.trackr-193.co"}},
	{"Steven Black Unified", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", 128_000, "hosts",
		[]sharedEntries{{From: "OISD Big", Count: 71_000}},
		[]string{"track88.pixelnet.io", "stat.trackr-193.co", "cdn.jpeterman-catalog.com", "telemetry.jpeterman-catalog.com"}},
	// Nearly everything in the smallest list is already covered by the other
	// two, which is the overlap finding the Insights screenshot shows.
	{"AdGuard DNS Filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", 54_000, "adblock",
		[]sharedEntries{{From: "OISD Big", Count: 38_500}, {From: "Steven Black Unified", Count: 15_150}},
		[]string{"adzone447.clickly.com", "imp2201.bidhub.cloud"}},
}

// pastBlock is a name that was blocked before an operator allowed it. Its
// history is seeded days back so Insights can show the correction as evidence.
type pastBlock struct {
	name    string
	clients []clientWeight
	count   int
	// from and to bound the days ago the blocked queries were spread across.
	from, to int
}

var pastBlocks = []pastBlock{{
	name:    "cdn.jpeterman-catalog.com",
	clients: []clientWeight{{"10.20.10.132", 6}, {"10.20.10.145", 3}, {"10.20.20.21", 2}},
	count:   143, from: 12, to: 9,
}}

// clusterNode describes one Sable server in the demo deployment.
type clusterNode struct {
	Name string
	// Addresses are the DNS service addresses the node advertises to operators.
	// They are descriptive only, which is why they can name Vandelay's real
	// resolver addresses while the nodes actually talk over loopback.
	Addresses []string
}

var clusterNodes = []clusterNode{
	{Name: "ns1-queens", Addresses: []string{"10.20.10.53"}},
	{Name: "ns2-queens", Addresses: []string{"10.20.10.54"}},
	{Name: "ns3-latham", Addresses: []string{"10.20.20.53"}},
}

const (
	clusterDomain    = "vandelay.com"
	operatorUsername = "art.vandelay"
	operatorName     = "Art Vandelay"
	operatorEmail    = "art@vandelay.com"
	// The demo database is thrown away on every run, so this password is a
	// fixture rather than a secret.
	operatorPassword = "LatexImporter2026!"
)

// deviceStory scripts one device's history so Insights has something true to
// say about it: a device that went quiet, one that got busy, one that is new,
// and one that started talking to new places.
type deviceStory struct {
	address string
	domains []string
	// perDay queries are spread across each day from daysFrom to daysTo ago,
	// and recent more across the last day.
	perDay           int
	daysFrom, daysTo int
	recent           int
	// established devices share the office's long history, so only their
	// recent change is news.
	established bool
}

var deviceStories = []deviceStory{
	// dock-camera-02 streamed steadily all week and stopped yesterday.
	{address: "10.20.30.43", domains: []string{"stream.dockcam-cloud.net", "ntp.ubnt.com"}, perDay: 160, daysFrom: 9, daysTo: 1, established: true},
	// The breakroom display normally checks in a little; today it is looping.
	{address: "10.20.30.44", domains: []string{"api.breakroom-signage.io", "cdn.breakroom-signage.io"}, perDay: 110, daysFrom: 9, daysTo: 1, recent: 1_450, established: true},
	// The doorbell was installed two days ago.
	{address: "10.20.30.46", domains: []string{"events.ringbell-cloud.com", "video.ringbell-cloud.com", "time.apple.com"}, perDay: 120, daysFrom: 2, daysTo: 0},
}

// georgeNewDomains are the collaboration tools George started using this week.
var georgeNewDomains = []string{
	"zoom.us", "us02web.zoom.us", "api.zoom.us", "figma.com", "www.figma.com", "static.figma.com",
	"api.notion.com", "www.notion.so", "msgstore.www.notion.so", "calendly.com", "assets.calendly.com",
	"api.loom.com", "cdn.loom.com", "app.asana.com", "api.asana.com", "miro.com", "api.miro.com",
	"linear.app", "api.linear.app", "cdn.linear.app", "docusign.net", "account.docusign.com",
}
