package unifi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	networkFixture = `{"data":[
		{"_id":"net-lan","name":"Default","purpose":"corporate","ip_subnet":"192.168.1.1/24","dhcpd_enabled":true,"dhcpd_dns_enabled":false,"dhcpd_dns_1":"9.9.9.9"},
		{"_id":"net-iot","name":"IoT VLAN","purpose":"vlan-only","ip_subnet":"192.168.30.1/24","dhcpd_enabled":true,"dhcpd_dns_enabled":true,"dhcpd_dns_1":"1.1.1.1","dhcpd_dns_2":"","dhcpd_dns_3":"bogus","dhcpd_dns_4":"192.168.1.53"},
		{"_id":"net-off","name":"Disabled","enabled":false,"ip_subnet":"192.168.9.1/24"},
		{"_id":"","name":"Nameless","ip_subnet":"192.168.8.1/24"},
		{"_id":"net-none","name":"No Subnet","purpose":"vlan-only"},
		{"_id":"net-vpn","name":"VPN Client","purpose":"vpn-client","ip_subnet":"10.8.0.5/32"}
	]}`
	reservationFixture = `{"data":[
		{"mac":"aa:bb:cc:dd:ee:01","name":"Printer","fixed_ip":"192.168.1.10","use_fixedip":true,"network_id":"net-lan"},
		{"mac":"aa:bb:cc:dd:ee:02","name":"Ignored","fixed_ip":"192.168.1.11","use_fixedip":false,"network_id":"net-lan"}
	]}`
	activeFixture = `{"data":[
		{"mac":"aa:bb:cc:dd:ee:01","name":"Printer","ip":"192.168.1.99","network_id":"net-lan","ipv6_addresses":["2001:db8:0:1:aa:bb:cc:1","fe80::9"]},
		{"mac":"aa:bb:cc:dd:ee:03","hostname":"Laptop","ip":"192.168.30.50","network_id":"net-iot","ipv6_addresses":["fd00::5","fe80::1","2001:db8:0:1:1:2:3:4","2001:db8:0:1:1:2:3:4","::ffff:192.0.2.1","ff02::1","::","bogus"]},
		{"mac":"aa:bb:cc:dd:ee:04","ip":"192.168.30.51","network_id":"net-iot","last_seen":1790000000,"uptime":"86400","tx_bytes":1.5e6,"rx_bytes":500000,"is_wired":false},
		{"mac":"AA:BB:CC:DD:EE:06","ip":"192.168.1.60","is_wired":true,"uptime":7200,"tx_bytes":10,"rx_bytes":10,"wired-tx_bytes":4000,"wired-rx_bytes":6000,"last_seen":"soon"},
		{"mac":"aa:bb:cc:dd:ee:05","name":"Broken","ip":"not-an-address","network_id":"net-iot"}
	]}`
	deviceFixture = `{"data":[
		{"mac":"AA:BB:CC:00:00:01","name":"Office AP","ip":"192.168.1.2","model":"U7PRO","type":"uap","shortname":"U7PRO"},
		{"mac":"aa:bb:cc:00:00:04","name":"UPS Tower","ip":"192.168.1.4","model":"USWDA23","type":"usw","shortname":"UPS23"},
		{"mac":"aa:bb:cc:00:00:05","name":"Home","ip":"192.168.1.1","model":"UDMA6A8","type":"udm","shortname":"UCGF"},
		{"mac":"aa:bb:cc:00:00:02","ip":"192.168.1.3","model":"USWED35"},
		{"mac":"aa:bb:cc:00:00:03","name":"Pending","ip":"","model":"USWED35"}
	]}`
)

func fixtureHandler(t *testing.T, authorize func(*http.Request) bool) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	serve := func(body string) http.HandlerFunc {
		return func(writer http.ResponseWriter, request *http.Request) {
			if !authorize(request) {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(body))
		}
	}
	mux.Handle("GET /proxy/network/api/s/default/rest/networkconf", serve(networkFixture))
	mux.Handle("GET /proxy/network/api/s/default/rest/user", serve(reservationFixture))
	mux.Handle("GET /proxy/network/api/s/default/stat/sta", serve(activeFixture))
	mux.Handle("GET /proxy/network/api/s/default/stat/device", serve(deviceFixture))
	return mux
}

func newTestClient(t *testing.T, server *httptest.Server, credentials Credentials) *Client {
	t.Helper()
	client, err := New(Options{
		ControllerURL:      server.URL,
		Site:               "default",
		Credentials:        credentials,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func TestInventoryWithAPIKey(t *testing.T) {
	server := httptest.NewTLSServer(fixtureHandler(t, func(request *http.Request) bool {
		return request.Header.Get("X-API-KEY") == "secret-key"
	}))
	defer server.Close()

	inventory, err := newTestClient(t, server, Credentials{APIKey: "secret-key"}).Inventory(t.Context())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(inventory.Networks) != 2 {
		t.Fatalf("read %d networks, want 2 (disabled, nameless, subnetless, and /32 VPN networks are skipped)", len(inventory.Networks))
	}
	for _, id := range []string{"net-none", "net-vpn"} {
		if _, found := inventory.NetworkByID(id); found {
			t.Fatalf("network %s has no addressable subnet but appears in the inventory", id)
		}
	}
	iot, found := inventory.NetworkByID("net-iot")
	if !found {
		t.Fatal("IoT network missing from inventory")
	}
	if iot.Slug != "iot-vlan" {
		t.Fatalf("IoT slug = %q, want %q", iot.Slug, "iot-vlan")
	}
	if len(iot.IPv4Subnets()) != 1 || iot.IPv4Subnets()[0] != netip.MustParsePrefix("192.168.30.0/24") {
		t.Fatalf("IoT subnets = %v, want the masked 192.168.30.0/24", iot.Subnets)
	}
	if len(inventory.Hosts) != 2 {
		t.Fatalf("read %d hosts, want 2 (nameless and malformed clients are skipped): %+v", len(inventory.Hosts), inventory.Hosts)
	}
	counts := inventory.HostCounts()
	if counts["net-lan"] != 1 || counts["net-iot"] != 1 {
		t.Fatalf("host counts = %v, want one per network", counts)
	}
}

func TestInventoryPrefersReservationOverActiveLease(t *testing.T) {
	server := httptest.NewTLSServer(fixtureHandler(t, func(*http.Request) bool { return true }))
	defer server.Close()

	inventory, err := newTestClient(t, server, Credentials{APIKey: "secret-key"}).Inventory(t.Context())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	var printer Host
	for _, host := range inventory.Hosts {
		if host.MAC == "aa:bb:cc:dd:ee:01" {
			printer = host
		}
	}
	if !printer.Reserved {
		t.Fatal("printer was not marked as a reservation")
	}
	if printer.Address != netip.MustParseAddr("192.168.1.10") {
		t.Fatalf("printer address = %s, want the reserved 192.168.1.10", printer.Address)
	}
}

// The controller reports every IPv6 address it has seen on a client. Only the
// global and unique-local ones name anything, and a reservation carries none
// at all, so the merged host must keep the active lease's filtered set.
func TestInventoryFiltersObservedIPv6(t *testing.T) {
	server := httptest.NewTLSServer(fixtureHandler(t, func(*http.Request) bool { return true }))
	defer server.Close()

	inventory, err := newTestClient(t, server, Credentials{APIKey: "secret-key"}).Inventory(t.Context())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	byMAC := make(map[string]Host, len(inventory.Hosts))
	for _, host := range inventory.Hosts {
		byMAC[host.MAC] = host
	}
	laptop := []netip.Addr{netip.MustParseAddr("2001:db8:0:1:1:2:3:4"), netip.MustParseAddr("fd00::5")}
	if !slices.Equal(byMAC["aa:bb:cc:dd:ee:03"].IPv6, laptop) {
		t.Fatalf("laptop IPv6 = %v, want the sorted global and unique-local addresses %v", byMAC["aa:bb:cc:dd:ee:03"].IPv6, laptop)
	}
	printer := []netip.Addr{netip.MustParseAddr("2001:db8:0:1:aa:bb:cc:1")}
	if !slices.Equal(byMAC["aa:bb:cc:dd:ee:01"].IPv6, printer) {
		t.Fatalf("printer IPv6 = %v, want the active lease's %v inherited by the winning reservation", byMAC["aa:bb:cc:dd:ee:01"].IPv6, printer)
	}
}

// The controller's own switches and access points are not clients, so only
// its device list names them. They stay out of Hosts, which the sync
// publishes, and a device with no name or no address names nothing.
func TestInventoryReadsGearApartFromHosts(t *testing.T) {
	server := httptest.NewTLSServer(fixtureHandler(t, func(*http.Request) bool { return true }))
	defer server.Close()

	inventory, err := newTestClient(t, server, Credentials{APIKey: "secret-key"}).Inventory(t.Context())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	want := []Host{
		{MAC: "aa:bb:cc:00:00:01", Hostname: "Office AP", Address: netip.MustParseAddr("192.168.1.2"), Kind: "access point"},
		{MAC: "aa:bb:cc:00:00:04", Hostname: "UPS Tower", Address: netip.MustParseAddr("192.168.1.4"), Kind: "ups"},
		{MAC: "aa:bb:cc:00:00:05", Hostname: "Home", Address: netip.MustParseAddr("192.168.1.1"), Kind: "gateway"},
	}
	if !slices.EqualFunc(inventory.Gear, want, func(left, right Host) bool {
		return left.MAC == right.MAC && left.Hostname == right.Hostname && left.Address == right.Address && left.Kind == right.Kind
	}) {
		t.Fatalf("gear = %+v, want %+v", inventory.Gear, want)
	}
	for _, host := range inventory.Hosts {
		if host.MAC == "aa:bb:cc:00:00:01" {
			t.Fatalf("gear leaked into the published hosts: %+v", host)
		}
	}
	// A UPS is filed under switches but carries power, not traffic.
	types := []string{inventory.Gear[0].DeviceType(), inventory.Gear[1].DeviceType(), inventory.Gear[2].DeviceType()}
	if !slices.Equal(types, []string{"network", "ups", "network"}) {
		t.Fatalf("device types = %q, want the access point and gateway as network and the UPS as a UPS", types)
	}
}

// A controller that will not list its devices still has clients to publish.
func TestInventoryWithoutGearStillReadsHosts(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("GET /proxy/network/api/s/default/stat/device", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	mux.Handle("/", fixtureHandler(t, func(*http.Request) bool { return true }))
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	inventory, err := newTestClient(t, server, Credentials{APIKey: "secret-key"}).Inventory(t.Context())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(inventory.Gear) != 0 || len(inventory.Hosts) != 2 {
		t.Fatalf("gear = %+v, hosts = %d; want no gear and both hosts", inventory.Gear, len(inventory.Hosts))
	}
}

func TestInventoryFallsBackToLocalAccountLogin(t *testing.T) {
	var loggedIn atomic.Bool
	var logins atomic.Int32
	mux := http.NewServeMux()
	mux.Handle("/proxy/network/", fixtureHandler(t, func(request *http.Request) bool {
		if loggedIn.Load() {
			return true
		}
		return request.Header.Get("X-API-KEY") == "good-key"
	}))
	mux.HandleFunc("POST /api/auth/login", func(writer http.ResponseWriter, request *http.Request) {
		logins.Add(1)
		body := make([]byte, 256)
		read, _ := request.Body.Read(body)
		if !strings.Contains(string(body[:read]), `"password":"correct-horse"`) {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		loggedIn.Store(true)
		writer.Header().Set("X-CSRF-Token", "csrf-value")
		http.SetCookie(writer, &http.Cookie{Name: "TOKEN", Value: "session"})
		writer.WriteHeader(http.StatusOK)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newTestClient(t, server, Credentials{APIKey: "stale-key", Username: "admin", Password: "correct-horse"})
	inventory, err := client.Inventory(t.Context())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(inventory.Networks) == 0 {
		t.Fatal("fallback login produced no networks")
	}
	if logins.Load() != 1 {
		t.Fatalf("logged in %d times, want exactly 1", logins.Load())
	}
}

func TestInventoryReportsUnauthorized(t *testing.T) {
	server := httptest.NewTLSServer(fixtureHandler(t, func(*http.Request) bool { return false }))
	defer server.Close()

	_, err := newTestClient(t, server, Credentials{APIKey: "wrong-key"}).Inventory(t.Context())
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Inventory error = %v, want ErrUnauthorized", err)
	}
}

func TestInventoryDoesNotRetryLoginForever(t *testing.T) {
	var logins atomic.Int32
	mux := http.NewServeMux()
	mux.Handle("/proxy/network/", fixtureHandler(t, func(*http.Request) bool { return false }))
	mux.HandleFunc("POST /api/auth/login", func(writer http.ResponseWriter, _ *http.Request) {
		logins.Add(1)
		writer.WriteHeader(http.StatusOK)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	client := newTestClient(t, server, Credentials{Username: "admin", Password: "bad"})
	if _, err := client.Inventory(t.Context()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Inventory error = %v, want ErrUnauthorized", err)
	}
	if logins.Load() != 1 {
		t.Fatalf("logged in %d times, want exactly 1", logins.Load())
	}
}

func TestNewRejectsUnusableOptions(t *testing.T) {
	cases := []struct {
		name    string
		options Options
	}{
		{name: "missing URL", options: Options{Credentials: Credentials{APIKey: "k"}}},
		{name: "missing credentials", options: Options{ControllerURL: "https://unifi.example"}},
		{name: "unsupported scheme", options: Options{ControllerURL: "ftp://unifi.example", Credentials: Credentials{APIKey: "k"}}},
		{name: "missing CA file", options: Options{ControllerURL: "https://unifi.example", Credentials: Credentials{APIKey: "k"}, CAFile: "/nope/ca.pem"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := New(testCase.options); err == nil {
				t.Fatal("New succeeded, want an error")
			}
		})
	}
}

func TestNewDefaultsSchemeAndSite(t *testing.T) {
	client, err := New(Options{ControllerURL: "unifi.example", Credentials: Credentials{APIKey: "k"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client.baseURL.Scheme != "https" || client.site != "default" {
		t.Fatalf("client defaulted to %s and site %q", client.baseURL, client.site)
	}
}

// unplacedFixture mirrors what a controller really returns: reservations
// mostly omit network_id and describe their network some other way, or not at
// all.
const unplacedFixture = `{"data":[
	{"mac":"aa:bb:cc:dd:ee:11","name":"Last Seen","fixed_ip":"192.168.1.20","use_fixedip":true,"last_connection_network_id":"net-lan"},
	{"mac":"aa:bb:cc:dd:ee:12","name":"Pinned","fixed_ip":"192.168.30.20","use_fixedip":true,"virtual_network_override_enabled":true,"virtual_network_override_id":"net-iot","last_connection_network_id":"net-lan"},
	{"mac":"aa:bb:cc:dd:ee:13","name":"Silent","fixed_ip":"192.168.30.21","use_fixedip":true},
	{"mac":"aa:bb:cc:dd:ee:14","name":"Server","fixed_ip":"192.168.1.21","use_fixedip":true},
	{"mac":"aa:bb:cc:dd:ee:15","name":"Stranger","fixed_ip":"172.16.4.9","use_fixedip":true},
	{"mac":"aa:bb:cc:dd:ee:16","name":"Moved","fixed_ip":"192.168.30.22","use_fixedip":true,"network_id":"net-lan"},
	{"mac":"aa:bb:cc:dd:ee:17","name":"Routed","fixed_ip":"172.16.4.10","use_fixedip":true,"network_id":"net-lan"}
]}`

const unplacedActiveFixture = `{"data":[
	{"mac":"aa:bb:cc:dd:ee:14","name":"Server","ip":"192.168.1.21","network_id":"net-lan"}
]}`

func TestInventoryPlacesReservationsWithoutNetworkID(t *testing.T) {
	mux := http.NewServeMux()
	serve := func(body string) http.HandlerFunc {
		return func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(body))
		}
	}
	mux.Handle("GET /proxy/network/api/s/default/rest/networkconf", serve(networkFixture))
	mux.Handle("GET /proxy/network/api/s/default/rest/user", serve(unplacedFixture))
	mux.Handle("GET /proxy/network/api/s/default/stat/sta", serve(unplacedActiveFixture))
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	inventory, err := newTestClient(t, server, Credentials{APIKey: "secret-key"}).Inventory(t.Context())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	networks := make(map[string]string, len(inventory.Hosts))
	for _, host := range inventory.Hosts {
		networks[host.MAC] = host.NetworkID
	}
	for _, testCase := range []struct {
		mac     string
		network string
		reason  string
	}{
		{"aa:bb:cc:dd:ee:11", "net-lan", "the last network the controller saw it on"},
		{"aa:bb:cc:dd:ee:12", "net-iot", "the network it is pinned to, not the one it last used"},
		{"aa:bb:cc:dd:ee:13", "net-iot", "the network whose subnet covers its address"},
		{"aa:bb:cc:dd:ee:14", "net-lan", "the network its own active lease reported"},
		{"aa:bb:cc:dd:ee:15", "", "no network covers its address"},
		{"aa:bb:cc:dd:ee:16", "net-iot", "the subnet holding its address, not the network the controller named"},
		{"aa:bb:cc:dd:ee:17", "net-lan", "no subnet holds its address, so the controller's answer stands"},
	} {
		if networks[testCase.mac] != testCase.network {
			t.Errorf("host %s is on network %q, want %q: %s", testCase.mac, networks[testCase.mac], testCase.network, testCase.reason)
		}
	}
	counts := inventory.HostCounts()
	if counts["net-lan"] != 3 || counts["net-iot"] != 3 {
		t.Fatalf("host counts = %v, want three hosts on each mapped network", counts)
	}
}

// A UNAS joins as a client, and its product line says it is storage. The
// reservation that wins the merge keeps what the active lease knew.
func TestUniFiDriveClientsAreStorage(t *testing.T) {
	t.Parallel()
	active, ok := clientPayload{MAC: "a4:f8:ff:7e:1f:aa", Hostname: "Home-UNAS-4", IP: "192.168.1.14", ProductLine: "unifi-drive"}.host("192.168.1.14", false)
	if !ok || active.DeviceType() != "storage" {
		t.Fatalf("active UNAS = %+v", active)
	}
	reserved, _ := clientPayload{MAC: "a4:f8:ff:7e:1f:aa", Name: "Home-UNAS-4", FixedIP: "192.168.1.14", UseFixedIP: true}.host("192.168.1.14", true)
	merged := mergeHosts([]Host{reserved}, []Host{active})
	if len(merged) != 1 || !merged[0].Reserved || merged[0].DeviceType() != "storage" {
		t.Fatalf("merged = %+v", merged)
	}
	if printer, _ := (clientPayload{MAC: "aa:bb:cc:dd:ee:01", Name: "Printer"}).host("192.168.1.10", false); printer.DeviceType() != "" {
		t.Fatalf("an ordinary client got type %q", printer.DeviceType())
	}
}

// The controller's fingerprint suggests a type with its confidence, and a
// type the operator chose in UniFi carries through, except for a broad
// category that covers too many kinds of device to stand for a choice.
func TestClientFingerprintsSuggestTypes(t *testing.T) {
	t.Parallel()
	category := func(value int) *int { return &value }
	for _, test := range []struct {
		name       string
		payload    clientPayload
		kind       string
		confidence int
		set        bool
	}{
		{"a phone", clientPayload{DeviceCategory: category(44), Confidence: 30}, "phone", 30, false},
		{"a chosen server", clientPayload{DeviceCategory: category(182), Confidence: 48, FingerprintOverride: true}, "server", 48, true},
		{"a broad choice", clientPayload{DeviceCategory: category(51), Confidence: 99, FingerprintOverride: true}, "smart-home", 99, false},
		{"an unknown category", clientPayload{DeviceCategory: category(119), Confidence: 99, FingerprintOverride: true}, "", 0, false},
		{"no fingerprint", clientPayload{Confidence: 99}, "", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			test.payload.MAC, test.payload.Hostname = "aa:bb:cc:dd:ee:10", "device"
			host, ok := test.payload.host("192.168.1.20", false)
			if !ok || host.Fingerprint != test.kind || host.FingerprintConfidence != test.confidence || host.FingerprintSet != test.set {
				t.Fatalf("host = %+v", host)
			}
		})
	}
}

// Every connected client is a station, named or not, with the traffic the
// controller counted since it connected. A counter written as a float or a
// string still reads, one that cannot be read is zero, and a client without
// a usable address is left out.
func TestInventoryReadsStationsWithTraffic(t *testing.T) {
	server := httptest.NewTLSServer(fixtureHandler(t, func(*http.Request) bool { return true }))
	defer server.Close()

	inventory, err := newTestClient(t, server, Credentials{APIKey: "secret-key"}).Inventory(t.Context())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	byMAC := make(map[string]Station, len(inventory.Stations))
	for _, station := range inventory.Stations {
		byMAC[station.MAC] = station
	}
	if len(inventory.Stations) != 4 {
		t.Fatalf("read %d stations, want 4 (the malformed client is left out): %+v", len(inventory.Stations), inventory.Stations)
	}
	nameless := byMAC["aa:bb:cc:dd:ee:04"]
	if nameless.Name != "" || nameless.NetworkID != "net-iot" || nameless.Uptime != 24*time.Hour || nameless.Bytes != 2_000_000 {
		t.Fatalf("nameless station = %+v, want no name on net-iot, up a day, 2 MB moved", nameless)
	}
	if !nameless.LastSeen.Equal(time.Unix(1790000000, 0)) {
		t.Fatalf("nameless last seen = %s, want the controller's", nameless.LastSeen)
	}
	wired := byMAC["aa:bb:cc:dd:ee:06"]
	if !wired.Wired || wired.Bytes != 10_000 || !wired.LastSeen.IsZero() || wired.NetworkID != "net-lan" {
		t.Fatalf("wired station = %+v, want its wired counters, no readable last seen, and the network covering its address", wired)
	}
	laptop := byMAC["aa:bb:cc:dd:ee:03"]
	if laptop.Name != "Laptop" || len(laptop.Addresses()) != 3 {
		t.Fatalf("laptop station = %+v, want its hostname and one IPv4 plus two IPv6 addresses", laptop)
	}
}

// A network's DHCP hands out the gateway unless the operator listed DNS
// servers, and says nothing Sable can trust when the controller does not run
// its DHCP.
func TestNetworksReadHandedOutDNS(t *testing.T) {
	server := httptest.NewTLSServer(fixtureHandler(t, func(*http.Request) bool { return true }))
	defer server.Close()

	inventory, err := newTestClient(t, server, Credentials{APIKey: "secret-key"}).Inventory(t.Context())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	lan, _ := inventory.NetworkByID("net-lan")
	servers, known := lan.HandedOutDNS()
	if !known || !slices.Equal(servers, []netip.Addr{netip.MustParseAddr("192.168.1.1")}) {
		t.Fatalf("default network hands out %v (known %t), want its gateway 192.168.1.1", servers, known)
	}
	iot, _ := inventory.NetworkByID("net-iot")
	servers, known = iot.HandedOutDNS()
	want := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("192.168.1.53")}
	if !known || !slices.Equal(servers, want) {
		t.Fatalf("IoT network hands out %v (known %t), want %v", servers, known, want)
	}
	if _, known := (Network{Gateway: netip.MustParseAddr("10.0.0.1")}).HandedOutDNS(); known {
		t.Fatal("a network whose DHCP the controller does not run claims to know its DNS servers")
	}
}

// A reservation left behind for a retired machine drops out while another
// connected device holds its address, so the old name is neither published
// at the new machine's address nor tied to its hardware. A reservation whose
// address is free, or whose own device is connected, stays.
func TestConnectedDevicesDisplaceStaleReservations(t *testing.T) {
	t.Parallel()
	reserve := func(mac, name, address string) Host {
		host, _ := clientPayload{MAC: mac, Hostname: name, FixedIP: address, UseFixedIP: true}.host(address, true)
		return host
	}
	retired := reserve("bc:24:11:c9:8b:08", "shuttle", "10.0.7.13")
	idle := reserve("bc:24:11:9c:da:78", "backrest", "10.0.7.9")
	moved := reserve("bc:24:11:14:31:8a", "homeassistant", "10.0.7.11")
	current, _ := clientPayload{MAC: "bc:24:11:d2:4d:7e", Name: "ltm-backup-relay", IP: "10.0.7.13"}.host("10.0.7.13", false)
	connected := stations([]clientPayload{
		{MAC: "bc:24:11:d2:4d:7e", Name: "ltm-backup-relay", IP: "10.0.7.13"},
		// The reserved device itself is connected, on a lease it got before
		// the reservation took, while something else briefly holds .11.
		{MAC: "bc:24:11:14:31:8a", IP: "10.0.7.201"},
		{MAC: "aa:bb:cc:00:00:01", IP: "10.0.7.11"},
	})
	hosts := withoutDisplacedReservations(mergeHosts([]Host{retired, idle, moved}, []Host{current}), connected)
	var names []string
	for _, host := range hosts {
		names = append(names, host.Hostname+"@"+host.Address.String())
	}
	if got := strings.Join(names, ","); got != "backrest@10.0.7.9,homeassistant@10.0.7.11,ltm-backup-relay@10.0.7.13" {
		t.Fatalf("hosts = %s", got)
	}
}
