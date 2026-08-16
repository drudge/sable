package unifi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	networkFixture = `{"data":[
		{"_id":"net-lan","name":"Default","purpose":"corporate","ip_subnet":"192.168.1.1/24"},
		{"_id":"net-iot","name":"IoT VLAN","purpose":"vlan-only","ip_subnet":"192.168.30.1/24"},
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
		{"mac":"aa:bb:cc:dd:ee:01","name":"Printer","ip":"192.168.1.99","network_id":"net-lan"},
		{"mac":"aa:bb:cc:dd:ee:03","hostname":"Laptop","ip":"192.168.30.50","network_id":"net-iot"},
		{"mac":"aa:bb:cc:dd:ee:04","ip":"192.168.30.51","network_id":"net-iot"},
		{"mac":"aa:bb:cc:dd:ee:05","name":"Broken","ip":"not-an-address","network_id":"net-iot"}
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
