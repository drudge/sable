package web

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/config"
)

// newDHCPSetupServer is a console with DHCP off and no scopes, on a host with
// one network.
func newDHCPSetupServer(t *testing.T) (*Server, *editableTestConfiguration, *testDHCPController) {
	t.Helper()
	server, configuration, controller := newDHCPConsoleServer(t)
	configuration.snapshot.Config.DHCP = config.DHCP{}
	controller.networks = []DHCPNetwork{{Interface: "eth0", Prefix: netip.MustParsePrefix("192.0.2.10/24"),
		Gateway: netip.MustParseAddr("192.0.2.1")}}
	return server, configuration, controller
}

// The setup empty state lists the networks this server is on, each with an
// Add Scope dialog filled in from it.
func TestDHCPConsoleSetupOffersHostNetworks(t *testing.T) {
	t.Parallel()
	server, _, _ := newDHCPSetupServer(t)
	response := dhcpConsoleRequest(t, server, http.MethodGet, "/dhcp", nil)
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("GET /dhcp = %d: %s", response.Code, body)
	}
	for _, want := range []string{"eth0", "192.0.2.10", `data-dialog-open="dhcp-scope-new-1"`, `id="dhcp-scope-new-1"`,
		`value="192.0.2.0/24"`, `value="192.0.2.100"`, `value="192.0.2.199"`, `value="192.0.2.1"`, `value="lan"`} {
		if !strings.Contains(body, want) {
			t.Errorf("setup lacks %q", want)
		}
	}
}

func TestDHCPSuggestedScopeAvoidsTheServersAddress(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ prefix, address, gateway, start, end, router string }{
		{"192.0.2.0/24", "192.0.2.10", "192.0.2.1", "192.0.2.100", "192.0.2.199", "192.0.2.1"},
		{"192.0.2.0/24", "192.0.2.150", "", "192.0.2.151", "192.0.2.199", ""},
		{"10.0.0.0/16", "10.0.0.2", "10.0.0.1", "10.0.0.100", "10.0.0.199", "10.0.0.1"},
		{"192.0.2.0/26", "192.0.2.1", "198.51.100.1", "192.0.2.32", "192.0.2.62", ""},
	} {
		bits := netip.MustParsePrefix(test.prefix).Bits()
		network := DHCPNetwork{Interface: "eth0", Prefix: netip.PrefixFrom(netip.MustParseAddr(test.address), bits)}
		if test.gateway != "" {
			network.Gateway = netip.MustParseAddr(test.gateway)
		}
		scope := dhcpSuggestedScope(network, "lan")
		if scope.Subnet != network.Prefix.Masked().String() || len(scope.Ranges) != 1 ||
			scope.Ranges[0] != (config.DHCPRange{Start: test.start, End: test.end}) || scope.Router != test.router {
			t.Errorf("dhcpSuggestedScope(%s, %s) = %+v", test.prefix, test.address, scope)
		}
	}
}

// Turn On probes for another DHCP server first and refuses while one
// answers, naming it; Turn On Anyway enables it regardless (docs/design/dhcp.md §4).
func TestDHCPConsoleTurnOnRefusesWhileAnotherServerAnswers(t *testing.T) {
	t.Parallel()
	server, configuration, controller := newDHCPConsoleServer(t)
	configuration.snapshot.Config.DHCP.Enabled = false
	controller.others = []DHCPOtherServer{{Interface: "eth0", Server: netip.MustParseAddr("192.0.2.1"), Offered: netip.MustParseAddr("192.0.2.57")}}

	response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/enabled", url.Values{"enabled": {"true"}})
	body := response.Body.String()
	if configuration.snapshot.Config.DHCP.Enabled || controller.probes != 1 {
		t.Fatalf("Turn On with another server answering: enabled %v, probes %d; want refused after one probe",
			configuration.snapshot.Config.DHCP.Enabled, controller.probes)
	}
	for _, want := range []string{"192.0.2.1", "eth0", "Turn On Anyway", "force"} {
		if !strings.Contains(body, want) {
			t.Errorf("refusal lacks %q: %s", want, body)
		}
	}

	response = dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/enabled", url.Values{"enabled": {"true"}, "force": {"true"}})
	if response.Code != http.StatusOK || !configuration.snapshot.Config.DHCP.Enabled || controller.probes != 1 {
		t.Fatalf("Turn On Anyway = %d, enabled %v, probes %d: %s", response.Code, configuration.snapshot.Config.DHCP.Enabled, controller.probes, response.Body.String())
	}

	controller.others = nil
	configuration.snapshot.Config.DHCP.Enabled = false
	response = dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/enabled", url.Values{"enabled": {"true"}})
	if !configuration.snapshot.Config.DHCP.Enabled || !strings.Contains(response.Body.String(), "Turned DHCP on") {
		t.Fatalf("Turn On with nothing else answering = %d: %s", response.Code, response.Body.String())
	}
}

func TestDHCPAPIProbesAndListsNetworks(t *testing.T) {
	t.Parallel()
	server, configuration, controller := newDHCPSetupServer(t)
	controller.others = []DHCPOtherServer{{Interface: "eth0", Server: netip.MustParseAddr("192.0.2.1"), Offered: netip.MustParseAddr("192.0.2.57")}}

	response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPost, "/api/v1/dhcp/probe", "")
	if response.Code != http.StatusUnprocessableEntity || controller.probes != 0 {
		t.Fatalf("probe with no scope = %d (probes %d); want 422 before probing", response.Code, controller.probes)
	}
	configuration.snapshot.Config.DHCP.Scopes = []config.DHCPScope{{ID: "lan", Subnet: "192.0.2.0/24"}}
	response = dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPost, "/api/v1/dhcp/probe", "")
	var probed struct {
		Others []DHCPOtherServer `json:"others"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &probed) != nil || len(probed.Others) != 1 || probed.Others[0].Server.String() != "192.0.2.1" {
		t.Fatalf("POST /api/v1/dhcp/probe = %d %s", response.Code, response.Body)
	}
	configuration.snapshot.Config.DHCP.Scopes = nil
	response = dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodGet, "/api/v1/dhcp/networks", "")
	var listed struct {
		Networks []struct {
			Interface string           `json:"interface"`
			Prefix    string           `json:"prefix"`
			Suggested config.DHCPScope `json:"suggested"`
		} `json:"networks"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &listed) != nil || len(listed.Networks) != 1 ||
		listed.Networks[0].Prefix != "192.0.2.10/24" || listed.Networks[0].Suggested.Subnet != "192.0.2.0/24" {
		t.Fatalf("GET /api/v1/dhcp/networks = %d %s", response.Code, response.Body)
	}
}
