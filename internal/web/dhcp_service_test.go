package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
)

// testDHCPController keeps leases in memory and removes them as the engine
// does: the row stays, released.
type testDHCPController struct {
	mutex    sync.Mutex
	leases   []store.DHCPLease
	networks []DHCPNetwork
	others   []DHCPOtherServer
	probes   int
}

func (controller *testDHCPController) Networks() ([]DHCPNetwork, error) {
	return controller.networks, nil
}

func (controller *testDHCPController) FindOthers(context.Context, config.DHCP) ([]DHCPOtherServer, error) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	controller.probes++
	return controller.others, nil
}

func (controller *testDHCPController) Status() DHCPStatus {
	return DHCPStatus{Enabled: true, Serving: true, Received: 12, Replied: 10}
}

func (controller *testDHCPController) Leases(context.Context) ([]store.DHCPLease, error) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	return append([]store.DHCPLease(nil), controller.leases...), nil
}

func (controller *testDHCPController) RemoveLease(_ context.Context, address netip.Addr) (bool, error) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	for index := range controller.leases {
		lease := &controller.leases[index]
		if lease.Address == address && dhcpRowHolds(*lease, time.Now()) {
			lease.State, lease.ExpiresAt = store.DHCPLeaseReleased, time.Now()
			return true, nil
		}
	}
	return false, nil
}

func newDHCPTestServer(t *testing.T) (*Server, *editableTestConfiguration, *testDHCPController) {
	t.Helper()
	server, configuration := newMCPTestServer(t)
	configuration.snapshot.Config.MCP.Tools = append(configuration.snapshot.Config.MCP.Tools, "list_dhcp_leases", "set_dhcp_reservation", "remove_dhcp_reservation", "get_dhcp_status")
	configuration.snapshot.Config.DHCP = config.DHCP{Enabled: true, Scopes: []config.DHCPScope{{
		ID: "lan", Name: "LAN", Subnet: "192.0.2.0/24", Router: "192.0.2.1", Domain: "home.test",
		Ranges:       []config.DHCPRange{{Start: "192.0.2.100", End: "192.0.2.199"}},
		Reservations: []config.DHCPReservation{{MAC: "00:11:22:33:44:01", Address: "192.0.2.10", Name: "printer"}},
	}}}
	now := time.Now()
	lease := func(address, mac, label string, state store.DHCPLeaseState, expires time.Time) store.DHCPLease {
		return store.DHCPLease{
			NodeID: "node-a", Address: netip.MustParseAddr(address), ScopeID: "lan", ClientKey: "01" + mac, MAC: mac,
			Hostname: label, Label: label, State: state, BoundAt: now.Add(-time.Hour), ExpiresAt: expires,
		}
	}
	controller := &testDHCPController{leases: []store.DHCPLease{
		lease("192.0.2.120", "00:11:22:33:44:20", "laptop", store.DHCPLeaseActive, now.Add(time.Hour)),
		lease("192.0.2.10", "00:11:22:33:44:01", "printer", store.DHCPLeaseActive, now.Add(time.Hour)),
		lease("192.0.2.130", "00:11:22:33:44:30", "gone", store.DHCPLeaseActive, now.Add(-time.Minute)),
		lease("192.0.2.140", "00:11:22:33:44:40", "left", store.DHCPLeaseReleased, now.Add(time.Hour)),
	}}
	server.SetDHCPController(controller)
	return server, configuration, controller
}

func dhcpAPIRequest(t *testing.T, server *Server, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

func TestDHCPAPIReadsStateAndLeases(t *testing.T) {
	t.Parallel()
	server, _, _ := newDHCPTestServer(t)
	response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodGet, "/api/v1/dhcp", "")
	var state struct {
		Status   DHCPStatus `json:"status"`
		Settings struct {
			Enabled bool `json:"enabled"`
			Scopes  []struct {
				ID     string `json:"id"`
				Subnet string `json:"subnet"`
			} `json:"scopes"`
		} `json:"settings"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &state) != nil {
		t.Fatalf("GET /api/v1/dhcp = %d %s", response.Code, response.Body)
	}
	if !state.Status.Serving || state.Status.Received != 12 || !state.Settings.Enabled || len(state.Settings.Scopes) != 1 || state.Settings.Scopes[0].Subnet != "192.0.2.0/24" {
		t.Fatalf("state = %+v", state)
	}
	response = dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodGet, "/api/v1/dhcp/leases?scope=lan", "")
	var listed struct{ Leases []dhcpLeaseView }
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &listed) != nil {
		t.Fatalf("GET leases = %d %s", response.Code, response.Body)
	}
	// Expired and released rows don't hold an address; the rest sort by address.
	if len(listed.Leases) != 2 || listed.Leases[0].Address != "192.0.2.10" || !listed.Leases[0].Reserved || listed.Leases[1].Address != "192.0.2.120" || listed.Leases[1].Reserved {
		t.Fatalf("leases = %+v; want 192.0.2.10 (reserved) then 192.0.2.120", listed.Leases)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodGet, "/api/v1/dhcp/leases?scope=guest", ""); !strings.Contains(response.Body.String(), `"leases":[]`) {
		t.Fatalf("other scope = %s; want no leases", response.Body)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_settings", http.MethodGet, "/api/v1/dhcp/leases", ""); response.Code != http.StatusForbidden {
		t.Fatalf("token without dhcp.read = %d; want 403", response.Code)
	}
}

func TestDHCPAPIReservesAndRemoves(t *testing.T) {
	t.Parallel()
	server, configuration, controller := newDHCPTestServer(t)
	reservations := func() []config.DHCPReservation { return configuration.snapshot.Config.DHCP.Scopes[0].Reservations }

	response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPost, "/api/v1/dhcp/leases/192.0.2.120/reserve", "")
	if response.Code != http.StatusOK || len(reservations()) != 2 || reservations()[1] != (config.DHCPReservation{MAC: "00:11:22:33:44:20", Address: "192.0.2.120", Name: "laptop"}) {
		t.Fatalf("reserve lease = %d %s; reservations %+v", response.Code, response.Body, reservations())
	}
	// The same MAC, written another way, replaces its reservation.
	response = dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPut, "/api/v1/dhcp/scopes/lan/reservations/00-11-22-33-44-20", `{"address":"192.0.2.21","name":"Laptop"}`)
	if response.Code != http.StatusOK || len(reservations()) != 2 || reservations()[1].Address != "192.0.2.21" || reservations()[1].Name != "laptop" {
		t.Fatalf("set reservation = %d %s; reservations %+v", response.Code, response.Body, reservations())
	}
	revision := configuration.snapshot.Revision
	response = dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPut, "/api/v1/dhcp/scopes/lan/reservations/00:11:22:33:44:99", `{"address":"198.51.100.5"}`)
	if response.Code != http.StatusUnprocessableEntity || configuration.snapshot.Revision != revision {
		t.Fatalf("reservation outside the subnet = %d %s; want 422 and nothing saved", response.Code, response.Body)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPut, "/api/v1/dhcp/scopes/guest/reservations/00:11:22:33:44:99", `{"address":"192.0.2.5"}`); response.Code != http.StatusNotFound {
		t.Fatalf("unknown scope = %d; want 404", response.Code)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodDelete, "/api/v1/dhcp/scopes/lan/reservations/00:11:22:33:44:20", ""); response.Code != http.StatusNoContent || len(reservations()) != 1 {
		t.Fatalf("remove reservation = %d %s", response.Code, response.Body)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodDelete, "/api/v1/dhcp/leases/192.0.2.120", ""); response.Code != http.StatusNoContent || controller.leases[0].State != store.DHCPLeaseReleased {
		t.Fatalf("remove lease = %d %s", response.Code, response.Body)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodDelete, "/api/v1/dhcp/leases/192.0.2.120", ""); response.Code != http.StatusNotFound {
		t.Fatalf("remove a lease twice = %d; want 404", response.Code)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_settings", http.MethodDelete, "/api/v1/dhcp/leases/192.0.2.10", ""); response.Code != http.StatusForbidden {
		t.Fatalf("token without dhcp.write = %d; want 403", response.Code)
	}
}

func TestDHCPAPISavesSettings(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPTestServer(t)
	revision := configuration.snapshot.Revision
	invalid := `{"enabled":true,"scopes":[{"id":"lan","name":"LAN","subnet":"192.0.2.0/24","ranges":[{"start":"10.9.9.1","end":"10.9.9.9"}]}]}`
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPut, "/api/v1/dhcp", invalid); response.Code != http.StatusUnprocessableEntity || configuration.snapshot.Revision != revision {
		t.Fatalf("range outside the subnet = %d %s; want 422 and nothing saved", response.Code, response.Body)
	}
	valid := `{"enabled":false,"scopes":[{"id":"lan","name":"LAN","subnet":"192.0.2.0/24","lease":"12h","ranges":[{"start":"192.0.2.50","end":"192.0.2.60"}]}]}`
	response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPut, "/api/v1/dhcp", valid)
	saved := configuration.snapshot.Config.DHCP
	if response.Code != http.StatusOK || saved.Enabled || saved.Scopes[0].Lease.Duration != 12*time.Hour || saved.Scopes[0].Ranges[0].Start != "192.0.2.50" {
		t.Fatalf("save = %d %s; saved %+v", response.Code, response.Body, saved)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPut, "/api/v1/dhcp", `{"enabeld":true}`); response.Code != http.StatusBadRequest {
		t.Fatalf("misspelled key = %d; want 400", response.Code)
	}
}

func TestDHCPMCPTools(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPTestServer(t)
	leases, failure := callMCPToolForTest(t, server, "sable_pat_admin", "list_dhcp_leases", map[string]any{})
	if listed, _ := leases["leases"].([]any); failure != "" || len(listed) != 2 {
		t.Fatalf("list_dhcp_leases = %v %q", leases, failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_settings", "list_dhcp_leases", map[string]any{}); failure != "this token needs dhcp.read to use list_dhcp_leases" {
		t.Fatalf("token without dhcp.read = %q", failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "set_dhcp_reservation", map[string]any{
		"scope": "lan", "mac": "00:11:22:33:44:50", "address": "192.0.2.50", "name": "tv",
	}); failure != "" || len(configuration.snapshot.Config.DHCP.Scopes[0].Reservations) != 2 {
		t.Fatalf("set_dhcp_reservation = %q", failure)
	}
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "remove_dhcp_reservation", map[string]any{"scope": "lan", "mac": "00:11:22:33:44:50"}); failure != "" || len(configuration.snapshot.Config.DHCP.Scopes[0].Reservations) != 1 {
		t.Fatalf("remove_dhcp_reservation = %q", failure)
	}
	server.SetClusterController(testReplicaClusterController{})
	if _, failure := callMCPToolForTest(t, server, "sable_pat_admin", "set_dhcp_reservation", map[string]any{
		"scope": "lan", "mac": "00:11:22:33:44:50", "address": "192.0.2.50",
	}); failure != replicaWriteMessage {
		t.Fatalf("replica write = %q; want %q", failure, replicaWriteMessage)
	}
	if status, failure := callMCPToolForTest(t, server, "sable_pat_admin", "get_dhcp_status", map[string]any{}); failure != "" || status["status"] == nil {
		t.Fatalf("replica read = %v %q", status, failure)
	}
}

func TestDHCPPermissionsAreGrantable(t *testing.T) {
	t.Parallel()
	for _, permission := range []string{auth.PermissionDHCPRead, auth.PermissionDHCPWrite} {
		found := false
		for _, known := range auth.AllPermissions {
			found = found || known == permission
		}
		if !found {
			t.Fatalf("%s isn't in auth.AllPermissions, so no role can be granted it", permission)
		}
	}
}
