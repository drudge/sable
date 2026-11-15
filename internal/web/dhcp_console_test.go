package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/store"
)

// newDHCPConsoleServer is the DHCP test server as a local console, which signs
// in on its own; the route table's permission test covers who may open it.
func newDHCPConsoleServer(t *testing.T) (*Server, *editableTestConfiguration, *testDHCPController) {
	t.Helper()
	server, configuration, controller := newDHCPTestServer(t)
	server.securityEnabled = false
	return server, configuration, controller
}

func dhcpConsoleRequest(t *testing.T, server *Server, method, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	request.Header.Set("HX-Request", "true")
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

func TestDHCPConsolePageListsLeasesAndReservations(t *testing.T) {
	t.Parallel()
	server, _, _ := newDHCPConsoleServer(t)
	response := dhcpConsoleRequest(t, server, http.MethodGet, "/dhcp?tab=reservations", nil)
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("GET /dhcp = %d: %s", response.Code, body)
	}
	for _, want := range []string{`id="dhcp-content"`, "Serving", "192.0.2.120", "00:11:22:33:44:20", "laptop",
		`data-isotope-panel="reservations"`, "192.0.2.10", "printer", `data-dhcp-reserve="192.0.2.120"`} {
		if !strings.Contains(body, want) {
			t.Errorf("DHCP page lacks %q", want)
		}
	}
	for _, unwanted := range []string{"192.0.2.130", "192.0.2.140", `data-dhcp-reserve="192.0.2.10"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("DHCP page shows %q: an expired or released lease, or Reserve on a reserved one", unwanted)
		}
	}
}

func TestDHCPConsoleReservesAndRemovesLeases(t *testing.T) {
	t.Parallel()
	server, configuration, controller := newDHCPConsoleServer(t)

	response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/leases/reserve", url.Values{"address": {"192.0.2.120"}, "name": {"Laptop"}})
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Reserved 192.0.2.120") {
		t.Fatalf("reserve = %d: %s", response.Code, response.Body.String())
	}
	reservations := configuration.snapshot.Config.DHCP.Scopes[0].Reservations
	if len(reservations) != 2 || reservations[1].MAC != "00:11:22:33:44:20" || reservations[1].Name != "laptop" {
		t.Fatalf("reservations after Reserve = %+v", reservations)
	}

	response = dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/leases/remove", url.Values{"address": {"192.0.2.120"}})
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Removed the lease on 192.0.2.120") {
		t.Fatalf("remove = %d: %s", response.Code, response.Body.String())
	}
	leases, _ := controller.Leases(t.Context())
	for _, lease := range leases {
		if lease.Address.String() == "192.0.2.120" && lease.State != store.DHCPLeaseReleased {
			t.Fatalf("lease after Remove = %+v", lease)
		}
	}

	response = dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/leases/remove", url.Values{"address": {"192.0.2.250"}})
	if body := response.Body.String(); !strings.Contains(body, "192.0.2.250 has no lease on this node") {
		t.Fatalf("removing a missing lease = %d: %s", response.Code, body)
	}
}

func TestDHCPConsoleEditsReservations(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPConsoleServer(t)

	form := url.Values{"scope": {"lan"}, "mac": {"00-11-22-33-44-55"}, "address": {"192.0.2.20"}, "name": {"nas"}, "comment": {"Closet"}}
	response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/reservations", form)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Saved the reservation for nas") {
		t.Fatalf("save = %d: %s", response.Code, response.Body.String())
	}
	reservations := configuration.snapshot.Config.DHCP.Scopes[0].Reservations
	if len(reservations) != 2 || reservations[1].MAC != "00:11:22:33:44:55" || reservations[1].Comment != "Closet" {
		t.Fatalf("reservations after save = %+v", reservations)
	}

	form.Set("address", "192.0.2.10")
	response = dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/reservations", form)
	if body := response.Body.String(); response.Code != http.StatusUnprocessableEntity || !strings.Contains(body, "toast-error") {
		t.Fatalf("a taken address = %d: %s", response.Code, body)
	}

	response = dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/reservations/delete", url.Values{"scope": {"lan"}, "mac": {"00:11:22:33:44:55"}})
	if response.Code != http.StatusOK || len(configuration.snapshot.Config.DHCP.Scopes[0].Reservations) != 1 {
		t.Fatalf("delete = %d, reservations %+v", response.Code, configuration.snapshot.Config.DHCP.Scopes[0].Reservations)
	}
}
