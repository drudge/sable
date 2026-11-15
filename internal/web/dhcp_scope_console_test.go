package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
)

func TestDHCPConsoleListsScopes(t *testing.T) {
	t.Parallel()
	server, _, _ := newDHCPConsoleServer(t)
	response := dhcpConsoleRequest(t, server, http.MethodGet, "/dhcp?tab=scopes", nil)
	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("GET /dhcp?tab=scopes = %d: %s", response.Code, body)
	}
	for _, want := range []string{`data-isotope-panel="scopes"`, "192.0.2.0/24", "192.0.2.100 – 192.0.2.199", "home.test",
		`data-dialog-open="dhcp-scope-new"`, `id="dhcp-scope-lan"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Scopes tab lacks %q", want)
		}
	}
}

func TestDHCPConsoleEditsScopes(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPConsoleServer(t)
	configuration.snapshot.Config.DHCP.Scopes[0].NTP = []string{"192.0.2.5"}

	form := url.Values{"new": {"1"}, "id": {"guest"}, "name": {"Guest"}, "subnet": {"198.51.100.0/24"},
		"range_start": {"198.51.100.50"}, "range_end": {"198.51.100.150"}, "router": {"198.51.100.1"},
		"dns": {"198.51.100.2, 198.51.100.3"}, "domain": {"guest.test"}, "lease": {"12h"}}
	response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/scopes", form)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Saved scope Guest") {
		t.Fatalf("add scope = %d: %s", response.Code, response.Body.String())
	}
	scopes := configuration.snapshot.Config.DHCP.Scopes
	if len(scopes) != 2 {
		t.Fatalf("scopes after add = %+v", scopes)
	}
	guest := scopes[1]
	if guest.ID != "guest" || guest.Lease.Duration != 12*time.Hour || len(guest.DNS) != 2 || guest.DNS[1] != "198.51.100.3" ||
		len(guest.Ranges) != 1 || guest.Ranges[0] != (config.DHCPRange{Start: "198.51.100.50", End: "198.51.100.150"}) {
		t.Fatalf("added scope = %+v", guest)
	}

	edit := url.Values{"id": {"lan"}, "name": {"Home"}, "subnet": {"192.0.2.0/24"}, "range_start": {"192.0.2.100"},
		"range_end": {"192.0.2.149"}, "router": {"192.0.2.1"}, "domain": {"home.test"}}
	response = dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/scopes", edit)
	if response.Code != http.StatusOK {
		t.Fatalf("edit scope = %d: %s", response.Code, response.Body.String())
	}
	lan := configuration.snapshot.Config.DHCP.Scopes[0]
	if lan.Name != "Home" || lan.Ranges[0].End != "192.0.2.149" || len(lan.Reservations) != 1 || len(lan.NTP) != 1 {
		t.Fatalf("edit must change the form's fields and keep the rest (reservations, NTP): %+v", lan)
	}

	edit.Set("range_end", "10.0.0.1")
	response = dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/scopes", edit)
	if body := response.Body.String(); response.Code != http.StatusUnprocessableEntity || !strings.Contains(body, "toast-error") {
		t.Fatalf("a range outside the subnet = %d: %s", response.Code, body)
	}

	add := url.Values{"new": {"1"}, "id": {"lan"}, "name": {"Again"}, "subnet": {"203.0.113.0/24"}}
	response = dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/scopes", add)
	if response.Code != http.StatusUnprocessableEntity || configuration.snapshot.Config.DHCP.Scopes[0].Name != "Home" {
		t.Fatalf("adding over an existing scope ID = %d, scope %+v", response.Code, configuration.snapshot.Config.DHCP.Scopes[0])
	}

	response = dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/scopes/delete", url.Values{"id": {"guest"}})
	if response.Code != http.StatusOK || len(configuration.snapshot.Config.DHCP.Scopes) != 1 {
		t.Fatalf("delete scope = %d, scopes %+v", response.Code, configuration.snapshot.Config.DHCP.Scopes)
	}
}

func TestDHCPConsoleTurnsTheServerOnAndOff(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPConsoleServer(t)
	response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/enabled", url.Values{"enabled": {"false"}})
	if response.Code != http.StatusOK || configuration.snapshot.Config.DHCP.Enabled || !strings.Contains(response.Body.String(), "Turned DHCP off") {
		t.Fatalf("turn off = %d, enabled %v: %s", response.Code, configuration.snapshot.Config.DHCP.Enabled, response.Body.String())
	}
	if body := response.Body.String(); !strings.Contains(body, "Turn On") || strings.Contains(body, "Turn Off") {
		t.Errorf("an off server's page lacks the Turn On button")
	}
	response = dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/enabled", url.Values{"enabled": {"true"}})
	if response.Code != http.StatusOK || !configuration.snapshot.Config.DHCP.Enabled {
		t.Fatalf("turn on = %d, enabled %v: %s", response.Code, configuration.snapshot.Config.DHCP.Enabled, response.Body.String())
	}
}

// TestDHCPServiceOperatorCannotTurnTheServerOff: turning DHCP on hands out
// every scope's router and resolvers, so it needs settings.write like the
// rest of [dhcp] (D47); the built-in Operator has only dhcp.write.
func TestDHCPServiceOperatorCannotTurnTheServerOff(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPTestServer(t)
	operator := actor{principal: auth.Principal{UserID: 12, Username: "dhcp-operator", Permissions: builtInRolePermissions("Operator")}}
	if err := server.dhcpService().SetEnabled(t.Context(), operator, false, false); err == nil || !configuration.snapshot.Config.DHCP.Enabled {
		t.Fatalf("Operator SetEnabled(false) = %v, enabled %v; want refused and still on", err, configuration.snapshot.Config.DHCP.Enabled)
	}
	admin := actor{principal: auth.Principal{UserID: 1, Username: "admin", Permissions: builtInRolePermissions("Administrator")}}
	if err := server.dhcpService().SetEnabled(t.Context(), admin, false, false); err != nil || configuration.snapshot.Config.DHCP.Enabled {
		t.Fatalf("Administrator SetEnabled(false) = %v, enabled %v", err, configuration.snapshot.Config.DHCP.Enabled)
	}
}
