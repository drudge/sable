package web

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// A scope is saved and removed one at a time, the way a reservation is. The
// path names the scope, and saving one keeps its reservations, which have
// routes of their own.
func TestDHCPAPISetsAndRemovesScopes(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPTestServer(t)
	scopes := func() int { return len(configuration.snapshot.Config.DHCP.Scopes) }

	guest := `{"name":"Guest","subnet":"198.51.100.0/24","lease":"2h","router":"198.51.100.1","ranges":[{"start":"198.51.100.50","end":"198.51.100.99"}]}`
	response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPut, "/api/v1/dhcp/scopes/guest", guest)
	var saved struct {
		ID     string `json:"id"`
		Subnet string `json:"subnet"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &saved) != nil || saved.ID != "guest" || scopes() != 2 {
		t.Fatalf("create scope = %d %s; %d scopes", response.Code, response.Body, scopes())
	}
	if lease := configuration.snapshot.Config.DHCP.Scopes[1].Lease.Duration; lease != 2*time.Hour {
		t.Fatalf("guest lease = %v; want 2h", lease)
	}

	edit := `{"id":"ignored","name":"LAN","subnet":"192.0.2.0/24","router":"192.0.2.1","ranges":[{"start":"192.0.2.150","end":"192.0.2.160"}]}`
	response = dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPut, "/api/v1/dhcp/scopes/lan", edit)
	lan := configuration.snapshot.Config.DHCP.Scopes[0]
	if response.Code != http.StatusOK || lan.ID != "lan" || lan.Ranges[0].Start != "192.0.2.150" || len(lan.Reservations) != 1 || lan.Reservations[0].Name != "printer" {
		t.Fatalf("edit scope = %d %s; lan %+v", response.Code, response.Body, lan)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodGet, "/api/v1/dhcp/scopes/lan", ""); response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &saved) != nil || saved.Subnet != "192.0.2.0/24" {
		t.Fatalf("get scope = %d %s", response.Code, response.Body)
	}

	revision := configuration.snapshot.Revision
	overlap := `{"name":"Overlap","subnet":"192.0.2.128/25","ranges":[{"start":"192.0.2.200","end":"192.0.2.210"}]}`
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPut, "/api/v1/dhcp/scopes/overlap", overlap); response.Code != http.StatusUnprocessableEntity || configuration.snapshot.Revision != revision {
		t.Fatalf("overlapping subnet = %d %s; want 422 and nothing saved", response.Code, response.Body)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodPut, "/api/v1/dhcp/scopes/Not%20A%20Label", guest); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("scope id that isn't a label = %d; want 422", response.Code)
	}
	// A scope sets every client's router and resolvers, so it needs
	// settings.write as well as dhcp.write (D47).
	if response := dhcpAPIRequest(t, server, "sable_pat_dhcp_operator", http.MethodPut, "/api/v1/dhcp/scopes/lan", edit); response.Code != http.StatusForbidden {
		t.Fatalf("operator saving a scope = %d; want 403", response.Code)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_dhcp_operator", http.MethodDelete, "/api/v1/dhcp/scopes/guest", ""); response.Code != http.StatusForbidden || scopes() != 2 {
		t.Fatalf("operator removing a scope = %d; want 403", response.Code)
	}

	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodDelete, "/api/v1/dhcp/scopes/guest", ""); response.Code != http.StatusNoContent || scopes() != 1 {
		t.Fatalf("remove scope = %d %s", response.Code, response.Body)
	}
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodDelete, "/api/v1/dhcp/scopes/guest", ""); response.Code != http.StatusNotFound {
		t.Fatalf("remove a scope twice = %d; want 404", response.Code)
	}
	// DHCP that's on needs a scope to serve.
	if response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodDelete, "/api/v1/dhcp/scopes/lan", ""); response.Code != http.StatusUnprocessableEntity || scopes() != 1 {
		t.Fatalf("remove the last scope while on = %d %s; want 422", response.Code, response.Body)
	}
}
