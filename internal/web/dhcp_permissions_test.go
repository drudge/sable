package web

import (
	"net/http"
	"testing"
)

// TestReview628OperatorCannotReplaceDHCPSettings: the built-in Operator has
// dhcp.write but not settings.write, so it may manage reservations and
// leases but not replace [dhcp], whose scope domain creates a Primary zone
// and whose router and resolvers go to every client (F39, D47).
func TestReview628OperatorCannotReplaceDHCPSettings(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPTestServer(t)
	revision := configuration.snapshot.Revision
	body := `{"enabled":true,"scopes":[{"id":"lan","name":"LAN","subnet":"192.0.2.0/24","router":"192.0.2.66","dns":["192.0.2.66"],"domain":"example.com","ranges":[{"start":"192.0.2.100","end":"192.0.2.199"}]}]}`
	response := dhcpAPIRequest(t, server, "sable_pat_dhcp_operator", http.MethodPut, "/api/v1/dhcp", body)
	if response.Code != http.StatusForbidden || configuration.snapshot.Revision != revision {
		saved := configuration.snapshot.Config.DHCP.Scopes[0]
		t.Fatalf("Operator PUT /api/v1/dhcp = %d; want 403 and nothing saved. Saved domain %q, router %q", response.Code, saved.Domain, saved.Router)
	}
	reservation := `{"address":"192.0.2.50","name":"tv"}`
	if response := dhcpAPIRequest(t, server, "sable_pat_dhcp_operator", http.MethodPut, "/api/v1/dhcp/scopes/lan/reservations/00:11:22:33:44:50", reservation); response.Code != http.StatusOK {
		t.Fatalf("Operator reservation = %d %s; want 200, dhcp.write covers reservations", response.Code, response.Body)
	}
}
