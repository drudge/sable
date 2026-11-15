package web

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/drudge/sable/internal/store"
)

// After a range takeover the store holds the offline node's row and the new
// owner's renewal for one address. The address is bound to one client at a
// time (RFC 2131 §4.3.1), so the table lists the newer binding once.
func TestDHCPLeaseTableListsATakenOverAddressOnce(t *testing.T) {
	t.Parallel()
	server, _, controller := newDHCPTestServer(t)
	now := time.Now()
	address := netip.MustParseAddr("192.0.2.120")
	controller.leases = []store.DHCPLease{
		{NodeID: "node-b", Address: address, ScopeID: "lan", ClientKey: "0100:11:22:33:44:19", MAC: "00:11:22:33:44:19",
			State: store.DHCPLeaseActive, BoundAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(22 * time.Hour)},
		{NodeID: "node-a", Address: address, ScopeID: "lan", ClientKey: "0100:11:22:33:44:20", MAC: "00:11:22:33:44:20", Hostname: "laptop",
			Label: "laptop", State: store.DHCPLeaseActive, BoundAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(2 * time.Hour)},
	}
	response := dhcpAPIRequest(t, server, "sable_pat_admin", http.MethodGet, "/api/v1/dhcp/leases", "")
	var listed struct{ Leases []dhcpLeaseView }
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &listed) != nil {
		t.Fatalf("GET leases = %d %s", response.Code, response.Body)
	}
	if len(listed.Leases) != 1 || listed.Leases[0].Address != "192.0.2.120" || listed.Leases[0].Node != "node-a" {
		t.Fatalf("leases = %+v; want 192.0.2.120 once, from node-a", listed.Leases)
	}
}

func TestDHCPNewestRowsKeepsTheLatestBinding(t *testing.T) {
	t.Parallel()
	now := time.Now()
	address := netip.MustParseAddr("192.0.2.120")
	other := netip.MustParseAddr("192.0.2.121")
	old := store.DHCPLease{NodeID: "node-b", Address: address, BoundAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(22 * time.Hour)}
	recent := store.DHCPLease{NodeID: "node-a", Address: address, BoundAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(2 * time.Hour)}
	tie := recent
	tie.NodeID, tie.ExpiresAt = "node-c", recent.ExpiresAt.Add(time.Hour)
	third := store.DHCPLease{NodeID: "node-a", Address: other}
	for name, test := range map[string]struct {
		rows []store.DHCPLease
		want []string
	}{
		"older first":  {[]store.DHCPLease{old, recent, third}, []string{"node-a", "node-a"}},
		"newer first":  {[]store.DHCPLease{recent, old, third}, []string{"node-a", "node-a"}},
		"equal bound":  {[]store.DHCPLease{recent, tie}, []string{"node-c"}},
		"equal bound2": {[]store.DHCPLease{tie, recent}, []string{"node-c"}},
	} {
		got := dhcpNewestRows(test.rows)
		nodes := []string{}
		for _, row := range got {
			nodes = append(nodes, row.NodeID)
		}
		if !slices.Equal(nodes, test.want) {
			t.Errorf("%s: nodes = %v; want %v", name, nodes, test.want)
		}
	}
}
