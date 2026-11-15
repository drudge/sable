package dhcp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

// After a takeover an address can have two rows: the offline node's, still
// active, and the new owner's. Load keeps the most recently bound one in
// either order, so a restart never forgets a lease the new owner granted
// (RFC 2131 §4.3.1) because of how node IDs sort.
func TestLoadKeepsTheNewestRowForAnAddress(t *testing.T) {
	engine := newTestEngine(t, func(scope *config.DHCPScope) {
		for index := range scope.Ranges {
			scope.Ranges[index].Node = "node-a"
		}
	})
	address := netip.MustParseAddr("10.0.7.150")
	stale := Lease{NodeID: "node-z", Address: address, ScopeID: "lan", ClientKey: "01aa:00:00:00:00:01", MAC: "aa:00:00:00:00:01",
		State: LeaseActive, BoundAt: testNow.Add(-2 * time.Hour), ExpiresAt: testNow.Add(22 * time.Hour)}
	laptop := Lease{NodeID: "node-a", Address: address, ScopeID: "lan", ClientKey: "01aa:00:00:00:00:02", MAC: "aa:00:00:00:00:02",
		State: LeaseActive, BoundAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(59 * time.Minute)}
	for name, rows := range map[string][]Lease{"owner first": {laptop, stale}, "owner last": {stale, laptop}} {
		engine.Load(rows)
		leases := engine.Leases()
		if len(leases) != 1 || leases[0].NodeID != "node-a" || leases[0].MAC != laptop.MAC {
			t.Errorf("%s: the view holds %+v for %s; want node-a's lease to the laptop, bound a minute ago", name, leases, address)
		}
	}
}
