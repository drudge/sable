package dhcp

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

// Review of #638. A node writes only its own lease rows (design §3 and the
// lease store: "Only a write by the owner takes a number"). The engine loads
// the mirrored rows of the other nodes with its own, and when a client that
// holds a lease on node-b takes one from node-a, node-a ends node-b's row and
// hands it back to be saved. On the real binaries the primary then held the
// replica's row as released under sequence 1 from a counter of its own for
// the replica, while the replica held it active under 5, and the two never
// met again.
func TestReview638EngineSavesOnlyItsOwnRows(t *testing.T) {
	engine, err := New(config.DHCP{Enabled: true, Scopes: []config.DHCPScope{testScope()}}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	mac := net.HardwareAddr{0, 0x77, 0, 0, 0, 1}
	engine.Load([]Lease{{
		NodeID: "node-b", Address: netip.MustParseAddr("10.0.7.150"), ScopeID: "lan",
		ClientKey: clientKey(clientPacket(Discover, mac), false), MAC: mac.String(), State: LeaseActive,
		BoundAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Hour),
	}})
	offered, answer := offerThenRequest(t, engine, testNow, mac)
	if answer.Reply == nil || answer.Reply.MessageType() != Ack {
		t.Fatalf("node-a didn't lease the client an address of its own (offered %s)", offered)
	}
	for _, lease := range answer.Save {
		if lease.NodeID != "node-a" {
			t.Errorf("node-a saves node-b's row for %s as %s; only the owner writes a lease", lease.Address, lease.State)
		}
	}
}
