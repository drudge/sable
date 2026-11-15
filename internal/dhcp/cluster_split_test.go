package dhcp

import (
	"net"
	"net/netip"
	"testing"

	"github.com/drudge/sable/internal/config"
)

// Two nodes split a scope's pool and can't reach each other: neither sees
// the other's leases. Every client asks both, as a broadcast reaches both,
// and still no address is leased to two clients, since each node allocates
// only from its own ranges (design §3). A reserved client gets its address
// from either node, and a node stays silent for an on-link address it
// doesn't allocate rather than NAK the other node's client (RFC 2131 §4.3.2).
func TestClusterPartitionNeverLeasesAnAddressTwice(t *testing.T) {
	settings := config.DHCP{Enabled: true, Scopes: []config.DHCPScope{testScope()}}
	nodes := map[string]*Engine{}
	for _, node := range []string{"node-a", "node-b"} {
		engine, err := New(settings, node)
		if err != nil {
			t.Fatal(err)
		}
		nodes[node] = engine
	}
	holder := map[netip.Addr]string{}
	for index := range 40 {
		mac := net.HardwareAddr{0, 0x55, 0, 0, byte(index >> 8), byte(index)}
		for node, engine := range nodes {
			offered, answer := offerThenRequest(t, engine, testNow, mac)
			if answer.Reply == nil {
				continue
			}
			if answer.Reply.MessageType() != Ack {
				t.Fatalf("%s answered %s's REQUEST for %s with %v", node, mac, offered, answer.Reply.MessageType())
			}
			if !engine.scopes[0].inRanges(offered) {
				t.Fatalf("%s leased %s outside its own ranges", node, offered)
			}
			if previous, taken := holder[offered]; taken && previous != mac.String() {
				t.Fatalf("%s leased %s to %s; %s already holds it", node, offered, mac, previous)
			}
			holder[offered] = mac.String()
		}
	}
	if len(holder) != 22 {
		t.Fatalf("leased %d addresses; want both nodes' 12 and 10 used up", len(holder))
	}
	reserved := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	for node, engine := range nodes {
		if got := bind(t, engine, reserved); got != netip.MustParseAddr("10.0.7.20") {
			t.Fatalf("%s gave the reserved client %s; want 10.0.7.20", node, got)
		}
	}
	reboot := clientPacket(Request, net.HardwareAddr{0, 0x66, 0, 0, 0, 1}, addrOption(optionRequestedIP, "10.0.7.150"))
	if result := nodes["node-a"].Handle(testNow, reboot, testLink); result.Reply != nil {
		t.Fatalf("node-a answered an INIT-REBOOT for node-b's 10.0.7.150 with %v", result.Reply.MessageType())
	}
}
