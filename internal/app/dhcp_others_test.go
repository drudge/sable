package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/dhcp"
)

// No test broadcasts a real DISCOVER: the machine running them may sit on
// the network the test scopes name, and its router would answer.
func init() {
	dhcpDefaultSeek = func(context.Context, dhcpProbeLink, []byte, time.Duration) ([][]byte, error) {
		return nil, errors.New("tests never send a DISCOVER to the network")
	}
}

var dhcpOthersTestMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}

func dhcpOthersTestLinks() ([]dhcpProbeLink, error) {
	return []dhcpProbeLink{
		{Index: 2, MAC: dhcpOthersTestMAC, Meta: dhcp.Meta{Interface: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.7.2/24")}}},
		{Index: 3, MAC: dhcpOthersTestMAC, Meta: dhcp.Meta{Interface: "eth1", Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.9.2/24")}}},
	}, nil
}

// dhcpOthersTestReply answers discover as server would, as a packet of kind.
func dhcpOthersTestReply(t *testing.T, discover []byte, kind dhcp.MessageType, server string, xid *[4]byte) []byte {
	t.Helper()
	request, err := dhcp.Parse(discover)
	if err != nil {
		t.Fatal(err)
	}
	reply := request
	reply.Op = 2
	reply.YIAddr = netip.MustParseAddr("10.0.7.50")
	if xid != nil {
		reply.XID = *xid
	}
	reply.Options = []dhcp.Option{
		{Code: 53, Data: []byte{byte(kind)}},
		{Code: 54, Data: netip.MustParseAddr(server).AsSlice()},
	}
	return reply.Marshal()
}

// A probe goes only out of links a serving scope covers, as a broadcast-flag
// DISCOVER (RFC 2131 §4.1), and reports each other server that OFFERed once.
// This node's own OFFER, a reply to another transaction, and an ACK aren't
// another server's offer.
func TestDHCPServiceFindsOtherServers(t *testing.T) {
	service, _, _ := newTestDHCPService(t, "")
	service.links = dhcpOthersTestLinks
	var probed []string
	service.seek = func(_ context.Context, link dhcpProbeLink, discover []byte, wait time.Duration) ([][]byte, error) {
		probed = append(probed, link.Meta.Interface)
		packet, err := dhcp.Parse(discover)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Flags&0x8000 == 0 || !slices.Equal(packet.CHAddr, dhcpOthersTestMAC) || packet.MessageType() != dhcp.Discover {
			t.Errorf("probe sent %+v; want a broadcast-flag DISCOVER from the link's MAC", packet)
		}
		if wait != dhcpOthersWait {
			t.Errorf("probe waits %v, want %v", wait, dhcpOthersWait)
		}
		other := [4]byte{1, 2, 3, 4}
		return [][]byte{
			dhcpOthersTestReply(t, discover, dhcp.Offer, "10.0.7.1", nil),
			dhcpOthersTestReply(t, discover, dhcp.Offer, "10.0.7.2", nil),
			dhcpOthersTestReply(t, discover, dhcp.Offer, "10.0.7.9", &other),
			dhcpOthersTestReply(t, discover, dhcp.Ack, "10.0.7.8", nil),
			dhcpOthersTestReply(t, discover, dhcp.Offer, "10.0.7.1", nil),
			{1, 2, 3},
		}, nil
	}
	found := service.findOthers(context.Background(), dhcpTestSettings(t))
	if !slices.Equal(probed, []string{"eth0"}) {
		t.Fatalf("probed %q, want only eth0, the link scope lan covers", probed)
	}
	want := []dhcpOtherServer{{Interface: "eth0", Server: netip.MustParseAddr("10.0.7.1"), Offered: netip.MustParseAddr("10.0.7.50")}}
	if !slices.Equal(found, want) {
		t.Fatalf("found %+v, want %+v", found, want)
	}
}

// The probe runs while the server runs and its finding goes when the server
// stops: an alert about a second server only matters while this one serves.
func TestDHCPServiceProbesWhileServing(t *testing.T) {
	service, listens, _ := newTestDHCPService(t, "")
	service.links = dhcpOthersTestLinks
	service.othersEvery = 10 * time.Millisecond
	var mutex sync.Mutex
	probes := 0
	service.seek = func(_ context.Context, _ dhcpProbeLink, discover []byte, _ time.Duration) ([][]byte, error) {
		mutex.Lock()
		probes++
		mutex.Unlock()
		return [][]byte{dhcpOthersTestReply(t, discover, dhcp.Offer, "10.0.7.1", nil)}, nil
	}
	ctx := context.Background()
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
		t.Fatal(err)
	}
	waitDHCPEvents(t, listens, []string{"listen"})
	deadline := time.Now().Add(5 * time.Second)
	count := func() int {
		mutex.Lock()
		defer mutex.Unlock()
		return probes
	}
	for len(service.otherServers()) == 0 || count() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the probe didn't report the other server, or didn't repeat")
		}
		time.Sleep(time.Millisecond)
	}
	service.Stop()
	if others := service.otherServers(); len(others) != 0 {
		t.Fatalf("other servers %+v after stopping, want none", others)
	}
	after := count()
	time.Sleep(50 * time.Millisecond)
	if more := count() - after; more != 0 {
		t.Fatalf("probed %d more times after stopping", more)
	}
}

// Each other server is its own problem alert, named for the node and link,
// and there is none while the probe finds nothing or DHCP is off.
func TestDHCPOtherServerAlerts(t *testing.T) {
	var found []dhcpOtherServer
	source := dhcpOtherServerAlertSource{
		node:  func() alertNode { return alertNode{ID: "n1", Name: "ns1", Clustered: false} },
		found: func() []dhcpOtherServer { return found },
	}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	if news, err := source.Alerts(context.Background(), now); err != nil || len(news) != 0 {
		t.Fatalf("alerts %v, %v with nothing found; want none", news, err)
	}
	found = []dhcpOtherServer{{Interface: "eth0", Server: netip.MustParseAddr("10.0.7.1"), Offered: netip.MustParseAddr("10.0.7.50")}}
	news, err := source.Alerts(context.Background(), now)
	if err != nil || len(news) != 1 {
		t.Fatalf("alerts %v, %v; want one", news, err)
	}
	alert := news[0]
	if alert.ID != "server.dhcp-other-server:n1:eth0:10.0.7.1" || !alert.Problem || alert.Headline != "10.0.7.1 answers DHCP on eth0" {
		t.Fatalf("alert %+v", alert)
	}
	var off *dhcpService
	if others := (dhcpOtherServerAlertSource{node: source.node, found: off.otherServers}).found(); others != nil {
		t.Fatalf("a node without DHCP found %v", others)
	}
}

// Servers that ping before offering answer a first DISCOVER late, so a probe
// that heard only this node retransmits it (same transaction, secs counted
// up, RFC 2131 §4.1) and takes the OFFER that answers the retransmit.
func TestDHCPServiceProbeRetransmits(t *testing.T) {
	service, _, _ := newTestDHCPService(t, "")
	service.links = dhcpOthersTestLinks
	var sent []dhcp.Packet
	service.seek = func(_ context.Context, _ dhcpProbeLink, discover []byte, _ time.Duration) ([][]byte, error) {
		packet, err := dhcp.Parse(discover)
		if err != nil {
			t.Fatal(err)
		}
		sent = append(sent, packet)
		if len(sent) == 1 {
			return [][]byte{dhcpOthersTestReply(t, discover, dhcp.Offer, "10.0.7.2", nil)}, nil
		}
		return [][]byte{dhcpOthersTestReply(t, discover, dhcp.Offer, "10.0.7.1", nil)}, nil
	}
	found := service.findOthers(context.Background(), dhcpTestSettings(t))
	if len(sent) != 2 || sent[0].XID != sent[1].XID || sent[0].Secs != 0 || sent[1].Secs != 4 {
		t.Fatalf("sent %d DISCOVERs %+v; want a retransmit of the first with secs 4", len(sent), sent)
	}
	if len(found) != 1 || found[0].Server != netip.MustParseAddr("10.0.7.1") {
		t.Fatalf("found %+v, want 10.0.7.1 from the retransmit", found)
	}
}
