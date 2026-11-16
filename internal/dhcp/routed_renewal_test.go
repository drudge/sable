package dhcp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

// routedEngine serves lan (10.0.7.0/24) through a relay and, when local is
// set, office (192.168.50.0/24) on the node's own link.
func routedEngine(t *testing.T, local bool) *Engine {
	t.Helper()
	scopes := []config.DHCPScope{testScope()}
	if local {
		office := testScope()
		office.ID, office.Name, office.Subnet, office.Router = "office", "Office", "192.168.50.0/24", "192.168.50.1"
		office.NTP, office.Routes, office.Boot, office.Options = nil, nil, nil, nil
		office.Domain, office.Search = "office.example.com", []string{"office.example.com"}
		office.Ranges = []config.DHCPRange{{Start: "192.168.50.100", End: "192.168.50.120", Node: "node-a"}}
		office.Reservations = nil
		scopes = append(scopes, office)
	}
	settings := config.DHCP{Enabled: true, Scopes: scopes}
	if err := settings.Validate(); err != nil {
		t.Fatalf("test scopes don't validate: %v", err)
	}
	engine, err := New(settings, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// officeLink is the node's own link; the lan scope reaches it through a relay
// at 10.0.7.1.
func officeLink(to string) Meta {
	meta := Meta{Interface: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.50.2/24")}}
	if to != "" {
		meta.To = netip.MustParseAddr(to)
	}
	return meta
}

// relayedBind leases a lan address through the relay, as a client behind a
// broadcast-only relay gets its first lease.
func relayedBind(t *testing.T, engine *Engine) netip.Addr {
	t.Helper()
	discover := clientPacket(Discover, testMAC)
	discover.GIAddr = netip.MustParseAddr("10.0.7.1")
	offer := engine.Handle(testNow, discover, officeLink("255.255.255.255"))
	if offer.Reply == nil {
		t.Fatalf("no relayed OFFER: %s", offer.Drop)
	}
	request := clientPacket(Request, testMAC, addrOption(optionServerID, "192.168.50.2"), addrOption(optionRequestedIP, offer.Reply.YIAddr.String()))
	request.GIAddr = discover.GIAddr
	ack := engine.Handle(testNow, request, officeLink("255.255.255.255"))
	if ack.Reply == nil || ack.Reply.MessageType() != Ack {
		t.Fatalf("no relayed ACK: %+v", ack)
	}
	return ack.Reply.YIAddr
}

func renewal(address netip.Addr) Packet {
	request := clientPacket(Request, testMAC)
	request.CIAddr = address
	return request
}

// A RENEWING client behind a relay that forwards broadcasts only unicasts
// straight to the server, routed, with giaddr zero (RFC 2131 §4.3.2,
// §4.4.5). The server takes the scope holding ciaddr, ACKs to ciaddr, and
// names the address the client sent to, whether or not the node also has a
// scope on the arrival link (F75, D106).
func TestRoutedRenewalTakesTheScopeHoldingCiaddr(t *testing.T) {
	for _, local := range []bool{false, true} {
		engine := routedEngine(t, local)
		bound := relayedBind(t, engine)
		result := engine.Handle(testNow.Add(30*time.Minute), renewal(bound), officeLink("192.168.50.2"))
		if result.Reply == nil || result.Reply.MessageType() != Ack {
			t.Fatalf("local scope %v: routed renewal of %s = %+v (%s); want an ACK", local, bound, result.Reply, result.Drop)
		}
		if result.Destination != ToClient || result.Reply.YIAddr != bound {
			t.Fatalf("local scope %v: ACK goes to %d for %s; want ciaddr %s", local, result.Destination, result.Reply.YIAddr, bound)
		}
		if id, _ := result.Reply.Option(optionServerID); netip.AddrFrom4([4]byte(id)) != netip.MustParseAddr("192.168.50.2") {
			t.Fatalf("local scope %v: server identifier = %v; want 192.168.50.2", local, id)
		}
	}
}

// A broadcast keeps the arrival link's rule: a client that moved onto the
// node's own link and rebinds with its old lan address is NAKed there, as
// before D106. A directed broadcast or an unknown destination counts as a
// broadcast.
func TestBroadcastRebindWithAnotherScopesCiaddrIsNaked(t *testing.T) {
	for _, to := range []string{"255.255.255.255", "192.168.50.255", ""} {
		engine := routedEngine(t, true)
		bound := relayedBind(t, engine)
		result := engine.Handle(testNow.Add(50*time.Minute), renewal(bound), officeLink(to))
		if result.Reply == nil || result.Reply.MessageType() != Nak {
			t.Fatalf("to %q: rebind of %s on the office link = %+v (%s); want a NAK", to, bound, result.Reply, result.Drop)
		}
	}
}

// A node whose own address is a /32 or a /31 (a cloud VM, a point-to-point
// link) has no directed broadcast there (RFC 3021): a renewal routed to that
// address is unicast, even though it is the prefix's last address.
func TestRoutedRenewalToANodeOnAHostPrefix(t *testing.T) {
	for _, prefix := range []string{"192.168.50.2/32", "192.168.50.3/31", "192.168.50.2/31"} {
		link := Meta{Interface: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix(prefix)}}
		engine := routedEngine(t, false)
		discover := clientPacket(Discover, testMAC)
		discover.GIAddr = netip.MustParseAddr("10.0.7.1")
		offer := engine.Handle(testNow, discover, link)
		if offer.Reply == nil {
			t.Fatalf("%s: no relayed OFFER: %s", prefix, offer.Drop)
		}
		id, _ := offer.Reply.Option(optionServerID)
		request := clientPacket(Request, testMAC, Option{Code: optionServerID, Data: id}, addrOption(optionRequestedIP, offer.Reply.YIAddr.String()))
		request.GIAddr = discover.GIAddr
		if ack := engine.Handle(testNow, request, link); ack.Reply == nil || ack.Reply.MessageType() != Ack {
			t.Fatalf("%s: no relayed ACK: %+v", prefix, ack)
		}
		link.To = netip.AddrFrom4([4]byte(id))
		result := engine.Handle(testNow.Add(30*time.Minute), renewal(offer.Reply.YIAddr), link)
		if result.Reply == nil || result.Reply.MessageType() != Ack {
			t.Fatalf("%s: routed renewal sent to %s = %+v (%s); want an ACK", prefix, link.To, result.Reply, result.Drop)
		}
	}
}
