package dhcp

import (
	"bytes"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

// vlanEngine serves two VLANs the node has no address on, lan
// (10.0.7.0/24) and iot (10.0.30.0/24), both through the router's relay, the
// way a homelab with VLANs on a UniFi gateway is set up (#673).
func vlanEngine(t *testing.T) *Engine {
	t.Helper()
	iot := testScope()
	iot.ID, iot.Name, iot.Subnet, iot.Router = "iot", "IoT", "10.0.30.0/24", "10.0.30.1"
	iot.NTP, iot.Routes, iot.Boot, iot.Options, iot.Reservations = nil, nil, nil, nil, nil
	iot.Domain, iot.Search = "iot.example.com", []string{"iot.example.com"}
	iot.Ranges = []config.DHCPRange{{Start: "10.0.30.100", End: "10.0.30.120", Node: "node-a"}}
	settings := config.DHCP{Enabled: true, Scopes: []config.DHCPScope{testScope(), iot}}
	if err := settings.Validate(); err != nil {
		t.Fatalf("test scopes don't validate: %v", err)
	}
	engine, err := New(settings, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// relayed is request as the relay forwards it: giaddr set to the relay's
// address on the client's VLAN, one hop, and option 82 when info is set.
func relayed(request Packet, giaddr string, info []byte) Packet {
	request.GIAddr, request.Hops = netip.MustParseAddr(giaddr), 1
	if info != nil {
		request.Options = append(request.Options, Option{Code: optionRelayInfo, Data: info})
	}
	return request
}

// A client on a VLAN the node isn't on gets an address from the scope its
// relay's giaddr falls in, keeps it through a unicast renewal and a relayed
// rebind, and its lease names the scope, so its name goes in that scope's
// zone. Option 82 comes back unchanged on every relayed reply and is kept on
// the lease (RFC 2131 §4.3.1, §4.3.2, §4.4.5; RFC 3046 §2.2).
func TestRelayedClientLifecycleOnAVLAN(t *testing.T) {
	engine := vlanEngine(t)
	link := officeLink("192.168.50.2")
	info := []byte{1, 6, 'p', 'o', 'r', 't', '1', '2', 2, 6, 0x74, 0xac, 0xb9, 0x00, 0x00, 0x01}
	host := Option{Code: optionHostname, Data: []byte("thermostat")}

	offer := engine.Handle(testNow, relayed(clientPacket(Discover, testMAC, host), "10.0.30.1", info), link)
	if offer.Reply == nil || offer.Destination != ToRelay {
		t.Fatalf("relayed DISCOVER = %+v (%s); want an OFFER to the relay", offer.Reply, offer.Drop)
	}
	address := offer.Reply.YIAddr
	if !netip.MustParsePrefix("10.0.30.0/24").Contains(address) {
		t.Fatalf("offered %s; want an iot address, chosen by giaddr 10.0.30.1", address)
	}
	if router, _ := offer.Reply.Option(optionRouter); !bytes.Equal(router, []byte{10, 0, 30, 1}) {
		t.Fatalf("router = %v; want the iot scope's 10.0.30.1", router)
	}
	serverID, _ := offer.Reply.Option(optionServerID)
	if !bytes.Equal(serverID, []byte{192, 168, 50, 2}) {
		t.Fatalf("server identifier = %v; want the node's own 192.168.50.2", serverID)
	}

	request := clientPacket(Request, testMAC, host, Option{Code: optionServerID, Data: serverID}, addrOption(optionRequestedIP, address.String()))
	ack := engine.Handle(testNow, relayed(request, "10.0.30.1", info), link)
	if ack.Reply == nil || ack.Reply.MessageType() != Ack || ack.Destination != ToRelay || ack.Reply.YIAddr != address {
		t.Fatalf("relayed REQUEST = %+v (%s); want an ACK for %s to the relay", ack.Reply, ack.Drop, address)
	}
	if echoed, _ := ack.Reply.Option(optionRelayInfo); !bytes.Equal(echoed, info) {
		t.Fatalf("ACK option 82 = %x; want %x unchanged", echoed, info)
	}
	if len(ack.Save) == 0 {
		t.Fatal("ACK saved no lease")
	}
	lease := ack.Save[len(ack.Save)-1]
	if lease.ScopeID != "iot" || lease.Hostname != "thermostat" || lease.Relay != hex.EncodeToString(info) {
		t.Fatalf("lease = %+v; want scope iot, hostname thermostat, and option 82 kept", lease)
	}

	// T1: the client unicasts straight to the server identifier, routed,
	// with giaddr zero and no option 82.
	renew := engine.Handle(testNow.Add(30*time.Minute), renewalFrom(address, host), link)
	if renew.Reply == nil || renew.Reply.MessageType() != Ack || renew.Destination != ToClient || renew.Reply.YIAddr != address {
		t.Fatalf("unicast renewal = %+v (%s); want an ACK to ciaddr %s", renew.Reply, renew.Drop, address)
	}

	// T2: the client broadcasts, and the relay forwards it with giaddr set.
	rebind := engine.Handle(testNow.Add(53*time.Minute), relayed(renewalFrom(address, host), "10.0.30.1", info), officeLink("255.255.255.255"))
	if rebind.Reply == nil || rebind.Reply.MessageType() != Ack || rebind.Destination != ToRelay || rebind.Reply.YIAddr != address {
		t.Fatalf("relayed rebind = %+v (%s); want an ACK for %s to the relay", rebind.Reply, rebind.Drop, address)
	}
	if echoed, _ := rebind.Reply.Option(optionRelayInfo); !bytes.Equal(echoed, info) {
		t.Fatalf("rebind ACK option 82 = %x; want %x unchanged", echoed, info)
	}

	// The other VLAN's relay address picks the other scope.
	other := engine.Handle(testNow, relayed(clientPacket(Discover, testMAC2()), "10.0.7.1", nil), link)
	if other.Reply == nil || !netip.MustParsePrefix("10.0.7.0/24").Contains(other.Reply.YIAddr) {
		t.Fatalf("DISCOVER relayed from 10.0.7.1 = %+v (%s); want a lan address", other.Reply, other.Drop)
	}
}

// A relayed request whose giaddr is in no scope is dropped with
// DropRelayNoScope, which the server warns about. A relay that names the
// client's subnet apart from giaddr (RFC 3527, RFC 3011) is still matched by
// giaddr alone.
func TestRelayedRequestOutsideEveryScope(t *testing.T) {
	engine := vlanEngine(t)
	linkSelection := []byte{5, 4, 10, 0, 30, 0}
	for name, request := range map[string]Packet{
		"no hint":        relayed(clientPacket(Discover, testMAC), "10.0.40.1", nil),
		"link selection": relayed(clientPacket(Discover, testMAC), "192.168.99.1", linkSelection),
	} {
		if result := engine.Handle(testNow, request, officeLink("192.168.50.2")); result.Reply != nil || result.Drop != DropRelayNoScope {
			t.Fatalf("%s: %+v (%s); want a drop with %q", name, result.Reply, result.Drop, DropRelayNoScope)
		}
	}
	if result := engine.Handle(testNow, clientPacket(Discover, testMAC), officeLink("255.255.255.255")); result.Drop == DropRelayNoScope {
		t.Fatal("a broadcast on a link with no scope counted as a relay with no scope")
	}
}

func TestLinkHint(t *testing.T) {
	cases := []struct {
		name    string
		options []Option
		want    string
		source  string
	}{
		{"none", nil, "", ""},
		{"circuit ID only", []Option{{Code: optionRelayInfo, Data: []byte{1, 2, 0, 1}}}, "", ""},
		{"link selection after circuit ID", []Option{{Code: optionRelayInfo, Data: []byte{1, 2, 0, 1, 5, 4, 10, 0, 30, 0}}}, "10.0.30.0", "link selection (RFC 3527)"},
		{"link selection with a bad length", []Option{{Code: optionRelayInfo, Data: []byte{5, 3, 10, 0, 30}}}, "", ""},
		{"truncated sub-option", []Option{{Code: optionRelayInfo, Data: []byte{1, 9, 0}}}, "", ""},
		{"subnet selection", []Option{addrOption(optionSubnetSelect, "10.0.30.0")}, "10.0.30.0", "subnet selection (RFC 3011)"},
		{"link selection wins", []Option{addrOption(optionSubnetSelect, "10.0.40.0"), {Code: optionRelayInfo, Data: []byte{5, 4, 10, 0, 30, 0}}}, "10.0.30.0", "link selection (RFC 3527)"},
	}
	for _, test := range cases {
		address, source := LinkHint(clientPacket(Discover, testMAC, test.options...))
		if source != test.source || (test.want != "" && address != netip.MustParseAddr(test.want)) || (test.want == "" && address.IsValid()) {
			t.Fatalf("%s: LinkHint = %v, %q; want %s, %q", test.name, address, source, test.want, test.source)
		}
	}
}

func renewalFrom(address netip.Addr, options ...Option) Packet {
	request := clientPacket(Request, testMAC, options...)
	request.CIAddr = address
	return request
}

func testMAC2() net.HardwareAddr { return net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66} }
