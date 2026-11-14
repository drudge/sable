package dhcp

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

// Each client message in each state RFC 2131 Table 4 tells apart, against a
// client that already holds 10.0.7.x from this node.
func TestRFC2131Table4ClientMessages(t *testing.T) {
	type check func(t *testing.T, engine *Engine, bound netip.Addr, result Result)
	wantReply := func(kind MessageType, destination Destination) check {
		return func(t *testing.T, _ *Engine, _ netip.Addr, result Result) {
			if result.Reply == nil || result.Reply.MessageType() != kind || result.Destination != destination {
				t.Fatalf("result = %+v; want message %d to destination %d", result, kind, destination)
			}
		}
	}
	wantSaved := func(state LeaseState) check {
		return func(t *testing.T, _ *Engine, bound netip.Addr, result Result) {
			if result.Reply != nil || result.Save == nil || result.Save.State != state || result.Save.Address != bound {
				t.Fatalf("result = %+v; want no reply and %s saved for %s", result, state, bound)
			}
		}
	}
	cases := []struct {
		name    string
		message func(bound netip.Addr) Packet
		check   check
	}{
		{"DISCOVER", func(netip.Addr) Packet { return clientPacket(Discover, testMAC) }, wantReply(Offer, ToHardware)},
		{"REQUEST selecting", func(bound netip.Addr) Packet {
			return clientPacket(Request, testMAC, ourServerID(), addrOption(optionRequestedIP, bound.String()))
		}, wantReply(Ack, ToHardware)},
		{"REQUEST init-reboot", func(bound netip.Addr) Packet {
			return clientPacket(Request, testMAC, addrOption(optionRequestedIP, bound.String()))
		}, wantReply(Ack, ToHardware)},
		{"REQUEST renewing", func(bound netip.Addr) Packet {
			packet := clientPacket(Request, testMAC)
			packet.CIAddr = bound
			return packet
		}, wantReply(Ack, ToClient)},
		{"REQUEST rebinding, broadcast", func(bound netip.Addr) Packet {
			packet := clientPacket(Request, testMAC)
			packet.CIAddr, packet.Flags = bound, broadcastFlag
			return packet
		}, wantReply(Ack, ToClient)},
		{"DECLINE", func(bound netip.Addr) Packet {
			return clientPacket(Decline, testMAC, ourServerID(), addrOption(optionRequestedIP, bound.String()))
		}, wantSaved(LeaseDeclined)},
		{"RELEASE", func(bound netip.Addr) Packet {
			packet := clientPacket(Release, testMAC, ourServerID())
			packet.CIAddr = bound
			return packet
		}, wantSaved(LeaseReleased)},
		{"INFORM", func(netip.Addr) Packet {
			packet := clientPacket(Inform, testMAC)
			packet.CIAddr = netip.MustParseAddr("10.0.7.40")
			return packet
		}, wantReply(Ack, ToClient)},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			engine := newTestEngine(t, nil)
			bound := bind(t, engine, testMAC)
			testCase.check(t, engine, bound, engine.Handle(testNow, testCase.message(bound), testLink))
		})
	}
}

// The fields RFC 2131 Table 3 sets in each server message, with the client
// identifier echoed in all of them (RFC 6842 §3).
func TestRFC2131Table3ServerMessages(t *testing.T) {
	engine := newTestEngine(t, nil)
	clientID := Option{Code: optionClientID, Data: []byte{1, 0, 0x11, 0x22, 0x33, 0x44, 0x55}}
	discover := clientPacket(Discover, testMAC, clientID, Option{Code: optionParameters, Data: []byte{1, 3, 6}})
	discover.Secs, discover.Hops = 9, 0
	offer := engine.Handle(testNow, discover, testLink).Reply
	assertReply(t, "OFFER", offer, replyShape{yiaddr: true, boot: true, lease: true, config: true})
	if !bytes.Equal(offer.CHAddr, testMAC) || offer.XID != discover.XID || offer.Secs != 0 || offer.CIAddr != netip.IPv4Unspecified() {
		t.Fatalf("OFFER header = %+v", offer)
	}
	request := clientPacket(Request, testMAC, clientID, ourServerID(), addrOption(optionRequestedIP, offer.YIAddr.String()))
	assertReply(t, "ACK", engine.Handle(testNow, request, testLink).Reply, replyShape{yiaddr: true, boot: true, lease: true, config: true})

	nak := engine.Handle(testNow, clientPacket(Request, testMAC, clientID, addrOption(optionRequestedIP, "192.168.9.9")), testLink).Reply
	assertReply(t, "NAK", nak, replyShape{})
	if _, found := nak.Option(optionMessage); !found {
		t.Error("NAK has no message (option 56)")
	}
	inform := clientPacket(Inform, testMAC, clientID)
	inform.CIAddr = netip.MustParseAddr("10.0.7.40")
	ack := engine.Handle(testNow, inform, testLink).Reply
	assertReply(t, "INFORM ACK", ack, replyShape{boot: true, config: true})
	if ack.CIAddr != inform.CIAddr {
		t.Errorf("INFORM ACK ciaddr = %s; want the client's %s", ack.CIAddr, inform.CIAddr)
	}
}

type replyShape struct{ yiaddr, boot, lease, config bool }

func assertReply(t *testing.T, name string, reply *Packet, want replyShape) {
	t.Helper()
	if reply == nil || reply.Op != 2 {
		t.Fatalf("%s = %+v; want a BOOTREPLY", name, reply)
	}
	if got := !reply.YIAddr.IsUnspecified(); got != want.yiaddr {
		t.Errorf("%s yiaddr = %s", name, reply.YIAddr)
	}
	if got := reply.SIAddr == netip.MustParseAddr("10.0.7.5") && reply.File == "pxelinux.0" && reply.SName == "tftp"; got != want.boot {
		t.Errorf("%s siaddr, sname, file = %s %q %q; want boot fields %v", name, reply.SIAddr, reply.SName, reply.File, want.boot)
	}
	for _, code := range []uint8{optionLeaseTime, optionRenewal, optionRebinding} {
		if _, found := reply.Option(code); found != want.lease {
			t.Errorf("%s option %d present = %v; want %v", name, code, found, want.lease)
		}
	}
	if _, found := reply.Option(optionSubnetMask); found != want.config {
		t.Errorf("%s subnet mask present = %v; want %v", name, found, want.config)
	}
	for _, code := range []uint8{optionMessageType, optionServerID, optionClientID} {
		if _, found := reply.Option(code); !found {
			t.Errorf("%s is missing option %d", name, code)
		}
	}
	for _, code := range []uint8{optionRequestedIP, optionParameters, optionMaxSize} {
		if _, found := reply.Option(code); found {
			t.Errorf("%s carries client-only option %d", name, code)
		}
	}
}

// The NAK rules: NAK only off-link or someone else's address; adopt an
// unknown address in this node's range; stay silent for another node's.
func TestRequestNAKAndAdoptRules(t *testing.T) {
	other := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66}
	reserved := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	cases := []struct {
		name      string
		mac       net.HardwareAddr
		requested string
		want      MessageType
	}{
		{"off-link", testMAC, "192.168.1.50", Nak},
		{"bound to another client", other, "", Nak},
		{"reserved for another client", testMAC, "10.0.7.20", Nak},
		{"reserved client asks for another address", reserved, "10.0.7.115", Nak},
		{"reserved client asks for its own", reserved, "10.0.7.20", Ack},
		{"unknown address in this node's range is adopted", testMAC, "10.0.7.118", Ack},
		{"another node's range", testMAC, "10.0.7.155", 0},
		{"on-link outside every range", testMAC, "10.0.7.60", 0},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			engine := newTestEngine(t, nil)
			requested := testCase.requested
			if requested == "" {
				requested = bind(t, engine, testMAC).String()
			}
			result := engine.Handle(testNow, clientPacket(Request, testCase.mac, addrOption(optionRequestedIP, requested)), testLink)
			got := MessageType(0)
			if result.Reply != nil {
				got = result.Reply.MessageType()
			}
			if got != testCase.want {
				t.Fatalf("reply = %d (%s); want %d", got, result.Drop, testCase.want)
			}
			if got == Ack && (result.Save == nil || result.Save.Address.String() != requested) {
				t.Fatalf("ACK saved %+v; want the lease on %s", result.Save, requested)
			}
		})
	}
}

// A relayed request is answered through the relay with option 82 echoed
// unchanged and last (RFC 3046 §2.1, §2.2); a relayed NAK sets the broadcast
// bit (RFC 2131 §4.3.2).
// A relayed request on a link that lists an IPv6 address first is answered
// from the link's IPv4 address; one with no IPv4 address is dropped. Neither
// may panic (F6).
func TestRelayedWithIPv6FirstAddress(t *testing.T) {
	engine := newTestEngine(t, nil)
	meta := Meta{Interface: "eth0", Addrs: []netip.Prefix{
		netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("10.0.7.2/24")}}
	request := clientPacket(Discover, testMAC)
	request.GIAddr = netip.MustParseAddr("10.0.7.1")
	result := engine.Handle(testNow, request, meta)
	if result.Reply == nil {
		t.Fatalf("no offer: %s", result.Drop)
	}
	if got := result.Reply.YIAddr; !got.Is4() {
		t.Fatal(got)
	}
	if id, _ := result.Reply.Option(optionServerID); netip.AddrFrom4([4]byte(id)) != netip.MustParseAddr("10.0.7.2") {
		t.Fatalf("server identifier = %v, want 10.0.7.2", id)
	}
	v6Only := Meta{Interface: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("fe80::1/64")}}
	if result := engine.Handle(testNow, request, v6Only); result.Reply != nil {
		t.Fatalf("answered a relayed request with no IPv4 server identifier: %+v", result.Reply)
	}
}

func TestRelayedRequestsEchoOption82(t *testing.T) {
	engine := newTestEngine(t, nil)
	relayInfo := Option{Code: optionRelayInfo, Data: []byte{1, 4, 0, 0, 0, 7, 2, 2, 0xbe, 0xef}}
	discover := clientPacket(Discover, testMAC, relayInfo)
	discover.GIAddr, discover.Hops = netip.MustParseAddr("10.0.7.1"), 1
	result := engine.Handle(testNow, discover, Meta{Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.50.2/24")}})
	if result.Reply == nil || result.Destination != ToRelay || result.Reply.GIAddr != discover.GIAddr {
		t.Fatalf("relayed DISCOVER = %+v; want an OFFER through the relay", result)
	}
	if data, _ := result.Reply.Option(optionRelayInfo); !bytes.Equal(data, relayInfo.Data) {
		t.Fatalf("option 82 = %x; want %x", data, relayInfo.Data)
	}
	wire := result.Reply.Marshal()
	tail := append([]byte{optionRelayInfo, byte(len(relayInfo.Data))}, relayInfo.Data...)
	if !bytes.Contains(wire, append(tail, 255)) {
		t.Fatal("option 82 isn't the last option before End")
	}
	nak := clientPacket(Request, testMAC, relayInfo, addrOption(optionRequestedIP, "172.16.0.9"))
	nak.GIAddr = discover.GIAddr
	result = engine.Handle(testNow, nak, Meta{Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.50.2/24")}})
	if result.Reply == nil || result.Reply.MessageType() != Nak || result.Destination != ToRelay || result.Reply.Flags&broadcastFlag == 0 {
		t.Fatalf("relayed NAK = %+v; want a NAK to the relay with the broadcast bit", result)
	}
	if data, _ := result.Reply.Option(optionRelayInfo); !bytes.Equal(data, relayInfo.Data) {
		t.Fatal("relayed NAK doesn't echo option 82")
	}
}

func TestSelectingAnotherServerDropsTheOffer(t *testing.T) {
	engine := newTestEngine(t, nil)
	offered := engine.Handle(testNow, clientPacket(Discover, testMAC), testLink).Reply.YIAddr
	result := engine.Handle(testNow, clientPacket(Request, testMAC, addrOption(optionServerID, "10.0.7.3"), addrOption(optionRequestedIP, offered.String())), testLink)
	if result.Reply != nil || len(engine.offers) != 0 {
		t.Fatalf("REQUEST for another server = %+v, %d offers held; want silence and the offer dropped", result, len(engine.offers))
	}
}

func TestScopeFlags(t *testing.T) {
	random := net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	reserved := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	t.Run("reserved_only", func(t *testing.T) {
		engine := newTestEngine(t, func(scope *config.DHCPScope) { scope.ReservedOnly = true })
		if result := engine.Handle(testNow, clientPacket(Discover, testMAC), testLink); result.Reply != nil {
			t.Fatalf("unreserved client got %+v", result.Reply)
		}
		if result := engine.Handle(testNow, clientPacket(Request, testMAC, addrOption(optionRequestedIP, "10.0.7.112")), testLink); result.Reply != nil {
			t.Fatalf("unreserved client adopted an address: %+v", result.Reply)
		}
		if got := bind(t, engine, reserved); got != netip.MustParseAddr("10.0.7.20") {
			t.Fatalf("reserved client bound %s; want 10.0.7.20", got)
		}
	})
	t.Run("block_random_macs", func(t *testing.T) {
		engine := newTestEngine(t, func(scope *config.DHCPScope) {
			scope.BlockRandomMACs = true
			scope.Reservations = append(scope.Reservations, config.DHCPReservation{MAC: "02:00:00:00:00:09", Address: "10.0.7.21"})
		})
		if result := engine.Handle(testNow, clientPacket(Discover, random), testLink); result.Reply != nil {
			t.Fatalf("locally administered MAC got %+v", result.Reply)
		}
		if got := bind(t, engine, net.HardwareAddr{0x02, 0, 0, 0, 0, 9}); got != netip.MustParseAddr("10.0.7.21") {
			t.Fatalf("reserved random MAC bound %s; want its reservation", got)
		}
	})
	t.Run("ignore_client_id", func(t *testing.T) {
		engine := newTestEngine(t, func(scope *config.DHCPScope) { scope.IgnoreClientID = true })
		first := bind(t, engine, testMAC, Option{Code: optionClientID, Data: []byte{0xff, 1, 2}})
		second := bind(t, engine, testMAC, Option{Code: optionClientID, Data: []byte{0xff, 3, 4}})
		if first != second {
			t.Fatalf("one MAC with two client IDs bound %s and %s; want one binding", first, second)
		}
	})
	t.Run("client id names the binding by default", func(t *testing.T) {
		engine := newTestEngine(t, nil)
		first := bind(t, engine, testMAC, Option{Code: optionClientID, Data: []byte{0xff, 1, 2}})
		second := bind(t, engine, testMAC, Option{Code: optionClientID, Data: []byte{0xff, 3, 4}})
		if first == second {
			t.Fatalf("two client IDs on one MAC shared %s; RFC 2131 §4.2 makes them two clients", first)
		}
	})
	t.Run("offer_delay", func(t *testing.T) {
		engine := newTestEngine(t, func(scope *config.DHCPScope) { scope.OfferDelay = config.Duration{Duration: 300 * time.Millisecond} })
		if result := engine.Handle(testNow, clientPacket(Discover, testMAC), testLink); result.Delay != 300*time.Millisecond {
			t.Fatalf("delay = %s; want 300ms", result.Delay)
		}
	})
}

// A new binding is probed first; an answer takes the address out for an
// hour, and the next DISCOVER gets another one.
func TestConflictProbe(t *testing.T) {
	engine := newTestEngine(t, nil)
	result := engine.Handle(testNow, clientPacket(Discover, testMAC), testLink)
	if result.Probe != result.Reply.YIAddr || result.ProbeTimeout != config.DefaultDHCPConflictProbe {
		t.Fatalf("probe = %s for %s; want the offered address for the default timeout", result.Probe, result.ProbeTimeout)
	}
	saved := engine.Conflict(testNow, result.Probe)
	if saved == nil || saved.State != LeaseDeclined || saved.ExpiresAt != testNow.Add(declineHold) {
		t.Fatalf("conflict saved %+v; want the address declined for an hour", saved)
	}
	next := engine.Handle(testNow, clientPacket(Discover, testMAC), testLink)
	if next.Reply.YIAddr == result.Probe {
		t.Fatalf("offered %s again after a conflict", result.Probe)
	}
	later := engine.Handle(testNow.Add(declineHold+time.Second), clientPacket(Request, net.HardwareAddr{9, 9, 9, 9, 9, 9}, addrOption(optionRequestedIP, result.Probe.String())), testLink)
	if later.Reply == nil || later.Reply.MessageType() != Ack {
		t.Fatalf("declined address after its hour = %+v; want it back in the pool", later)
	}
	renewal := engine.Handle(testNow, clientPacket(Discover, testMAC), testLink)
	if renewal.Probe.IsValid() {
		t.Fatal("a client's own pending offer was probed again")
	}
	noProbe := newTestEngine(t, func(scope *config.DHCPScope) { scope.ConflictProbe = &config.Duration{} })
	if result := noProbe.Handle(testNow, clientPacket(Discover, testMAC), testLink); result.Probe.IsValid() {
		t.Fatal("conflict_probe = 0s still probes")
	}
}

// RFC 8925 §3.3: a client that asks for option 108 is offered 0.0.0.0 with
// the wait; one that doesn't gets an address.
func TestIPv6OnlyPreferred(t *testing.T) {
	engine := newTestEngine(t, func(scope *config.DHCPScope) { scope.IPv6OnlyPreferred = config.Duration{Duration: 30 * time.Minute} })
	asking := engine.Handle(testNow, clientPacket(Discover, testMAC, Option{Code: optionParameters, Data: []byte{1, 3, 108}}), testLink)
	if !asking.Reply.YIAddr.IsUnspecified() || replyUint32(t, asking.Reply, optionV6OnlyPrefer) != 1800 || len(engine.offers) != 0 {
		t.Fatalf("v6-only OFFER yiaddr %s, %d offers held; want 0.0.0.0, 1800 s, nothing held", asking.Reply.YIAddr, len(engine.offers))
	}
	plain := engine.Handle(testNow, clientPacket(Discover, testMAC, Option{Code: optionParameters, Data: []byte{1, 3}}), testLink)
	if _, found := plain.Reply.Option(optionV6OnlyPrefer); found || plain.Reply.YIAddr.IsUnspecified() {
		t.Fatalf("client that didn't ask got option 108 or no address: %+v", plain.Reply)
	}
}

// The walk starts at a hash of the client key, so a client lands on the
// same address after the lease table is lost; and only this node's ranges
// are used, until they run out.
func TestAllocation(t *testing.T) {
	first := bind(t, newTestEngine(t, nil), testMAC)
	if again := bind(t, newTestEngine(t, nil), testMAC); again != first {
		t.Fatalf("fresh engine gave %s; want the same %s", again, first)
	}
	engine := newTestEngine(t, nil)
	requested := engine.Handle(testNow, clientPacket(Discover, testMAC, addrOption(optionRequestedIP, "10.0.7.113")), testLink)
	if requested.Reply.YIAddr != netip.MustParseAddr("10.0.7.113") {
		t.Fatalf("free requested address not offered: got %s", requested.Reply.YIAddr)
	}
	engine = newTestEngine(t, nil)
	seen := map[netip.Addr]bool{}
	for index := range 12 {
		address := bind(t, engine, net.HardwareAddr{0, 0x22, 0, 0, 0, byte(index)})
		if seen[address] || !engine.scopes[0].inRanges(address) {
			t.Fatalf("bound %s twice or outside node-a's ranges", address)
		}
		seen[address] = true
	}
	if result := engine.Handle(testNow, clientPacket(Discover, net.HardwareAddr{0, 0x33, 0, 0, 0, 1}), testLink); result.Reply != nil {
		t.Fatalf("13th client offered %s from a 12-address pool", result.Reply.YIAddr)
	}
}

// Options: 121 carries the default route a client loses when it ignores
// option 3 (RFC 3442), 249 mirrors it when asked, extra options follow the
// request list, and a reply never outgrows the client's maximum size.
func TestReplyOptions(t *testing.T) {
	engine := newTestEngine(t, nil)
	reply := engine.Handle(testNow, clientPacket(Discover, testMAC, Option{Code: optionParameters, Data: []byte{121, 249, 119}}), testLink).Reply
	routes, _ := reply.Option(optionRoutes)
	want := []byte{16, 10, 9, 10, 0, 7, 3, 0, 10, 0, 7, 1}
	if !bytes.Equal(routes, want) {
		t.Fatalf("option 121 = %v; want %v", routes, want)
	}
	if ms, _ := reply.Option(optionMSRoutes); !bytes.Equal(ms, want) {
		t.Fatalf("option 249 = %v; want a copy of 121", ms)
	}
	if search, _ := reply.Option(optionSearch); !bytes.Equal(search, []byte("\x03lan\x07example\x03com\x00")) {
		t.Fatalf("option 119 = %q", search)
	}
	if _, found := reply.Option(44); found {
		t.Fatal("option 44 sent though the list didn't ask for it")
	}
	if dns, _ := reply.Option(optionDNS); !bytes.Equal(dns, []byte{10, 0, 7, 2}) {
		t.Fatalf("option 6 = %v; want this node when dns is unset", dns)
	}
	if all := engine.Handle(testNow, clientPacket(Discover, testMAC), testLink).Reply; !hasOption(all, 44) {
		t.Fatal("a client with no request list didn't get option 44")
	}
	huge := newTestEngine(t, func(scope *config.DHCPScope) {
		scope.Options = append(scope.Options, config.DHCPOption{Code: 43, Hex: string(bytes.Repeat([]byte("ab"), 255))},
			config.DHCPOption{Code: 224, Hex: string(bytes.Repeat([]byte("cd"), 255))})
	})
	small := huge.Handle(testNow, clientPacket(Discover, testMAC), testLink).Reply
	if size := len(small.Marshal()); size > 576-28 {
		t.Fatalf("reply is %d bytes; want it inside a 576-byte datagram", size)
	}
	if !hasOption(small, optionLeaseTime) || !hasOption(small, optionServerID) {
		t.Fatal("trimming dropped a required option")
	}
}

func hasOption(packet *Packet, code uint8) bool {
	_, found := packet.Option(code)
	return found
}

func TestWireRoundTrip(t *testing.T) {
	engine := newTestEngine(t, nil)
	discover := clientPacket(Discover, testMAC, Option{Code: optionHostname, Data: []byte("printer")})
	parsed, err := Parse(discover.Marshal())
	if err != nil || parsed.MessageType() != Discover || !bytes.Equal(parsed.CHAddr, testMAC) {
		t.Fatalf("Parse = %+v, %v", parsed, err)
	}
	reply := engine.Handle(testNow, parsed, testLink).Reply
	if _, err := Parse(reply.Marshal()); err == nil {
		t.Fatal("Parse accepted a BOOTREPLY")
	}
	if len(reply.Marshal()) < 300 {
		t.Fatal("reply is shorter than BOOTP's 300 bytes")
	}
}
