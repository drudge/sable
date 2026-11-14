package dhcp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

var (
	testNow    = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	testServer = netip.MustParseAddr("10.0.7.2")
	testLink   = Meta{Interface: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.7.2/24")}}
	testMAC    = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
)

// testScope is a small LAN: two ranges on node-a, one on node-b, a
// reservation, and the options a home network sets.
func testScope() config.DHCPScope {
	enabled := true
	return config.DHCPScope{
		ID: "lan", Name: "LAN", Subnet: "10.0.7.0/24", Enabled: &enabled,
		Lease: config.Duration{Duration: time.Hour}, Router: "10.0.7.1",
		Domain: "lan.example.com", Search: []string{"lan.example.com"}, NTP: []string{"10.0.7.1"},
		Routes: []config.DHCPRoute{{To: "10.9.0.0/16", Via: "10.0.7.3"}},
		Ranges: []config.DHCPRange{
			{Start: "10.0.7.100", End: "10.0.7.101", Node: "node-a"},
			{Start: "10.0.7.110", End: "10.0.7.119", Node: "node-a"},
			{Start: "10.0.7.150", End: "10.0.7.159", Node: "node-b"},
		},
		Reservations: []config.DHCPReservation{{MAC: "aa:bb:cc:dd:ee:01", Address: "10.0.7.20", Name: "nas"}},
		Boot:         &config.DHCPBoot{NextServer: "10.0.7.5", ServerName: "tftp", File: "pxelinux.0"},
		Options:      []config.DHCPOption{{Code: 44, Value: []string{"10.0.7.5"}}},
	}
}

func newTestEngine(t *testing.T, edit func(*config.DHCPScope)) *Engine {
	t.Helper()
	settings := testScope()
	if edit != nil {
		edit(&settings)
	}
	dhcp := config.DHCP{Enabled: true, Scopes: []config.DHCPScope{settings}}
	if err := dhcp.Validate(); err != nil {
		t.Fatalf("test scope doesn't validate: %v", err)
	}
	engine, err := New(dhcp, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func clientPacket(kind MessageType, mac net.HardwareAddr, options ...Option) Packet {
	return Packet{
		Op: 1, HType: 1, XID: [4]byte{1, 2, 3, 4}, CHAddr: mac,
		CIAddr: netip.IPv4Unspecified(), GIAddr: netip.IPv4Unspecified(),
		Options: append([]Option{{Code: optionMessageType, Data: []byte{byte(kind)}}}, options...),
	}
}

func addrOption(code uint8, address string) Option {
	octets := netip.MustParseAddr(address).As4()
	return Option{Code: code, Data: octets[:]}
}

func ourServerID() Option { return addrOption(optionServerID, testServer.String()) }

// bind runs DISCOVER then a SELECTING REQUEST and returns the bound address.
func bind(t *testing.T, engine *Engine, mac net.HardwareAddr, options ...Option) netip.Addr {
	t.Helper()
	offer := engine.Handle(testNow, clientPacket(Discover, mac, options...), testLink)
	if offer.Reply == nil {
		t.Fatalf("no OFFER: %s", offer.Drop)
	}
	request := clientPacket(Request, mac, append(options, ourServerID(), addrOption(optionRequestedIP, offer.Reply.YIAddr.String()))...)
	ack := engine.Handle(testNow, request, testLink)
	if ack.Reply == nil || ack.Reply.MessageType() != Ack {
		t.Fatalf("no ACK for %s: %+v", offer.Reply.YIAddr, ack)
	}
	return ack.Reply.YIAddr
}

func replyUint32(t *testing.T, reply *Packet, code uint8) uint32 {
	t.Helper()
	data, found := reply.Option(code)
	if !found || len(data) != 4 {
		t.Fatalf("option %d = %x, %v; want 4 bytes", code, data, found)
	}
	return binary.BigEndian.Uint32(data)
}
