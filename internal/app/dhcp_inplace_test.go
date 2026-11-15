package app

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dhcp"
)

// A change to reservations alone applies to the running server: port 67
// stays bound, so clients mid-exchange keep getting answers (D48), and the
// next DISCOVER from the reserved client is offered its reservation.
func TestDHCPServiceAppliesReservationsInPlace(t *testing.T) {
	service, listens, _ := newTestDHCPService(t, "")
	ctx := context.Background()
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
		t.Fatal(err)
	}
	waitDHCPEvents(t, listens, []string{"listen"})
	conn := listens.last()
	conn.inbound <- dhcpTestPacket(dhcp.Discover).Marshal()
	<-conn.wrote

	reserved := dhcpTestSettings(t)
	reserved.Scopes[0].Reservations = []config.DHCPReservation{{MAC: dhcpTestMAC.String(), Address: "10.0.7.50", Name: "printer"}}
	if err := service.Apply(ctx, ctx, reserved); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	waitDHCPEvents(t, listens, []string{"listen"})

	discover := dhcpTestPacket(dhcp.Discover)
	discover.XID = [4]byte{1, 2, 3, 4}
	conn.inbound <- discover.Marshal()
	<-conn.wrote
	_, sent := conn.snapshot()
	if got, want := sent[len(sent)-1].reply.YIAddr, netip.MustParseAddr("10.0.7.50"); got != want {
		t.Fatalf("after reserving, the client is offered %v; want its reservation %v", got, want)
	}

	// A change to anything else still replaces the server.
	moved := dhcpTestSettings(t)
	moved.Scopes[0].Reservations = reserved.Scopes[0].Reservations
	moved.Scopes[0].Router = "10.0.7.254"
	if err := service.Apply(ctx, ctx, moved); err != nil {
		t.Fatal(err)
	}
	waitDHCPEvents(t, listens, []string{"listen", "close", "listen"})
}

// A server that has to bind again after its socket failed binds with the
// reservations applied in place, not the ones it started with.
func TestDHCPServiceRebindKeepsInPlaceReservations(t *testing.T) {
	service, listens, _ := newTestDHCPService(t, "")
	ctx := context.Background()
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
		t.Fatal(err)
	}
	waitDHCPEvents(t, listens, []string{"listen"})
	reserved := dhcpTestSettings(t)
	reserved.Scopes[0].Reservations = []config.DHCPReservation{{MAC: dhcpTestMAC.String(), Address: "10.0.7.50"}}
	if err := service.Apply(ctx, ctx, reserved); err != nil {
		t.Fatal(err)
	}
	_ = listens.last().Close()
	waitDHCPEvents(t, listens, []string{"listen", "close", "listen"})
	conn := listens.last()
	conn.inbound <- dhcpTestPacket(dhcp.Discover).Marshal()
	<-conn.wrote
	_, sent := conn.snapshot()
	if got, want := sent[0].reply.YIAddr, netip.MustParseAddr("10.0.7.50"); got != want {
		t.Fatalf("after a rebind the client is offered %v; want its reservation %v", got, want)
	}
}

// Taking new reservations withdraws a pending offer of an address that is
// now reserved for another client, so it isn't offered again (RFC 2131
// §4.3.1: a server should not offer an address it would NAK).
func TestEngineRescopeWithdrawsReservedOffer(t *testing.T) {
	settings := dhcpTestSettings(t)
	engine, err := dhcp.New(settings, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	meta := dhcp.Meta{Interface: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.7.2/24")}}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	offered := engine.Handle(now, dhcpTestPacket(dhcp.Discover), meta).Reply.YIAddr
	reserved := dhcpTestSettings(t)
	reserved.Scopes[0].Reservations = []config.DHCPReservation{{MAC: "02:00:00:00:00:99", Address: offered.String()}}
	next, err := dhcp.New(reserved, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	engine.Rescope(next)
	if again := engine.Handle(now.Add(time.Second), dhcpTestPacket(dhcp.Discover), meta).Reply.YIAddr; again == offered {
		t.Fatalf("after %v was reserved for another client it is still offered", offered)
	}
}
