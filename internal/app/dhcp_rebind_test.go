package app

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dhcp"
)

// Review of #630. A reservation applied in place while the supervisor is
// binding again (it has built the next server from the settings it had, and
// that server isn't the current one yet) has to reach the server that ends
// up on port 67. The change starts when the rebind's listen call does, which
// is inside that window; listen gives it 200 ms, so a fix that makes the
// change wait for the bind passes as well as one that checks again after it.
func TestReview630ReservationDuringRebindReachesTheNewServer(t *testing.T) {
	service, listens, _ := newTestDHCPService(t, "")
	ctx := context.Background()
	reserved := dhcpTestSettings(t)
	reserved.Scopes[0].Reservations = []config.DHCPReservation{{MAC: dhcpTestMAC.String(), Address: "10.0.7.50"}}
	var calls atomic.Int32
	applied := make(chan error, 1)
	service.listen = func(ctx context.Context, port int) (dhcpConn, error) {
		if calls.Add(1) == 2 {
			done := make(chan struct{})
			go func() {
				applied <- service.Apply(ctx, ctx, reserved)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(200 * time.Millisecond):
			}
		}
		return listens.listen(ctx, port)
	}
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
		t.Fatal(err)
	}
	waitDHCPEvents(t, listens, []string{"listen"})
	_ = listens.last().Close()
	waitDHCPEvents(t, listens, []string{"listen", "close", "listen"})
	if err := <-applied; err != nil {
		t.Fatal(err)
	}
	conn := listens.last()
	conn.inbound <- dhcpTestPacket(dhcp.Discover).Marshal()
	<-conn.wrote
	_, sent := conn.snapshot()
	if got, want := sent[0].reply.YIAddr, netip.MustParseAddr("10.0.7.50"); got != want {
		t.Fatalf("a reservation saved while the server was binding again is not served: the client is offered %v; want its reservation %v (settings say %v)",
			got, want, service.active.Scopes[0].Reservations)
	}
}

// Review of #630. Reservation changes land while requests are being
// answered: nothing races, the socket is bound once, and every DISCOVER is
// answered.
func TestReview630ReservationEditsUnderLoad(t *testing.T) {
	service, listens, _ := newTestDHCPService(t, "")
	ctx := context.Background()
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
		t.Fatal(err)
	}
	waitDHCPEvents(t, listens, []string{"listen"})
	conn := listens.last()
	var group sync.WaitGroup
	group.Go(func() {
		for index := range 200 {
			next := dhcpTestSettings(t)
			if index%2 == 0 {
				next.Scopes[0].Reservations = []config.DHCPReservation{{MAC: "02:00:00:00:00:99", Address: "10.0.7.60", Name: "nas"}}
			}
			if err := service.Apply(ctx, ctx, next); err != nil {
				t.Error(err)
			}
		}
	})
	answered := 0
	for index := range 200 {
		discover := dhcpTestPacket(dhcp.Discover)
		discover.XID = [4]byte{9, 9, byte(index >> 8), byte(index)}
		conn.inbound <- discover.Marshal()
		select {
		case <-conn.wrote:
			answered++
		case <-time.After(2 * time.Second):
		}
	}
	group.Wait()
	if answered != 200 {
		t.Fatalf("%d of 200 DISCOVERs answered during reservation edits", answered)
	}
	waitDHCPEvents(t, listens, []string{"listen"})
}
