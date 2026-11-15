package app

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/drudge/sable/internal/dhcp"
	"github.com/drudge/sable/internal/store"
)

// bindDHCPTestClient runs DISCOVER and REQUEST for mac on the service's
// current socket and returns the acknowledged address.
func bindDHCPTestClient(t *testing.T, conn *fakeDHCPConn, mac net.HardwareAddr) netip.Addr {
	t.Helper()
	discover := dhcpTestPacket(dhcp.Discover)
	discover.CHAddr = mac
	conn.inbound <- discover.Marshal()
	<-conn.wrote
	_, sent := conn.snapshot()
	request := dhcpTestRequest(sent[len(sent)-1].reply)
	request.CHAddr = mac
	conn.inbound <- request.Marshal()
	<-conn.wrote
	_, sent = conn.snapshot()
	ack := sent[len(sent)-1].reply
	if ack.MessageType() != dhcp.Ack {
		t.Fatalf("got %v; want an ACK", ack.MessageType())
	}
	return ack.YIAddr
}

// Removing a lease on a running server frees the address in the engine and
// writes the row released, so another client is acknowledged on it and a
// restart doesn't bring the lease back.
func TestDHCPServiceRemovesLeaseWhileServing(t *testing.T) {
	service, listens, database := newTestDHCPService(t, "")
	ctx := context.Background()
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
		t.Fatal(err)
	}
	conn := listens.last()
	address := bindDHCPTestClient(t, conn, dhcpTestMAC)
	if status := service.Status(); !status.Enabled || !status.Serving {
		t.Fatalf("status = %+v; want enabled and serving", status)
	}
	removed, err := service.RemoveLease(ctx, address)
	if err != nil || !removed {
		t.Fatalf("RemoveLease(%s) = %v, %v; want removed", address, removed, err)
	}
	rows, err := database.DHCPLeases(ctx)
	if err != nil || len(rows) != 1 || rows[0].State != store.DHCPLeaseReleased {
		t.Fatalf("store = %+v (%v); want the lease released", rows, err)
	}
	other := net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	request := dhcpTestPacket(dhcp.Request, dhcp.Option{Code: 50, Data: address.AsSlice()})
	request.CHAddr, request.XID = other, [4]byte{1, 2, 3, 4}
	conn.inbound <- request.Marshal()
	<-conn.wrote
	if _, sent := conn.snapshot(); sent[len(sent)-1].reply.MessageType() != dhcp.Ack {
		t.Fatalf("another client asking for the removed %s got %v; want an ACK", address, sent[len(sent)-1].reply.MessageType())
	}
	if removed, err := service.RemoveLease(ctx, netip.MustParseAddr("10.0.7.250")); removed || err != nil {
		t.Fatalf("removing an address with no lease = %v, %v; want false, nil", removed, err)
	}
}

// With the server off there's no engine, so the store row is released
// directly and a server started later doesn't serve the lease.
func TestDHCPServiceRemovesStoredLeaseWhileStopped(t *testing.T) {
	service, _, database := newTestDHCPService(t, "")
	ctx := context.Background()
	now := time.Now()
	address := netip.MustParseAddr("10.0.7.105")
	if _, err := database.SaveDHCPLease(ctx, store.DHCPLease{
		NodeID: "node-a", Address: address, ScopeID: "lan", ClientKey: "01" + dhcpTestMAC.String(), MAC: dhcpTestMAC.String(),
		State: store.DHCPLeaseActive, BoundAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	removed, err := service.RemoveLease(ctx, address)
	rows, _ := database.DHCPLeases(ctx)
	if err != nil || !removed || len(rows) != 1 || rows[0].State != store.DHCPLeaseReleased {
		t.Fatalf("RemoveLease = %v, %v; store %+v; want the row released", removed, err, rows)
	}
	if removed, err := service.RemoveLease(ctx, address); removed || err != nil {
		t.Fatalf("second removal = %v, %v; want false, nil", removed, err)
	}
}

// A removal sent after the server stopped is refused, never sent on the
// closed queue.
func TestDHCPServerRefusesSubmitAfterStop(t *testing.T) {
	harness := startDHCPServer(t, func(context.Context, []dhcp.Lease) error { return nil }, nil)
	harness.cancel()
	err := <-harness.done
	harness.done <- err // for the cleanup's stop
	removal := &dhcpRemoval{address: netip.MustParseAddr("10.0.7.100"), done: make(chan dhcpRemoved, 1)}
	if harness.server.submit(context.Background(), dhcpRequest{remove: removal}) {
		t.Fatal("submit after stop reported queued")
	}
	if harness.server.accepting() {
		t.Fatal("a stopped server reports accepting")
	}
}
