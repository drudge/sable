package dhcp

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
)

// A host that already holds a lease under a client identifier that isn't
// its MAC (systemd-networkd, dhcpcd and UEFI send RFC 4361 DUIDs) keeps
// working when the admin reserves an address for its MAC (F13).
var reservingClientID = Option{Code: optionClientID, Data: []byte{0xff, 1, 2, 3, 4, 0, 2, 0, 0, 0xab, 0x11, 9, 9, 9, 9}}

// reserveAndReload binds testMAC under reservingClientID, then reloads the
// engine with a reservation for testMAC at reserve (or at the bound address
// when reserve is empty), carrying the leases over as a config reload does.
func reserveAndReload(t *testing.T, reserve string) (*Engine, netip.Addr, netip.Addr) {
	t.Helper()
	before := newTestEngine(t, nil)
	held := bind(t, before, testMAC, reservingClientID)
	if reserve == "" {
		reserve = held.String()
	}
	after := newTestEngine(t, func(settings *config.DHCPScope) {
		settings.Reservations = append(settings.Reservations,
			config.DHCPReservation{MAC: testMAC.String(), Address: reserve, Name: "host"})
	})
	after.Load(before.Leases())
	return after, held, netip.MustParseAddr(reserve)
}

func renew(engine *Engine, now time.Time, address netip.Addr) Result {
	request := clientPacket(Request, testMAC, reservingClientID)
	request.CIAddr = address
	return engine.Handle(now, request, testLink)
}

func TestReview618ReservingTheHeldAddressKeepsIt(t *testing.T) {
	engine, held, _ := reserveAndReload(t, "")
	answer := renew(engine, testNow.Add(30*time.Minute), held)
	if answer.Reply == nil || answer.Reply.MessageType() != Ack || answer.Reply.YIAddr != held {
		offered, _ := offerThenRequest(t, engine, testNow.Add(31*time.Minute), testMAC, reservingClientID)
		t.Fatalf("renewing its own reserved %s: answer %+v drop %q; after that it was offered %s", held, answer.Reply, answer.Drop, offered)
	}
	if active := activeFor(engine, testMAC.String()); len(active) != 1 || active[0] != held {
		t.Fatalf("active leases for %s = %v, want only %s", testMAC, active, held)
	}
}

func TestReview618ReservingElsewhereReleasesTheOldLease(t *testing.T) {
	engine, held, reserved := reserveAndReload(t, "10.0.7.21")
	now := testNow.Add(30 * time.Minute)
	stored := map[netip.Addr]Lease{}
	for _, lease := range engine.Leases() {
		stored[lease.Address] = lease
	}
	renew(engine, now, held) // NAKed toward the free reservation (D17)
	offered, answer := offerThenRequest(t, engine, now, testMAC, reservingClientID)
	if offered != reserved || answer.Reply == nil || answer.Reply.MessageType() != Ack {
		t.Fatalf("after the NAK: offered %s, answer %+v drop %q; want %s ACKed", offered, answer.Reply, answer.Drop, reserved)
	}
	for _, lease := range answer.Save {
		stored[lease.Address] = lease
	}
	if active := activeFor(engine, testMAC.String()); len(active) != 1 || active[0] != reserved {
		t.Fatalf("engine: active leases for %s = %v, want only %s", testMAC, active, reserved)
	}
	if row := stored[held]; row.State == LeaseActive && row.ExpiresAt.After(now) {
		t.Fatalf("store: %s is still active for %s after it moved to %s", held, testMAC, reserved)
	}
}

func activeFor(engine *Engine, mac string) []netip.Addr {
	var active []netip.Addr
	now := testNow.Add(30 * time.Minute)
	for _, lease := range engine.Leases() {
		if strings.EqualFold(lease.MAC, mac) && lease.State == LeaseActive && lease.ExpiresAt.After(now) {
			active = append(active, lease.Address)
		}
	}
	return active
}
