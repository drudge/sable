package dhcp

import (
	"net"
	"testing"
)

// An operator removing a lease frees the address for another client at once,
// and saves the row released so the store agrees with the engine.
func TestRemoveFreesTheAddress(t *testing.T) {
	engine := newTestEngine(t, nil)
	bound := bind(t, engine, testMAC)
	removed := engine.Remove(testNow, bound)
	if removed == nil || removed.State != LeaseReleased || !removed.ExpiresAt.Equal(testNow) {
		t.Fatalf("Remove(%s) = %+v; want the lease released now", bound, removed)
	}
	other := net.HardwareAddr{0, 0x33, 0, 0, 0, 1}
	taken := engine.Handle(testNow, clientPacket(Request, other, addrOption(optionRequestedIP, bound.String())), testLink)
	if taken.Reply == nil || taken.Reply.MessageType() != Ack {
		t.Fatalf("another client asking for the removed %s got %+v; want an ACK", bound, taken)
	}
	if again := engine.Remove(testNow, bound); again == nil {
		t.Fatal("the new holder's lease couldn't be removed")
	}
	if none := engine.Remove(testNow, bound); none != nil {
		t.Fatalf("removing a lease that no longer holds saved %+v; want nothing", none)
	}
}

// A pending offer of a removed address can't be acknowledged afterward.
func TestRemoveDropsPendingOffer(t *testing.T) {
	engine := newTestEngine(t, nil)
	conflict := engine.Handle(testNow, clientPacket(Discover, testMAC), testLink)
	address := conflict.Reply.YIAddr
	if saved := engine.Conflict(testNow, address, "echo"); saved == nil {
		t.Fatal("no conflict row")
	}
	if removed := engine.Remove(testNow, address); removed == nil {
		t.Fatalf("declined %s not removed", address)
	}
	for ref, pending := range engine.offers {
		if pending.address == address {
			t.Fatalf("offer to %v of %s survived removal", ref, address)
		}
	}
}
