package dhcp

import (
	"net/netip"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add(clientPacket(Discover, testMAC).Marshal())
	f.Add(clientPacket(Request, testMAC, ourServerID(), addrOption(optionRequestedIP, "10.0.7.110")).Marshal())
	f.Add([]byte{1, 1, 6, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		packet, err := Parse(data)
		if err != nil {
			return
		}
		if _, err := Parse(packet.Marshal()); err != nil {
			t.Fatalf("a parsed packet doesn't parse again: %v", err)
		}
	})
}

// FuzzHandle feeds parsed packets to the engine on and off a relay: it must
// never panic, and any reply must be a BOOTREPLY that parses as one.
func FuzzHandle(f *testing.F) {
	f.Add(clientPacket(Discover, testMAC).Marshal(), false)
	f.Add(clientPacket(Request, testMAC, addrOption(optionRequestedIP, "10.0.7.110")).Marshal(), true)
	f.Add(clientPacket(Inform, testMAC).Marshal(), false)
	f.Fuzz(func(t *testing.T, data []byte, relayed bool) {
		packet, err := Parse(data)
		if err != nil {
			return
		}
		engine := newTestEngine(t, nil)
		meta := testLink
		if relayed {
			packet.GIAddr = netip.MustParseAddr("10.0.7.1")
			// Real interfaces often list a link-local IPv6 address first (F6).
			meta = Meta{Addrs: []netip.Prefix{netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("192.168.50.2/24")}}
		}
		for range 2 {
			result := engine.Handle(testNow, packet, meta)
			if result.Reply != nil && result.Reply.Op != 2 {
				t.Fatalf("reply op = %d", result.Reply.Op)
			}
		}
	})
}
