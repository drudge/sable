package dhcp

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/drudge/sable/internal/config"
)

// Review probes for PR #618 (Blake). Findings fail; checks pass.

var reviewNAS = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01} // testScope's reservation, 10.0.7.20

// offerThenRequest runs DISCOVER and, when an OFFER comes back, the
// SELECTING REQUEST for exactly what was offered.
func offerThenRequest(t *testing.T, engine *Engine, now time.Time, mac net.HardwareAddr, options ...Option) (offered netip.Addr, answer Result) {
	t.Helper()
	offer := engine.Handle(now, clientPacket(Discover, mac, options...), testLink)
	if offer.Reply == nil {
		return netip.Addr{}, offer
	}
	offered = offer.Reply.YIAddr
	request := clientPacket(Request, mac, append(slicesClone(options), ourServerID(), addrOption(optionRequestedIP, offered.String()))...)
	return offered, engine.Handle(now, request, testLink)
}

func slicesClone(options []Option) []Option { return append([]Option(nil), options...) }

// A server must stand behind its own OFFER: the SELECTING REQUEST for the
// offered address gets an ACK, or the DISCOVER gets nothing. An OFFER
// followed by a NAK for the same address loops the client forever.
func TestReview618ServerNeverNAKsItsOwnOffer(t *testing.T) {
	check := func(t *testing.T, engine *Engine, now time.Time, options ...Option) {
		t.Helper()
		for round := range 3 {
			offered, answer := offerThenRequest(t, engine, now.Add(time.Duration(round)*10*time.Second), reviewNAS, options...)
			if !offered.IsValid() {
				return // silence is fine
			}
			if answer.Reply == nil || answer.Reply.MessageType() != Ack {
				message, _ := func() ([]byte, bool) {
					if answer.Reply == nil {
						return nil, false
					}
					return answer.Reply.Option(optionMessage)
				}()
				t.Fatalf("round %d: offered %s, then answered the REQUEST for it with %+v (%q, drop %q); want ACK",
					round, offered, answer.Reply, message, answer.Drop)
			}
		}
	}
	t.Run("reserved address still leased to another client", func(t *testing.T) {
		// The operator reserves .20 for the NAS while a phone holds it.
		engine := newTestEngine(t, nil)
		engine.Load([]Lease{{NodeID: "node-a", Address: netip.MustParseAddr("10.0.7.20"), ScopeID: "lan",
			ClientKey: "01001122334466", MAC: "00:11:22:33:44:66", State: LeaseActive,
			BoundAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Hour)}})
		check(t, engine, testNow)
	})
	t.Run("reserved client changes its client identifier", func(t *testing.T) {
		// PXE firmware, then the OS: same MAC, different option 61.
		engine := newTestEngine(t, nil)
		firmware := Option{Code: optionClientID, Data: append([]byte{1}, reviewNAS...)}
		if got := bind(t, engine, reviewNAS, firmware); got != netip.MustParseAddr("10.0.7.20") {
			t.Fatalf("firmware bound %s; want the reservation", got)
		}
		system := Option{Code: optionClientID, Data: []byte{0xff, 1, 2, 3, 4, 0, 2, 0, 0, 0xab, 0x11, 9, 9, 9, 9}}
		check(t, engine, testNow.Add(time.Minute), system)
	})
	t.Run("reserved client declined its reservation", func(t *testing.T) {
		engine := newTestEngine(t, nil)
		bind(t, engine, reviewNAS)
		declined := engine.Handle(testNow, clientPacket(Decline, reviewNAS, ourServerID(), addrOption(optionRequestedIP, "10.0.7.20")), testLink)
		if lastSave(declined) == nil || lastSave(declined).State != LeaseDeclined {
			t.Fatalf("decline not recorded: %+v", declined)
		}
		check(t, engine, testNow.Add(time.Minute))
	})
}

// A reserved client keeps its reservation across a client identifier change:
// the reservation is by MAC, so the lease on it is the same machine's.
func TestReview618ReservationSurvivesClientIDChange(t *testing.T) {
	engine := newTestEngine(t, nil)
	firmware := Option{Code: optionClientID, Data: append([]byte{1}, reviewNAS...)}
	bind(t, engine, reviewNAS, firmware)
	system := Option{Code: optionClientID, Data: []byte{0xff, 1, 2, 3, 4, 0, 2, 0, 0, 0xab, 0x11, 9, 9, 9, 9}}
	offered, answer := offerThenRequest(t, engine, testNow.Add(time.Minute), reviewNAS, system)
	if offered != netip.MustParseAddr("10.0.7.20") || answer.Reply == nil || answer.Reply.MessageType() != Ack {
		t.Fatalf("after the OS took over from PXE: offered %s, answer %+v drop %q; want 10.0.7.20 ACKed", offered, answer.Reply, answer.Drop)
	}
}

// Whatever Handle returns in Save is all the store ever sees. Replaying the
// saved rows (keyed like the store: node, address) must give the engine's
// own view, or a restart brings back leases the engine had ended.
func TestReview618SavedLeasesReplayToTheEngineView(t *testing.T) {
	engine := newTestEngine(t, nil)
	stored := map[netip.Addr]Lease{}
	handle := func(now time.Time, packet Packet) Result {
		result := engine.Handle(now, packet, testLink)
		for _, lease := range result.Save {
			stored[lease.Address] = lease
		}
		return result
	}
	offer := handle(testNow, clientPacket(Discover, testMAC))
	first := offer.Reply.YIAddr
	handle(testNow, clientPacket(Request, testMAC, ourServerID(), addrOption(optionRequestedIP, first.String())))
	// The client comes back asking for another free address in the range
	// (INIT-REBOOT after it was set by hand, or a new reservation).
	second := netip.MustParseAddr("10.0.7.118")
	if second == first {
		second = netip.MustParseAddr("10.0.7.117")
	}
	moved := handle(testNow.Add(time.Minute), clientPacket(Request, testMAC, addrOption(optionRequestedIP, second.String())))
	if moved.Reply == nil || moved.Reply.MessageType() != Ack {
		t.Fatalf("move to %s not ACKed: %+v", second, moved)
	}
	for _, lease := range engine.Leases() {
		row, found := stored[lease.Address]
		if !found {
			t.Errorf("engine holds %s (%s) but nothing was saved for it", lease.Address, lease.State)
			continue
		}
		if row.State != lease.State || !row.ExpiresAt.Equal(lease.ExpiresAt) {
			t.Errorf("%s: engine says %s until %s, the store was told %s until %s", lease.Address,
				lease.State, lease.ExpiresAt.Format(time.TimeOnly), row.State, row.ExpiresAt.Format(time.TimeOnly))
		}
	}
}

// Lease text goes into TEXT columns (Postgres rejects NUL and bad UTF-8) and
// later into DNS names and the console. Option 12 and 60 are raw bytes from
// the network; some clients send a trailing NUL.
func TestReview618LeaseTextIsStorable(t *testing.T) {
	for name, payload := range map[string][]byte{
		"trailing NUL": []byte("printer\x00"), "bad UTF-8": {'t', 'v', 0xff, 0xfe}, "control": []byte("a\x1b[31mb\n"),
	} {
		t.Run(name, func(t *testing.T) {
			engine := newTestEngine(t, nil)
			offer := engine.Handle(testNow, clientPacket(Discover, testMAC), testLink)
			ack := engine.Handle(testNow, clientPacket(Request, testMAC, ourServerID(),
				addrOption(optionRequestedIP, offer.Reply.YIAddr.String()),
				Option{Code: optionHostname, Data: payload}, Option{Code: optionVendorClass, Data: payload}), testLink)
			if lastSave(ack) == nil {
				t.Fatalf("no lease saved: %+v", ack)
			}
			for field, value := range map[string]string{"hostname": lastSave(ack).Hostname, "vendor_class": lastSave(ack).VendorClass} {
				if !utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
					t.Errorf("%s saved as %q: not valid UTF-8 text without control characters", field, value)
				}
			}
		})
	}
}

// With a small reply budget (no option 57: 576 bytes) and a large vendor
// option, the options a client can't work without must be the last to go.
func TestReview618SmallReplyKeepsDNSAnd108(t *testing.T) {
	engine := newTestEngine(t, func(scope *config.DHCPScope) {
		scope.IPv6OnlyPreferred = config.Duration{Duration: 30 * time.Minute}
		scope.DNS = []string{"10.0.7.2", "10.0.7.3"}
		scope.Search = []string{"lan.example.com", "corp.example.com", "eng.corp.example.com"}
		scope.Options = []config.DHCPOption{{Code: 43, Hex: strings.Repeat("ab", 180)}}
	})
	asked := Option{Code: optionParameters, Data: []byte{1, 3, 6, 15, 42, 43, 119, 121}}
	offer := engine.Handle(testNow, clientPacket(Discover, testMAC, asked), testLink)
	if offer.Reply == nil {
		t.Fatalf("no offer: %s", offer.Drop)
	}
	if _, found := offer.Reply.Option(optionDNS); !found {
		var kept []uint8
		for _, option := range offer.Reply.Options {
			kept = append(kept, option.Code)
		}
		t.Errorf("OFFER for %s has no DNS servers (option 6); kept options %v", offer.Reply.YIAddr, kept)
	}
	asked108 := Option{Code: optionParameters, Data: []byte{1, 3, 6, 15, 42, 43, 119, 121, 108}}
	v6 := engine.Handle(testNow, clientPacket(Discover, testMAC, asked108), testLink)
	if v6.Reply == nil {
		t.Fatalf("no offer: %s", v6.Drop)
	}
	if _, found := v6.Reply.Option(optionV6OnlyPrefer); !found {
		t.Errorf("OFFER with yiaddr %s to a client that asked for option 108 doesn't carry it (RFC 8925 §3.3 MUST)", v6.Reply.YIAddr)
	}
}

// The engine's maps must stay bounded by the pool, not by how many clients
// ever passed through (phones rotate MACs per network and per day).
func TestReview618ClientIndexIsBounded(t *testing.T) {
	engine := newTestEngine(t, nil)
	now := testNow
	for round := range 50 {
		for index := range 12 {
			mac := net.HardwareAddr{0, 0x44, byte(round >> 8), byte(round), 0, byte(index)}
			offer := engine.Handle(now, clientPacket(Discover, mac), testLink)
			if offer.Reply == nil {
				t.Fatalf("round %d client %d: no offer: %s", round, index, offer.Drop)
			}
			engine.Handle(now, clientPacket(Request, mac, ourServerID(), addrOption(optionRequestedIP, offer.Reply.YIAddr.String())), testLink)
		}
		now = now.Add(2 * time.Hour) // every lease (1 h) has expired
	}
	if len(engine.leases) > 13 || len(engine.clients) > 13 {
		t.Fatalf("after 600 clients through a 12-address pool: %d leases, %d client index entries; want at most 13 each",
			len(engine.leases), len(engine.clients))
	}
}

// ---- checks (expected to pass) ----

func TestReview618WireFormat(t *testing.T) {
	long := bytes.Repeat([]byte{0x5a}, 300)
	relay := []byte{1, 4, 'e', 't', 'h', '9'}
	packet := Packet{Op: 2, HType: 1, XID: [4]byte{9, 9, 9, 9}, CHAddr: testMAC,
		CIAddr: netip.IPv4Unspecified(), YIAddr: netip.MustParseAddr("10.0.7.110"),
		SIAddr: netip.IPv4Unspecified(), GIAddr: netip.MustParseAddr("10.0.7.1"),
		Options: []Option{{Code: optionRelayInfo, Data: relay}, {Code: optionMessageType, Data: []byte{byte(Ack)}},
			{Code: 43, Data: long}, {Code: optionServerID, Data: []byte{10, 0, 7, 2}}}}
	wire := packet.Marshal()
	if len(wire) < 300 {
		t.Errorf("marshalled %d bytes; BOOTP minimum is 300", len(wire))
	}
	// Walk the options by hand: 43 must be split, 82 must be last before END.
	options := wire[240:]
	var codes []byte
	var got43 []byte
	for len(options) > 0 && options[0] != 255 {
		if options[0] == 0 {
			options = options[1:]
			continue
		}
		code, length := options[0], int(options[1])
		if code == 43 {
			got43 = append(got43, options[2:2+length]...)
		}
		codes = append(codes, code)
		options = options[2+length:]
	}
	if !bytes.Equal(got43, long) {
		t.Errorf("option 43: %d bytes on the wire, want 300 split per RFC 3396", len(got43))
	}
	if len(codes) == 0 || codes[len(codes)-1] != optionRelayInfo {
		t.Errorf("option order %v; option 82 must be last (RFC 3046 §2.1)", codes)
	}
}

func TestReview618ParseRejectsRepliesAndShortPackets(t *testing.T) {
	reply := Packet{Op: 2, HType: 1, CHAddr: testMAC, Options: []Option{{Code: optionMessageType, Data: []byte{byte(Offer)}}}}
	if _, err := Parse(reply.Marshal()); err == nil {
		t.Error("a BOOTREPLY parsed as a request")
	}
	wire := clientPacket(Discover, testMAC).Marshal()
	for _, cut := range []int{0, 1, 43, 235, 239, 240, 241} {
		if _, err := Parse(wire[:cut]); err == nil {
			t.Errorf("a %d-byte packet parsed", cut)
		}
	}
}

func TestReview618ExpiredLeaseIsReusedAndRenewalExtends(t *testing.T) {
	engine := newTestEngine(t, nil)
	holders := map[netip.Addr]bool{}
	for index := range 12 {
		holders[bind(t, engine, net.HardwareAddr{0, 0x22, 0, 0, 0, byte(index)})] = true
	}
	late := testNow.Add(61 * time.Minute)
	newcomer := net.HardwareAddr{0, 0x55, 0, 0, 0, 1}
	offered, answer := offerThenRequest(t, engine, late, newcomer)
	if !holders[offered] || answer.Reply == nil || answer.Reply.MessageType() != Ack {
		t.Fatalf("expired pool: offered %s, answer %+v; want a reused address ACKed", offered, answer)
	}
	// The old holder comes back for it: NAK, it's someone else's now.
	var old net.HardwareAddr
	for index := range 12 {
		mac := net.HardwareAddr{0, 0x22, 0, 0, 0, byte(index)}
		if engine.clients[clientRef{"lan", clientKey(clientPacket(Discover, mac), false)}] == offered {
			old = mac
		}
	}
	if old != nil {
		back := engine.Handle(late, clientPacket(Request, old, addrOption(optionRequestedIP, offered.String())), testLink)
		if back.Reply == nil || back.Reply.MessageType() != Nak {
			t.Fatalf("old holder's INIT-REBOOT for a reassigned address: %+v; want NAK", back)
		}
	}
	renew := clientPacket(Request, newcomer)
	renew.CIAddr = offered
	renewed := engine.Handle(late.Add(30*time.Minute), renew, testLink)
	if lastSave(renewed) == nil || !lastSave(renewed).ExpiresAt.Equal(late.Add(90*time.Minute)) || renewed.Destination != ToClient {
		t.Fatalf("renewal: %+v", renewed)
	}
}

func TestReview618ConcurrentHandle(t *testing.T) {
	engine := newTestEngine(t, nil)
	var group sync.WaitGroup
	for worker := range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range 200 {
				mac := net.HardwareAddr{0, 0x66, 0, byte(worker), byte(index >> 8), byte(index)}
				offer := engine.Handle(testNow, clientPacket(Discover, mac), testLink)
				if offer.Reply != nil {
					engine.Handle(testNow, clientPacket(Request, mac, ourServerID(), addrOption(optionRequestedIP, offer.Reply.YIAddr.String())), testLink)
				}
				engine.Leases()
				engine.Conflict(testNow, netip.MustParseAddr("10.0.7.119"), "echo")
			}
		}()
	}
	group.Wait()
	seen := map[string]netip.Addr{}
	for _, lease := range engine.Leases() {
		if lease.State != LeaseActive {
			continue
		}
		if other, dup := seen[lease.ClientKey]; dup {
			t.Fatalf("client %s holds %s and %s", lease.ClientKey, other, lease.Address)
		}
		seen[lease.ClientKey] = lease.Address
	}
}

// BenchmarkDiscoverFullLargePool measures one DISCOVER on a big exhausted
// pool with the offer table full: the per-packet cost a flood can force while
// the engine lock is held. A benchmark, not a test, so a loaded runner can't
// fail the suite on wall-clock time.
func BenchmarkDiscoverFullLargePool(b *testing.B) {
	enabled := true
	settings := config.DHCP{Enabled: true, Scopes: []config.DHCPScope{{
		ID: "big", Name: "Big", Subnet: "10.64.0.0/16", Enabled: &enabled, Lease: config.Duration{Duration: time.Hour},
		Router: "10.64.0.1", Ranges: []config.DHCPRange{{Start: "10.64.1.0", End: "10.64.255.254"}},
	}}}
	if err := settings.Validate(); err != nil {
		b.Fatalf("a /16 scope doesn't validate: %v", err)
	}
	engine, err := New(settings, "")
	if err != nil {
		b.Fatal(err)
	}
	link := Meta{Addrs: []netip.Prefix{netip.MustParsePrefix("10.64.0.2/16")}}
	var leases []Lease
	first := toUint(netip.MustParseAddr("10.64.1.0"))
	total := toUint(netip.MustParseAddr("10.64.255.254")) - first + 1
	for index := uint32(0); index < total-1024; index++ {
		leases = append(leases, Lease{NodeID: "", Address: fromUint(first + index), ScopeID: "big",
			ClientKey: "held" + fromUint(first+index).String(), State: LeaseActive, BoundAt: testNow, ExpiresAt: testNow.Add(time.Hour)})
	}
	engine.Load(leases)
	for index := range 1100 { // fill the last 1024 addresses with offers
		engine.Handle(testNow, clientPacket(Discover, net.HardwareAddr{0, 0x77, 0, 0, byte(index >> 8), byte(index)}), link)
	}
	b.ResetTimer()
	for index := range b.N {
		engine.Handle(testNow, clientPacket(Discover, net.HardwareAddr{0, 0x78, 0, 0, byte(index >> 8), byte(index)}), link)
	}
}

// lastSave is the lease a result binds: Handle returns old before new (D19).
func lastSave(result Result) *Lease {
	if len(result.Save) == 0 {
		return nil
	}
	return &result.Save[len(result.Save)-1]
}

// A reserved client moved to the pool (D17) gets only what a pool client
// would: no ACK for an on-link address outside this node's ranges, nor for
// the server's own address.
func TestReservedClientOffReservationKeepsPoolRules(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.Load([]Lease{{NodeID: "node-a", Address: netip.MustParseAddr("10.0.7.20"), ScopeID: "lan",
		ClientKey: "01001122334466", MAC: "00:11:22:33:44:66", State: LeaseActive,
		BoundAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Hour)}})
	for _, address := range []string{"10.0.7.250", "10.0.7.155", "10.0.7.2"} {
		answer := engine.Handle(testNow, clientPacket(Request, reviewNAS, addrOption(optionRequestedIP, address)), testLink)
		if answer.Reply != nil && answer.Reply.MessageType() == Ack {
			t.Errorf("ACKed %s for the reserved client while its reservation is taken", address)
		}
	}
}
