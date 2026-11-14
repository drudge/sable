package dhcp

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/drudge/sable/internal/config"
)

// Findings F7–F10 from the #618 review.

// F7: options 12 and 60 reach the store as text PostgreSQL accepts.
func TestReview618LeaseTextIsStorable(t *testing.T) {
	for name, raw := range map[string]string{
		"nul":     "printer\x00",
		"invalid": "a\xff\xfeb",
		"control": "a\x1b[31mb\n",
	} {
		t.Run(name, func(t *testing.T) {
			engine := newTestEngine(t, nil)
			offer := engine.Handle(testNow, clientPacket(Discover, testMAC), testLink)
			request := clientPacket(Request, testMAC, ourServerID(), addrOption(optionRequestedIP, offer.Reply.YIAddr.String()),
				Option{Code: optionHostname, Data: []byte(raw)}, Option{Code: optionVendorClass, Data: []byte(raw)})
			result := engine.Handle(testNow, request, testLink)
			if len(result.Save) == 0 {
				t.Fatalf("no lease saved: %s", result.Drop)
			}
			saved := result.Save[len(result.Save)-1]
			for field, text := range map[string]string{"hostname": saved.Hostname, "vendor_class": saved.VendorClass} {
				if !utf8.ValidString(text) || strings.ContainsFunc(text, unicode.IsControl) || text == "" {
					t.Errorf("%s saved as %q: not valid UTF-8 text without control characters", field, text)
				}
			}
		})
	}
}

// F8: replaying every saved lease gives the store the engine's own view.
func TestReview618SavedLeasesReplayToTheEngineView(t *testing.T) {
	engine := newTestEngine(t, nil)
	store := map[netip.Addr]Lease{}
	keep := func(result Result) {
		for _, lease := range result.Save {
			store[lease.Address] = lease
		}
	}
	offer := engine.Handle(testNow, clientPacket(Discover, testMAC), testLink)
	keep(engine.Handle(testNow, clientPacket(Request, testMAC, ourServerID(),
		addrOption(optionRequestedIP, offer.Reply.YIAddr.String())), testLink))
	moved := "10.0.7.112"
	if offer.Reply.YIAddr.String() == moved {
		moved = "10.0.7.113"
	}
	later := testNow.Add(time.Minute)
	ack := engine.Handle(later, clientPacket(Request, testMAC, addrOption(optionRequestedIP, moved)), testLink)
	if ack.Reply == nil || ack.Reply.MessageType() != Ack {
		t.Fatalf("INIT-REBOOT to %s not ACKed: %s", moved, ack.Drop)
	}
	keep(ack)
	for _, lease := range engine.Leases() {
		saved, found := store[lease.Address]
		if !found || saved.State != lease.State || !saved.ExpiresAt.Equal(lease.ExpiresAt) {
			t.Errorf("%s: engine says %s until %s, the store was told %s until %s", lease.Address,
				lease.State, lease.ExpiresAt.Format(time.TimeOnly), saved.State, saved.ExpiresAt.Format(time.TimeOnly))
		}
	}
}

// F9: a 576-octet OFFER keeps DNS and option 108 over a big vendor option.
func TestReview618SmallReplyKeepsDNSAnd108(t *testing.T) {
	engine := newTestEngine(t, func(scope *config.DHCPScope) {
		scope.IPv6OnlyPreferred = config.Duration{Duration: 30 * time.Minute}
		scope.Options = append(scope.Options, config.DHCPOption{Code: 43, Hex: strings.Repeat("ab", 255)})
	})
	asked := Option{Code: optionParameters, Data: []byte{1, 3, 6, 15, 28, 43, optionV6OnlyPrefer}}
	result := engine.Handle(testNow, clientPacket(Discover, testMAC, asked), testLink)
	if result.Reply == nil {
		t.Fatalf("no OFFER: %s", result.Drop)
	}
	if _, found := result.Reply.Option(optionV6OnlyPrefer); !found {
		t.Errorf("OFFER with yiaddr %s to a client that asked for option 108 doesn't carry it (RFC 8925 §3.3 MUST)", result.Reply.YIAddr)
	}
	if _, found := result.Reply.Option(optionDNS); !found {
		t.Error("OFFER dropped option 6")
	}
}

// F10: the client index stays as small as the lease view.
func TestReview618ClientIndexIsBounded(t *testing.T) {
	engine := newTestEngine(t, nil)
	now := testNow
	for index := range 600 {
		mac := net.HardwareAddr{0x00, 0x16, 0x3e, 0, byte(index >> 8), byte(index)}
		offer := engine.Handle(now, clientPacket(Discover, mac), testLink)
		if offer.Reply == nil {
			t.Fatalf("client %d: no OFFER: %s", index, offer.Drop)
		}
		engine.Handle(now, clientPacket(Request, mac, ourServerID(), addrOption(optionRequestedIP, offer.Reply.YIAddr.String())), testLink)
		now = now.Add(2 * time.Hour)
	}
	if leases, clients := len(engine.leases), len(engine.clients); leases > 13 || clients > 13 {
		t.Fatalf("after 600 clients through a 12-address pool: %d leases, %d client index entries; want at most 13 each", leases, clients)
	}
}
