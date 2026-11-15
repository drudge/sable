package dhcp

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/config"
)

// testLabel stands in for the app's rule: lowercase, and a lease never
// takes wpad (D39) while a reservation may.
func testLabel(name string, reserved bool) string {
	label := strings.ToLower(name)
	if !reserved && label == "wpad" {
		return ""
	}
	return label
}

func wireName(labels ...string) []byte {
	var out []byte
	for _, label := range labels {
		out = append(append(out, byte(len(label))), label...)
	}
	return out
}

func fqdnOption(flags uint8, name []byte) Option {
	return Option{Code: optionClientFQDN, Data: append([]byte{flags, 0, 0}, name...)}
}

// TestClientFQDNReply checks the option 81 answer in OFFER and ACK against
// RFC 4702 §4 and the lease name against §4's "ignore option 12".
func TestClientFQDNReply(t *testing.T) {
	reserved, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	cases := []struct {
		name      string
		mac       net.HardwareAddr
		edit      func(*config.DHCPScope)
		options   []Option
		flags     uint8
		domain    []byte
		hostname  string
		noLabeler bool
	}{
		{name: "wire, server updates", mac: testMAC,
			options: []Option{fqdnOption(fqdnE|fqdnS, wireName("Laptop"))},
			flags:   fqdnE | fqdnS, domain: append(wireName("laptop", "lan", "example", "com"), 0), hostname: "Laptop"},
		{name: "client asks to update A itself: server overrides", mac: testMAC,
			options: []Option{fqdnOption(fqdnE, append(wireName("laptop", "home", "arpa"), 0))},
			flags:   fqdnE | fqdnS | fqdnO, domain: append(wireName("laptop", "lan", "example", "com"), 0), hostname: "laptop"},
		{name: "client asks for no updates: server overrides", mac: testMAC,
			options: []Option{fqdnOption(fqdnE|fqdnN, wireName("laptop"))},
			flags:   fqdnE | fqdnS | fqdnO, domain: append(wireName("laptop", "lan", "example", "com"), 0), hostname: "laptop"},
		{name: "deprecated ASCII answered in ASCII", mac: testMAC,
			options: []Option{fqdnOption(fqdnS, []byte("laptop.home.arpa"))},
			flags:   fqdnS, domain: []byte("laptop.lan.example.com"), hostname: "laptop"},
		{name: "FQDN wins over option 12", mac: testMAC,
			options: []Option{{Code: optionHostname, Data: []byte("other")}, fqdnOption(fqdnE|fqdnS, wireName("laptop"))},
			flags:   fqdnE | fqdnS, domain: append(wireName("laptop", "lan", "example", "com"), 0), hostname: "laptop"},
		{name: "empty FQDN falls back to option 12", mac: testMAC,
			options: []Option{{Code: optionHostname, Data: []byte("printer")}, fqdnOption(fqdnE|fqdnS, nil)},
			flags:   fqdnE | fqdnS, domain: append(wireName("printer", "lan", "example", "com"), 0), hostname: "printer"},
		{name: "reservation's name beats the client's", mac: reserved,
			options: []Option{fqdnOption(fqdnE|fqdnS, wireName("whatever"))},
			flags:   fqdnE | fqdnS, domain: append(wireName("nas", "lan", "example", "com"), 0), hostname: "whatever"},
		{name: "lease named wpad registers nothing (D39)", mac: testMAC,
			options: []Option{fqdnOption(fqdnE|fqdnS, wireName("wpad"))},
			flags:   fqdnE | fqdnN | fqdnO, domain: wireName("wpad"), hostname: "wpad"},
		{name: "reservation may be wpad (D39)", mac: reserved,
			edit:    func(scope *config.DHCPScope) { scope.Reservations[0].Name = "wpad" },
			options: []Option{fqdnOption(fqdnE|fqdnS, wireName("wpad"))},
			flags:   fqdnE | fqdnS, domain: append(wireName("wpad", "lan", "example", "com"), 0), hostname: "wpad"},
		{name: "scope registers no names", mac: testMAC,
			edit:    func(scope *config.DHCPScope) { off := false; scope.RegisterNames = &off },
			options: []Option{fqdnOption(fqdnE|fqdnS, wireName("laptop"))},
			flags:   fqdnE | fqdnN | fqdnO, domain: wireName("laptop"), hostname: "laptop"},
		{name: "no labeler registers nothing", mac: testMAC, noLabeler: true,
			options: []Option{fqdnOption(fqdnE, wireName("laptop"))},
			flags:   fqdnE | fqdnN, domain: wireName("laptop"), hostname: "laptop"},
		{name: "compression pointer is no label", mac: testMAC,
			options: []Option{{Code: optionHostname, Data: []byte("printer")}, fqdnOption(fqdnE|fqdnS, []byte{0xc0, 0x0c})},
			flags:   fqdnE | fqdnS, domain: append(wireName("printer", "lan", "example", "com"), 0), hostname: "printer"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			engine := newTestEngine(t, test.edit)
			if !test.noLabeler {
				engine.SetLabeler(testLabel)
			}
			offer := engine.Handle(testNow, clientPacket(Discover, test.mac, test.options...), testLink)
			if offer.Reply == nil {
				t.Fatalf("no OFFER: %s", offer.Drop)
			}
			request := clientPacket(Request, test.mac, append(test.options, ourServerID(), addrOption(optionRequestedIP, offer.Reply.YIAddr.String()))...)
			ack := engine.Handle(testNow, request, testLink)
			for kind, reply := range map[string]*Packet{"OFFER": offer.Reply, "ACK": ack.Reply} {
				data, found := reply.Option(optionClientFQDN)
				if !found {
					t.Fatalf("%s has no option 81", kind)
				}
				want := append([]byte{test.flags, 255, 255}, test.domain...)
				if !bytes.Equal(data, want) {
					t.Errorf("%s option 81 = %v, want %v", kind, data, want)
				}
			}
			if got := lastSave(ack).Hostname; got != test.hostname {
				t.Errorf("lease hostname = %q, want %q", got, test.hostname)
			}
		})
	}
}

// TestNoFQDNOptionUnasked: RFC 4702 §4 answers only a client that sent it.
func TestNoFQDNOptionUnasked(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.SetLabeler(testLabel)
	offer := engine.Handle(testNow, clientPacket(Discover, testMAC, Option{Code: optionHostname, Data: []byte("laptop")}), testLink)
	if _, found := offer.Reply.Option(optionClientFQDN); found {
		t.Fatal("OFFER carries option 81 the client never sent")
	}
}
