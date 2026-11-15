package app

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/drudge/sable/internal/dhcp"
)

// A lease never publishes wpad or isatap, any case or spelling the label
// cleans to, while a reservation named so does (D39).
func TestDHCPNamesLeaseNeverWPADOrISATAP(t *testing.T) {
	harness := newNamesHarness(t)
	harness.config.dhcp.Scopes[0].Reservations[0].Name = "WPAD"
	harness.set(
		namesTestLease("10.9.0.100", "02:00:00:00:00:01", "wpad", namesTestTime),
		namesTestLease("10.9.0.101", "02:00:00:00:00:02", "ISATAP", namesTestTime),
		namesTestLease("10.9.0.102", "02:00:00:00:00:03", "wpad.", namesTestTime),
		namesTestLease("10.9.0.103", "02:00:00:00:00:04", "laptop", namesTestTime),
	)
	harness.namer.reconcile(context.Background())
	assertRecords(t, harness.records("lan.example.com"),
		"laptop A 10.9.0.103 dhcp", "wpad A 10.9.0.10 dhcp")
}

func TestDHCPLabel(t *testing.T) {
	for _, test := range []struct {
		name     string
		reserved bool
		want     string
	}{
		{"Nick's Laptop", false, "nicks-laptop"},
		{"wpad", false, ""},
		{"Isatap", false, ""},
		{"wpad", true, "wpad"},
		{"isatap", true, "isatap"},
		{"wpad-proxy", false, "wpad-proxy"},
	} {
		if got := dhcpLabel(test.name, test.reserved); got != test.want {
			t.Errorf("dhcpLabel(%q, %v) = %q, want %q", test.name, test.reserved, got, test.want)
		}
	}
}

// The namer asks the UniFi sync to run when the names reservations publish
// change, so a UniFi record a new reservation now owns goes at once rather
// than at the next sync tick. Lease changes alone don't hit the controller.
func TestDHCPNamerKicksUniFiWhenReservedNamesChange(t *testing.T) {
	harness := newNamesHarness(t)
	kicks := 0
	harness.namer.kick = func() { kicks++ }
	harness.namer.reconcile(context.Background())
	if kicks != 0 {
		t.Fatalf("first reconcile kicked UniFi %d times; it syncs on its own at start", kicks)
	}
	harness.set(namesTestLease("10.9.0.100", "02:00:00:00:00:01", "laptop", namesTestTime))
	harness.namer.reconcile(context.Background())
	if kicks != 0 {
		t.Fatalf("a lease change kicked UniFi %d times", kicks)
	}
	harness.config.dhcp.Scopes[0].Reservations[0].Name = "scanner"
	harness.namer.reconcile(context.Background())
	if kicks != 1 {
		t.Fatalf("renamed reservation: %d kicks, want 1", kicks)
	}
	harness.config.dhcp.Enabled = false
	harness.namer.reconcile(context.Background())
	if kicks != 2 {
		t.Fatalf("DHCP off: %d kicks, want 2", kicks)
	}
	harness.namer.reconcile(context.Background())
	if kicks != 2 {
		t.Fatalf("unchanged state kicked again: %d kicks", kicks)
	}
}

// The engine prepare builds answers option 81 with the namer's label rule,
// so the name a client is told matches the one the namer publishes.
func TestDHCPEngineUsesNamerLabels(t *testing.T) {
	service := &dhcpService{node: func() string { return "n1" }}
	server, err := service.prepare(namesTestDHCP())
	if err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	link := dhcp.Meta{Interface: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/24")}}
	for hostname, want := range map[string]string{
		"Nick's Laptop": "\x0cnicks-laptop\x03lan\x07example\x03com\x00",
		"wpad":          "\x04wpad",
	} {
		name := append([]byte{byte(len(hostname))}, hostname...)
		discover := dhcp.Packet{Op: 1, HType: 1, CHAddr: mac,
			CIAddr: netip.IPv4Unspecified(), GIAddr: netip.IPv4Unspecified(),
			Options: []dhcp.Option{{Code: 53, Data: []byte{1}}, {Code: 81, Data: append([]byte{0x05, 0, 0}, name...)}}}
		offer := server.engine.Handle(namesTestTime, discover, link)
		if offer.Reply == nil {
			t.Fatalf("no OFFER: %s", offer.Drop)
		}
		data, found := offer.Reply.Option(81)
		if !found || len(data) < 3 || string(data[3:]) != want {
			t.Errorf("%q: option 81 = %q, want name %q", hostname, data, want)
		}
	}
}
