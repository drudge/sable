package dnsname

import (
	"net/netip"
	"testing"
)

func TestReverseZone(t *testing.T) {
	cases := []struct {
		prefix  string
		want    string
		wantErr bool
	}{
		{prefix: "192.168.1.0/24", want: "1.168.192.in-addr.arpa"},
		{prefix: "192.168.1.1/24", want: "1.168.192.in-addr.arpa"},
		{prefix: "10.0.0.0/16", want: "0.10.in-addr.arpa"},
		{prefix: "10.0.0.0/8", want: "10.in-addr.arpa"},
		{prefix: "192.168.10.0/26", want: "10.168.192.in-addr.arpa"},
		{prefix: "0.0.0.0/0", wantErr: true},
		{prefix: "fd00:abcd::/32", want: "d.c.b.a.0.0.d.f.ip6.arpa"},
		{prefix: "2001:db8::/48", want: "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"},
		{prefix: "::/0", wantErr: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.prefix, func(t *testing.T) {
			got, err := ReverseZone(netip.MustParsePrefix(testCase.prefix))
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("ReverseZone(%s) = %q, want an error", testCase.prefix, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReverseZone(%s): %v", testCase.prefix, err)
			}
			if got != testCase.want {
				t.Fatalf("ReverseZone(%s) = %q, want %q", testCase.prefix, got, testCase.want)
			}
		})
	}
}

func TestReverseName(t *testing.T) {
	cases := []struct {
		address string
		want    string
	}{
		{address: "192.168.1.50", want: "50.1.168.192.in-addr.arpa"},
		{address: "fd00::1", want: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"},
	}
	for _, testCase := range cases {
		got, err := ReverseName(netip.MustParseAddr(testCase.address))
		if err != nil {
			t.Fatalf("ReverseName(%s): %v", testCase.address, err)
		}
		if got != testCase.want {
			t.Fatalf("ReverseName(%s) = %q, want %q", testCase.address, got, testCase.want)
		}
	}
}

func TestReverseNameLandsInsideReverseZone(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.30.0/24")
	zone, err := ReverseZone(prefix)
	if err != nil {
		t.Fatalf("ReverseZone: %v", err)
	}
	name, err := ReverseName(netip.MustParseAddr("192.168.30.7"))
	if err != nil {
		t.Fatalf("ReverseName: %v", err)
	}
	if name != "7."+zone {
		t.Fatalf("ReverseName = %q, want it inside %q", name, zone)
	}
}
