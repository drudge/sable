package web

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestClusterDNSAddressDefaults(t *testing.T) {
	local := []netip.Addr{netip.MustParseAddr("192.168.1.4"), netip.MustParseAddr("2001:db8::4"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fe80::4")}
	for _, tc := range []struct {
		name            string
		listeners, want []string
	}{
		{"IPv4 wildcard", []string{"0.0.0.0:53"}, []string{"192.168.1.4"}},
		{"IPv6 wildcard", []string{"[::]:5353"}, []string{"[2001:db8::4]:5353"}},
		{"explicit loopback demo", []string{"127.0.0.1:17353"}, []string{"127.0.0.1:17353"}},
		{"duplicates", []string{"0.0.0.0:53", "192.168.1.4:53"}, []string{"192.168.1.4"}},
		{"invalid", []string{"bad", "0.0.0.0:0", "[fe80::4%en0]:53"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := clusterDNSAddressDefaults(tc.listeners, local); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
