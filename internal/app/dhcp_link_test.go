package app

import (
	"net"
	"testing"
)

// The loopback interface reports 127.0.0.1/8 as an IPv4 prefix, whatever
// length the kernel hands its mask back in.
func TestDHCPLinkReadsIPv4Prefixes(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range interfaces {
		if device.Flags&net.FlagLoopback == 0 {
			continue
		}
		meta, err := dhcpLink(device.Index)
		if err != nil {
			t.Fatal(err)
		}
		for _, prefix := range meta.Addrs {
			if prefix.String() == "127.0.0.1/8" {
				return
			}
		}
		t.Fatalf("loopback prefixes = %v; want 127.0.0.1/8", meta.Addrs)
	}
	t.Skip("no loopback interface")
}
