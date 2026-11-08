package clustertest

import (
	"net"
	"os"
	"testing"
)

// Ports holds the loopback HTTP, HTTPS, and DNS listen addresses of one node.
type Ports struct {
	HTTP  string
	HTTPS string
	DNS   string
}

// AllocatePorts reserves three loopback TCP addresses.
func AllocatePorts(t *testing.T) Ports {
	t.Helper()
	return Ports{HTTP: AllocateTCPAddress(t), HTTPS: AllocateTCPAddress(t), DNS: AllocateTCPAddress(t)}
}

// AllocateTCPAddress reserves a free loopback TCP address.
func AllocateTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate local integration-test listener: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

// AllocateIPv6TCPAddress reserves a loopback IPv6 address. IPv6 is a supported
// deployment, not an optional extra, so a host without loopback IPv6 fails the
// suite instead of quietly skipping the coverage. Set SABLE_INTEGRATION_NO_IPV6
// to run on a host or container image that has IPv6 disabled.
func AllocateIPv6TCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		if os.Getenv("SABLE_INTEGRATION_NO_IPV6") != "" {
			t.Skipf("loopback IPv6 is unavailable and SABLE_INTEGRATION_NO_IPV6 is set: %v", err)
		}
		t.Fatalf("allocate loopback IPv6 integration-test listener: %v\nenable IPv6 on this host, or set SABLE_INTEGRATION_NO_IPV6=1 to skip IPv6 coverage", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
