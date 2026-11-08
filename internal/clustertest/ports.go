package clustertest

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
)

// Ports holds the loopback HTTP, HTTPS, and DNS listen addresses of one node.
type Ports struct {
	HTTP  string
	HTTPS string
	DNS   string
}

// Nodes listen on ports below the kernel's ephemeral range (from 32768 on
// Linux, 49152 on macOS). A port the kernel hands out for ":0" comes from
// that range, so once it is released another node's outgoing connection can
// take it before the node it was meant for binds it.
const (
	lowestListenPort  = 10000
	highestListenPort = 32767
)

// handedOut keeps one test process from giving the same port to two nodes
// before either binds it.
var handedOut struct {
	sync.Mutex
	ports map[int]bool
}

// AllocatePorts reserves three loopback TCP addresses.
func AllocatePorts(t *testing.T) Ports {
	t.Helper()
	return Ports{HTTP: AllocateTCPAddress(t), HTTPS: AllocateTCPAddress(t), DNS: AllocateTCPAddress(t)}
}

// AllocateTCPAddress reserves a free loopback TCP address.
func AllocateTCPAddress(t *testing.T) string {
	t.Helper()
	address, err := allocateListenAddress("127.0.0.1")
	if err != nil {
		t.Fatalf("allocate local integration-test listener: %v", err)
	}
	return address
}

// AllocateIPv6TCPAddress reserves a loopback IPv6 address. IPv6 is a supported
// deployment, not an optional extra, so a host without loopback IPv6 fails the
// suite instead of quietly skipping the coverage. Set SABLE_INTEGRATION_NO_IPV6
// to run on a host or container image that has IPv6 disabled.
func AllocateIPv6TCPAddress(t *testing.T) string {
	t.Helper()
	address, err := allocateListenAddress("::1")
	if err != nil {
		if os.Getenv("SABLE_INTEGRATION_NO_IPV6") != "" {
			t.Skipf("loopback IPv6 is unavailable and SABLE_INTEGRATION_NO_IPV6 is set: %v", err)
		}
		t.Fatalf("allocate loopback IPv6 integration-test listener: %v\nenable IPv6 on this host, or set SABLE_INTEGRATION_NO_IPV6=1 to skip IPv6 coverage", err)
	}
	return address
}

// allocateListenAddress picks a port no node in this process was given and
// that host can listen on now.
func allocateListenAddress(host string) (string, error) {
	handedOut.Lock()
	defer handedOut.Unlock()
	if handedOut.ports == nil {
		handedOut.ports = make(map[int]bool)
	}
	var lastErr error
	for range 200 {
		port := lowestListenPort + rand.IntN(highestListenPort-lowestListenPort+1)
		if handedOut.ports[port] {
			continue
		}
		address := net.JoinHostPort(host, strconv.Itoa(port))
		listener, err := net.Listen("tcp", address)
		if err != nil {
			lastErr = err
			continue
		}
		if err := listener.Close(); err != nil {
			return "", err
		}
		handedOut.ports[port] = true
		return address, nil
	}
	return "", fmt.Errorf("no free port in %d-%d: %w", lowestListenPort, highestListenPort, lastErr)
}
