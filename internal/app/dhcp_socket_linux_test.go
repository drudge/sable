package app

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

// reuseAddrSquatter binds a UDP port the way dnsmasq and ISC dhcpd bind port
// 67: on every IPv4 address, with SO_REUSEADDR set.
func reuseAddrSquatter(t *testing.T) (net.PacketConn, int) {
	t.Helper()
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		err := raw.Control(func(fd uintptr) {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		})
		if err != nil {
			return err
		}
		return optionErr
	}}
	conn, err := config.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("bind the squatter: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, conn.LocalAddr().(*net.UDPAddr).Port
}

// Another DHCP server on this host must make the bind fail, so dhcpService
// logs it and retries. Sharing the port has both servers answer every
// broadcast DISCOVER.
func TestListenDHCPFailsWhenAnotherServerHoldsThePort(t *testing.T) {
	_, port := reuseAddrSquatter(t)
	conn, err := listenDHCP(context.Background(), port)
	if err == nil {
		_ = conn.Close()
		t.Fatal("listenDHCP bound a port another server holds with SO_REUSEADDR; both would answer")
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("listenDHCP error = %v, want EADDRINUSE", err)
	}
}

// Two Sable processes on one host: the second one's bind fails too.
func TestListenDHCPFailsWhenSableHoldsThePort(t *testing.T) {
	squatter, port := reuseAddrSquatter(t)
	_ = squatter.Close()
	first, err := listenDHCP(context.Background(), port)
	if err != nil {
		t.Skipf("first listenDHCP on port %d: %v", port, err)
	}
	defer func() { _ = first.Close() }()
	second, err := listenDHCP(context.Background(), port)
	if err == nil {
		_ = second.Close()
		t.Fatal("a second listenDHCP on the same port succeeded")
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("second listenDHCP error = %v, want EADDRINUSE", err)
	}
	// Closing the first frees the port at once: a [dhcp] reload restarts
	// the listener and UDP has no TIME_WAIT to wait out.
	_ = first.Close()
	third, err := listenDHCP(context.Background(), port)
	if err != nil {
		t.Fatalf("listenDHCP right after the first closed: %v", err)
	}
	_ = third.Close()
}
