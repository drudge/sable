package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"testing"
	"time"
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

// The probe listens on port 68, which a DHCP client on this host (dhcpcd,
// dhclient) holds with SO_REUSEADDR. The probe must bind beside it, or it
// never runs on a host that also gets an address by DHCP.
func TestListenDHCPClientSharesThePortWithADHCPClient(t *testing.T) {
	_, port := reuseAddrSquatter(t)
	conn, err := listenDHCPClient(context.Background(), port)
	if err != nil {
		t.Fatalf("listenDHCPClient beside a DHCP client: %v", err)
	}
	_ = conn.Close()
}

// The server reads each datagram's destination, so a unicast renewal routed
// to this node takes the scope holding its ciaddr (D106).
func TestListenDHCPReportsTheDestinationAddress(t *testing.T) {
	conn, err := listenDHCP(context.Background(), 0)
	if err != nil {
		t.Fatalf("listenDHCP: %v", err)
	}
	defer func() { _ = conn.Close() }()
	port := conn.conn.LocalAddr().(*net.UDPAddr).Port
	sender, err := net.Dial("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	if _, err := sender.Write([]byte("renew")); err != nil {
		t.Fatal(err)
	}
	_ = conn.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 64)
	n, arrival, err := conn.ReadPacket(buffer)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buffer[:n]) != "renew" || arrival.to != netip.MustParseAddr("127.0.0.1") || arrival.ifIndex == 0 {
		t.Fatalf("read %q from %+v; want \"renew\" sent to 127.0.0.1 on an interface", buffer[:n], arrival)
	}
}
