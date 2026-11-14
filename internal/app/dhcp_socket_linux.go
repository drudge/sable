package app

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

// udpDHCPConn is the server's UDP socket on port 67 of every IPv4 address.
// IP_PKTINFO names the interface each request came in on, which picks the
// scope (RFC 2131 §4.3.1), and sends each broadcast reply out of that same
// interface; without it the kernel routes 255.255.255.255 by the default
// route alone.
type udpDHCPConn struct {
	conn   net.PacketConn
	packet *ipv4.PacketConn
}

// listenDHCP opens the server socket. Port 67 is below 1024, so the process
// needs CAP_NET_BIND_SERVICE, as it does for DNS on port 53.
//
// The socket is bound without SO_REUSEADDR on purpose. Linux lets UDP sockets
// that all set it share a port and hands each of them every broadcast, and
// dnsmasq and ISC dhcpd set it. With it, Sable would bind beside another DHCP
// server on this host and both would answer each DISCOVER. Without it the
// bind fails with EADDRINUSE, which dhcpService logs and retries.
func listenDHCP(ctx context.Context, port int) (*udpDHCPConn, error) {
	return openDHCPSocket(ctx, port, false)
}

// listenDHCPClient opens the probe's socket on the client port. It sets
// SO_REUSEADDR so it binds beside a DHCP client on this host (dhcpcd,
// dhclient), which holds port 68 the same way; listenDHCP must not.
func listenDHCPClient(ctx context.Context, port int) (*udpDHCPConn, error) {
	return openDHCPSocket(ctx, port, true)
}

func openDHCPSocket(ctx context.Context, port int, shared bool) (*udpDHCPConn, error) {
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		err := raw.Control(func(fd uintptr) {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
			if optionErr == nil && shared {
				optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}
		})
		if err != nil {
			return err
		}
		return optionErr
	}}
	conn, err := config.ListenPacket(ctx, "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}
	packet := ipv4.NewPacketConn(conn)
	if err := packet.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ask for the arrival interface: %w", err)
	}
	return &udpDHCPConn{conn: conn, packet: packet}, nil
}

func (conn *udpDHCPConn) ReadPacket(buffer []byte) (int, int, error) {
	n, control, _, err := conn.packet.ReadFrom(buffer)
	if err != nil {
		return 0, 0, err
	}
	if control == nil {
		return n, 0, nil
	}
	return n, control.IfIndex, nil
}

func (conn *udpDHCPConn) WritePacket(payload []byte, ifIndex int, source netip.Addr, destination netip.AddrPort) error {
	control := &ipv4.ControlMessage{IfIndex: ifIndex}
	if source.Is4() {
		control.Src = source.AsSlice()
	}
	_, err := conn.packet.WriteTo(payload, control, net.UDPAddrFromAddrPort(destination))
	return err
}

func (conn *udpDHCPConn) Close() error { return conn.conn.Close() }

// seekDHCP is a dhcpSeek on a UDP socket on port 68, shared with a DHCP
// client on the host (listenDHCPClient); IP_PKTINFO sends the
// broadcast out of link and keeps only replies that came in on it.
func seekDHCP(ctx context.Context, link dhcpProbeLink, discover []byte, wait time.Duration) ([][]byte, error) {
	conn, err := listenDHCPClient(ctx, dhcpClientPort)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.conn.SetDeadline(time.Now().Add(wait))
	stop := context.AfterFunc(ctx, func() { _ = conn.conn.SetDeadline(time.Now()) })
	defer stop()
	broadcast := netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), dhcpServerPort)
	if err := conn.WritePacket(discover, link.Index, netip.Addr{}, broadcast); err != nil {
		return nil, err
	}
	var replies [][]byte
	buffer := make([]byte, dhcpMaxPacket+1)
	for {
		n, ifIndex, err := conn.ReadPacket(buffer)
		if err != nil {
			// The deadline ends every probe; it isn't a failure.
			return replies, nil
		}
		if ifIndex == link.Index && n <= dhcpMaxPacket {
			replies = append(replies, bytes.Clone(buffer[:n]))
		}
	}
}
