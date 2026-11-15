package app

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/drudge/sable/internal/neighbors"
)

// dhcpProber checks an address before it is offered (RFC 2131 §4.4.1,
// "SHOULD probe the reused address before allocating"): an ICMP echo from
// an unprivileged ping socket, then the neighbor table, which the echo made
// the kernel fill even for a host that drops pings but answers ARP. A
// neighbor entry with another hardware address counts though it may be
// stale: setting an address aside for an hour costs a pool slot, and
// offering a taken one costs two hosts their connection.
type dhcpProber struct {
	listen    func() (net.PacketConn, error)
	neighbors func() ([]neighbors.Entry, error)
	logger    *slog.Logger
	// unavailable is set once the ping socket failed to open, so the reason
	// is logged once; the neighbor check still runs.
	unavailable atomic.Bool
}

func newDHCPProber(logger *slog.Logger) *dhcpProber {
	return &dhcpProber{
		listen:    func() (net.PacketConn, error) { return icmp.ListenPacket("udp4", "0.0.0.0") },
		neighbors: neighbors.Read,
		logger:    logger,
	}
}

// probe is a dhcpProbe.
func (prober *dhcpProber) probe(ctx context.Context, address netip.Addr, client net.HardwareAddr, timeout time.Duration) (string, bool) {
	if prober.echo(ctx, address, timeout) {
		return "echo", true
	}
	entries, err := prober.neighbors()
	if err != nil {
		prober.logger.Debug("read neighbors for DHCP conflict probe", "error", err)
		return "", false
	}
	for _, entry := range entries {
		if entry.Address == address && !bytes.Equal(entry.MAC, client) {
			return entry.MAC.String(), true
		}
	}
	return "", false
}

// echo reports whether address answered an ICMP echo within timeout.
func (prober *dhcpProber) echo(ctx context.Context, address netip.Addr, timeout time.Duration) bool {
	conn, err := prober.listen()
	if err != nil {
		if !prober.unavailable.Swap(true) {
			prober.logger.Warn("DHCP conflict probe can't ping; checking the neighbor table only. "+
				"Allow unprivileged ping with net.ipv4.ping_group_range", "error", err)
		}
		return false
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	request, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{Seq: 1, Data: []byte("sable dhcp")}}).Marshal(nil)
	if err != nil {
		return false
	}
	target := &net.UDPAddr{IP: address.AsSlice()}
	if _, err := conn.WriteTo(request, target); err != nil {
		return false
	}
	buffer := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			return false
		}
		from, ok := peer.(*net.UDPAddr)
		if !ok || !from.IP.Equal(target.IP) {
			continue
		}
		if reply, err := icmp.ParseMessage(1, buffer[:n]); err == nil && reply.Type == ipv4.ICMPTypeEchoReply {
			return true
		}
	}
}
