package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/drudge/sable/internal/dhcp"
)

const (
	// dhcpQueueSize bounds the requests waiting for the engine. A burst past
	// it is dropped and counted; clients retransmit (RFC 2131 §4.1).
	dhcpQueueSize = 512
	// dhcpMaxPacket is the largest datagram read. A client may ask for
	// replies up to 1500 bytes (RFC 2132 §9.10); anything larger isn't DHCP.
	dhcpMaxPacket  = 1500
	dhcpServerPort = 67
	dhcpClientPort = 68
)

// dhcpConn is the server's socket: datagrams with the interface they
// arrived on, and replies sent out of a chosen interface from a chosen
// source address.
type dhcpConn interface {
	ReadPacket(buffer []byte) (n int, ifIndex int, err error)
	WritePacket(payload []byte, ifIndex int, source netip.Addr, destination netip.AddrPort) error
	Close() error
}

// dhcpStats counts what the server did with each datagram.
type dhcpStats struct {
	Received, Replied, Dropped, QueueFull, StoreFailed, Panics atomic.Uint64
}

type dhcpRequest struct {
	payload []byte
	ifIndex int
}

// dhcpServer moves datagrams between a socket and the engine. One goroutine
// reads, one serves in arrival order, so the leases of one ACK are written
// before the next request is looked at.
type dhcpServer struct {
	engine *dhcp.Engine
	conn   dhcpConn
	save   func(context.Context, []dhcp.Lease) error
	link   func(ifIndex int) (dhcp.Meta, error)
	now    func() time.Time
	logger *slog.Logger
	queue  chan dhcpRequest
	stats  *dhcpStats
}

// run serves until ctx ends or the socket fails, then closes the socket.
func (server *dhcpServer) run(ctx context.Context) error {
	server.queue = make(chan dhcpRequest, dhcpQueueSize)
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.serve(ctx)
	}()
	stop := context.AfterFunc(ctx, func() { _ = server.conn.Close() })
	defer stop()
	err := server.read()
	close(server.queue)
	<-done
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (server *dhcpServer) read() error {
	for {
		buffer := make([]byte, dhcpMaxPacket)
		n, ifIndex, err := server.conn.ReadPacket(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read DHCP socket: %w", err)
		}
		server.stats.Received.Add(1)
		select {
		case server.queue <- dhcpRequest{payload: buffer[:n], ifIndex: ifIndex}:
		default:
			server.stats.QueueFull.Add(1)
		}
	}
}

func (server *dhcpServer) serve(ctx context.Context) {
	for request := range server.queue {
		server.handleSafely(ctx, request)
	}
}

// handleSafely answers one request. A panic loses that request only: the
// client retransmits, and the server keeps serving the rest of the network.
func (server *dhcpServer) handleSafely(ctx context.Context, request dhcpRequest) {
	defer func() {
		if recovered := recover(); recovered != nil {
			server.stats.Panics.Add(1)
			server.logger.Error("DHCP request panicked", "panic", recovered)
		}
	}()
	server.handle(ctx, request)
}

func (server *dhcpServer) handle(ctx context.Context, request dhcpRequest) {
	packet, err := dhcp.Parse(request.payload)
	if err != nil {
		server.stats.Dropped.Add(1)
		return
	}
	meta, err := server.link(request.ifIndex)
	if err != nil {
		server.stats.Dropped.Add(1)
		return
	}
	result := server.engine.Handle(server.now(), packet, meta)
	if len(result.Save) > 0 {
		// The ACK promises the client its lease, so it goes out only once the
		// store has it (RFC 2131 §4.3.1: the server must commit the binding
		// before it sends the DHCPACK).
		if err := server.save(ctx, result.Save); err != nil {
			server.stats.StoreFailed.Add(1)
			server.logger.Warn("save DHCP lease; reply withheld", "error", err)
			return
		}
	}
	if result.Reply == nil {
		server.stats.Dropped.Add(1)
		server.logger.Debug("DHCP request dropped", "type", packet.MessageType(), "reason", result.Drop)
		return
	}
	server.send(ctx, packet, result, request.ifIndex)
}

// send writes a reply now, or after the scope's offer delay without holding
// up the requests behind it.
func (server *dhcpServer) send(ctx context.Context, request dhcp.Packet, result dhcp.Result, ifIndex int) {
	payload := result.Reply.Marshal()
	source := dhcpServerIdentifier(*result.Reply)
	destination := dhcpDestination(request, result.Destination)
	write := func() {
		if err := server.conn.WritePacket(payload, ifIndex, source, destination); err != nil {
			server.logger.Warn("send DHCP reply", "to", destination, "error", err)
			return
		}
		server.stats.Replied.Add(1)
	}
	if result.Delay <= 0 {
		write()
		return
	}
	go func() {
		timer := time.NewTimer(result.Delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
			write()
		}
	}()
}

// dhcpDestination maps the engine's choice to an address and port
// (RFC 2131 §4.1). A client without an address gets the limited broadcast:
// unicasting to yiaddr needs an ARP entry the server isn't allowed to add.
func dhcpDestination(request dhcp.Packet, destination dhcp.Destination) netip.AddrPort {
	switch destination {
	case dhcp.ToRelay:
		return netip.AddrPortFrom(request.GIAddr, dhcpServerPort)
	case dhcp.ToClient:
		return netip.AddrPortFrom(request.CIAddr, dhcpClientPort)
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), dhcpClientPort)
}

// dhcpServerIdentifier is option 54, which the reply's source address must
// match for clients that check it (RFC 2131 §4.1).
func dhcpServerIdentifier(reply dhcp.Packet) netip.Addr {
	data, found := reply.Option(54)
	if !found || len(data) != 4 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(data))
}
