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
	// dhcpSaveTimeout bounds one lease save or reload, so a hung store gives
	// up before a client's first retransmit at 4 s (RFC 2131 §4.1) and the
	// requests behind it are still answered in time.
	dhcpSaveTimeout = 2 * time.Second
	// dhcpReloadInterval is the least time between reads of the store while
	// the engine is stale. A store that stays down is then read once a second,
	// not once per datagram with dhcpSaveTimeout behind each.
	dhcpReloadInterval = time.Second
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
	// Handled counts requests that changed leases and need no reply: a
	// saved RELEASE or DECLINE (RFC 2131 §4.3.3, §4.3.4).
	Received, Replied, Handled, Dropped, QueueFull, StoreFailed, Panics atomic.Uint64
	// DelayedFull counts delayed OFFERs dropped because
	// dhcpMaxDelayedOffers clients were already waiting for one.
	DelayedFull atomic.Uint64
	// Stale counts requests left unanswered while the engine waits to reload
	// from the store after a failed save.
	Stale atomic.Uint64
	// Conflicts counts offered addresses a probe found in use.
	Conflicts atomic.Uint64
}

// dhcpRequest is a datagram for the engine, or a probe's conflict to record
// in its turn.
type dhcpRequest struct {
	payload  []byte
	ifIndex  int
	conflict *dhcpConflict
}

// dhcpConflict is an offered address something else answered for.
type dhcpConflict struct {
	address netip.Addr
	holder  string
}

// dhcpProbe reports what already uses address, if anything: "echo", or the
// hardware address the neighbor table holds for it other than client's.
type dhcpProbe func(ctx context.Context, address netip.Addr, client net.HardwareAddr, timeout time.Duration) (holder string, found bool)

// dhcpServer moves datagrams between a socket and the engine. One goroutine
// reads, one serves in arrival order, so the leases of one ACK are written
// before the next request is looked at.
type dhcpServer struct {
	engine *dhcp.Engine
	conn   dhcpConn
	save   func(context.Context, []dhcp.Lease) error
	// load reads every lease from the store, to put the engine back in step
	// with it after a failed save (the engine changes its view before the
	// save, and the store is the record).
	load   func(context.Context) ([]dhcp.Lease, error)
	link   func(ifIndex int) (dhcp.Meta, error)
	probe  dhcpProbe
	now    func() time.Time
	logger *slog.Logger
	queue  chan dhcpRequest
	stats  *dhcpStats
	// delayed holds the OFFERs waiting out offer_delay.
	delayed dhcpDelayedOffers
	// stale is set when a save failed and no reload has succeeded since.
	// Only the serve goroutine touches it.
	stale bool
	// reloadedAt is when the last reload started; only the serve goroutine
	// touches it.
	reloadedAt time.Time
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
	// A failed read leaves the socket open; close it here too, or with
	// SO_REUSEADDR a restarted listener binds beside the leaked one.
	defer func() { _ = server.conn.Close() }()
	err := server.read()
	// Probes queue conflicts; none may run once the queue is closed.
	server.delayed.stop()
	close(server.queue)
	<-done
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (server *dhcpServer) read() error {
	for {
		// One byte spare tells a datagram over dhcpMaxPacket from one that
		// fits, so an oversize one is dropped instead of parsed truncated.
		buffer := make([]byte, dhcpMaxPacket+1)
		n, ifIndex, err := server.conn.ReadPacket(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read DHCP socket: %w", err)
		}
		server.stats.Received.Add(1)
		if n > dhcpMaxPacket {
			server.stats.Dropped.Add(1)
			continue
		}
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
// The engine may have changed its view before the panic, so the next request
// reloads it from the store first, as after a failed save (D27).
func (server *dhcpServer) handleSafely(ctx context.Context, request dhcpRequest) {
	defer func() {
		if recovered := recover(); recovered != nil {
			server.stats.Panics.Add(1)
			server.stale = true
			server.logger.Error("DHCP request panicked; reloading leases before the next answer", "panic", recovered)
		}
	}()
	server.handle(ctx, request)
}

func (server *dhcpServer) handle(ctx context.Context, request dhcpRequest) {
	if server.stale && !server.reloadStale(ctx) {
		// Until the engine matches the store again, any answer may promise
		// what the store doesn't hold; stay silent and let clients retransmit.
		server.stats.Stale.Add(1)
		return
	}
	if request.conflict != nil {
		server.recordConflict(ctx, *request.conflict)
		return
	}
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
	if len(result.Save) > 0 && !server.commit(ctx, result.Save) {
		return
	}
	if result.Reply == nil {
		counter, message := &server.stats.Dropped, "DHCP request dropped"
		if len(result.Save) > 0 {
			counter, message = &server.stats.Handled, "DHCP request handled"
		}
		counter.Add(1)
		server.logger.Debug(message, "type", packet.MessageType(), "reason", result.Drop)
		return
	}
	server.send(ctx, packet, result, request.ifIndex)
}

// recordConflict takes a probed address out of the pool, in the serve
// goroutine like every other engine change, and saves it through commit.
func (server *dhcpServer) recordConflict(ctx context.Context, conflict dhcpConflict) {
	if lease := server.engine.Conflict(server.now(), conflict.address, conflict.holder); lease != nil {
		server.commit(ctx, []dhcp.Lease{*lease})
	}
}

// commit writes the leases a request changed. The ACK promises the client
// its lease, so it goes out only once the store has it (RFC 2131 §4.3.1).
// The engine already changed its view, so a failed save reloads it from the
// store rather than leave the two apart (D27).
func (server *dhcpServer) commit(ctx context.Context, leases []dhcp.Lease) bool {
	saveCtx, cancel := context.WithTimeout(ctx, dhcpSaveTimeout)
	err := server.save(saveCtx, leases)
	cancel()
	if err == nil {
		return true
	}
	server.stats.StoreFailed.Add(1)
	server.logger.Warn("save DHCP lease; reply withheld", "error", err)
	server.stale = true
	server.reload(ctx)
	return false
}

// reloadStale reloads a stale engine unless the last try was under
// dhcpReloadInterval ago. A clock that went back counts as due.
func (server *dhcpServer) reloadStale(ctx context.Context) bool {
	if since := server.now().Sub(server.reloadedAt); since >= 0 && since < dhcpReloadInterval {
		return false
	}
	return server.reload(ctx)
}

// reload replaces the engine's lease view with the store's and reports
// whether it did. Pending offers live outside the view and survive.
func (server *dhcpServer) reload(ctx context.Context) bool {
	server.reloadedAt = server.now()
	loadCtx, cancel := context.WithTimeout(ctx, dhcpSaveTimeout)
	defer cancel()
	leases, err := server.load(loadCtx)
	if err != nil {
		server.logger.Warn("read DHCP leases from the store; not answering until it works", "error", err)
		return false
	}
	server.engine.Load(leases)
	server.stale = false
	return true
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
	var probe func() bool
	if result.Probe.IsValid() && server.probe != nil {
		probe = func() bool { return server.probeFree(ctx, request, result) }
	}
	if result.Delay <= 0 && probe == nil {
		write()
		return
	}
	if ctx.Err() != nil {
		return
	}
	if !server.delayed.schedule(dhcpOfferKey(request), result.Delay, write, probe) {
		server.stats.DelayedFull.Add(1)
		server.logger.Debug("delayed DHCP OFFER dropped; too many waiting", "limit", dhcpMaxDelayedOffers)
	}
}

// probeFree checks the offered address off the serve goroutine and reports
// whether the OFFER may go (RFC 2131 §4.4.1). A taken address is queued for
// the engine to set aside; the client's retransmitted DISCOVER gets another.
func (server *dhcpServer) probeFree(ctx context.Context, request dhcp.Packet, result dhcp.Result) bool {
	holder, found := server.probe(ctx, result.Probe, request.CHAddr, result.ProbeTimeout)
	if !found {
		return true
	}
	server.stats.Conflicts.Add(1)
	server.logger.Warn("offered DHCP address is in use; setting it aside", "address", result.Probe, "holder", holder)
	select {
	case server.queue <- dhcpRequest{conflict: &dhcpConflict{address: result.Probe, holder: holder}}:
	default:
		server.stats.QueueFull.Add(1)
	}
	return false
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
