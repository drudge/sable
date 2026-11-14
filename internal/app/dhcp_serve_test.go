package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dhcp"
)

var dhcpTestMAC = net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}

// fakeDHCPConn feeds datagrams to the server and records what it sends,
// with the saves, in one ordered log.
type fakeDHCPConn struct {
	inbound chan []byte
	closed  chan struct{}
	once    sync.Once
	mutex   sync.Mutex
	events  []string
	sent    []fakeDHCPSend
	wrote   chan struct{}
}

type fakeDHCPSend struct {
	reply       dhcp.Packet
	ifIndex     int
	source      netip.Addr
	destination netip.AddrPort
}

func newFakeDHCPConn() *fakeDHCPConn {
	return &fakeDHCPConn{inbound: make(chan []byte, 8), closed: make(chan struct{}), wrote: make(chan struct{}, 8)}
}

func (conn *fakeDHCPConn) ReadPacket(buffer []byte) (int, int, error) {
	select {
	case payload := <-conn.inbound:
		return copy(buffer, payload), 7, nil
	case <-conn.closed:
		return 0, 0, net.ErrClosed
	}
}

func (conn *fakeDHCPConn) WritePacket(payload []byte, ifIndex int, source netip.Addr, destination netip.AddrPort) error {
	// Parse reads client messages only, so the copy it gets says BOOTREQUEST.
	asRequest := append([]byte(nil), payload...)
	asRequest[0] = 1
	reply, err := dhcp.Parse(asRequest)
	if err != nil {
		return err
	}
	conn.log("write " + reply.MessageType().String())
	conn.mutex.Lock()
	conn.sent = append(conn.sent, fakeDHCPSend{reply, ifIndex, source, destination})
	conn.mutex.Unlock()
	conn.wrote <- struct{}{}
	return nil
}

func (conn *fakeDHCPConn) Close() error {
	conn.once.Do(func() { close(conn.closed) })
	return nil
}

func (conn *fakeDHCPConn) log(event string) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	conn.events = append(conn.events, event)
}

func (conn *fakeDHCPConn) snapshot() ([]string, []fakeDHCPSend) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	return append([]string(nil), conn.events...), append([]fakeDHCPSend(nil), conn.sent...)
}

type dhcpServerHarness struct {
	server *dhcpServer
	conn   *fakeDHCPConn
	stats  *dhcpStats
	cancel context.CancelFunc
	done   chan error
}

func startDHCPServer(t *testing.T, save func(context.Context, []dhcp.Lease) error, link func(int) (dhcp.Meta, error)) *dhcpServerHarness {
	t.Helper()
	engine, err := dhcp.New(dhcpTestSettings(t), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if link == nil {
		link = func(int) (dhcp.Meta, error) {
			return dhcp.Meta{Interface: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.7.2/24")}}, nil
		}
	}
	harness := &dhcpServerHarness{conn: newFakeDHCPConn(), stats: &dhcpStats{}, done: make(chan error, 1)}
	harness.server = &dhcpServer{
		engine: engine, conn: harness.conn, save: save, link: link,
		load:   func(context.Context) ([]dhcp.Lease, error) { return nil, nil },
		now:    func() time.Time { return time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC) },
		logger: slog.New(slog.NewTextHandler(testLogWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug})), stats: harness.stats,
	}
	ctx, cancel := context.WithCancel(context.Background())
	harness.cancel = cancel
	go func() { harness.done <- harness.server.run(ctx) }()
	t.Cleanup(harness.stop)
	return harness
}

// dhcpTestSettings is one enabled scope, 10.0.7.0/24, leasing .100 to .119.
func dhcpTestSettings(t *testing.T) config.DHCP {
	t.Helper()
	enabled := true
	settings := config.DHCP{Enabled: true, Scopes: []config.DHCPScope{{
		ID: "lan", Name: "LAN", Subnet: "10.0.7.0/24", Enabled: &enabled,
		Lease: config.Duration{Duration: time.Hour}, Router: "10.0.7.1",
		Ranges: []config.DHCPRange{{Start: "10.0.7.100", End: "10.0.7.119"}},
	}}}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	return settings
}

func (harness *dhcpServerHarness) stop() {
	harness.cancel()
	<-harness.done
}

func (harness *dhcpServerHarness) exchange(t *testing.T, request dhcp.Packet) {
	t.Helper()
	harness.conn.inbound <- request.Marshal()
}

func (harness *dhcpServerHarness) waitWrite(t *testing.T) {
	t.Helper()
	select {
	case <-harness.conn.wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("no reply was sent")
	}
}

// waitIdle waits until the server has looked at every datagram it read.
func (harness *dhcpServerHarness) waitIdle(t *testing.T, received uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if harness.stats.Received.Load() >= received && len(harness.server.queue) == 0 {
			time.Sleep(10 * time.Millisecond)
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the server didn't take the request")
}

func dhcpTestPacket(kind dhcp.MessageType, options ...dhcp.Option) dhcp.Packet {
	return dhcp.Packet{
		Op: 1, HType: 1, XID: [4]byte{9, 8, 7, 6}, CHAddr: dhcpTestMAC,
		CIAddr: netip.IPv4Unspecified(), YIAddr: netip.IPv4Unspecified(),
		SIAddr: netip.IPv4Unspecified(), GIAddr: netip.IPv4Unspecified(),
		Options: append([]dhcp.Option{{Code: 53, Data: []byte{byte(kind)}}}, options...),
	}
}

func dhcpTestRequest(offered dhcp.Packet) dhcp.Packet {
	return dhcpTestPacket(dhcp.Request,
		dhcp.Option{Code: 50, Data: offered.YIAddr.AsSlice()},
		dhcp.Option{Code: 54, Data: []byte{10, 0, 7, 2}})
}

// The ACK tells a client it holds a lease, so the lease is in the store
// first (RFC 2131 §4.3.1), and the OFFER and ACK leave the interface the
// request came in on, from the server identifier, to the limited broadcast.
func TestDHCPServerSavesBeforeAck(t *testing.T) {
	var harness *dhcpServerHarness
	harness = startDHCPServer(t, func(_ context.Context, leases []dhcp.Lease) error {
		harness.conn.log("save " + leases[len(leases)-1].Address.String())
		return nil
	}, nil)
	harness.exchange(t, dhcpTestPacket(dhcp.Discover))
	harness.waitWrite(t)
	_, sent := harness.conn.snapshot()
	offer := sent[0]
	if offer.reply.MessageType() != dhcp.Offer || offer.ifIndex != 7 ||
		offer.source != netip.MustParseAddr("10.0.7.2") ||
		offer.destination != netip.MustParseAddrPort("255.255.255.255:68") {
		t.Fatalf("offer = %+v; want an OFFER on interface 7 from 10.0.7.2 to 255.255.255.255:68", offer)
	}
	harness.exchange(t, dhcpTestRequest(offer.reply))
	harness.waitWrite(t)
	events, _ := harness.conn.snapshot()
	want := []string{"write OFFER", "save " + offer.reply.YIAddr.String(), "write ACK"}
	if len(events) != len(want) || events[0] != want[0] || events[1] != want[1] || events[2] != want[2] {
		t.Fatalf("events = %q; want %q", events, want)
	}
}

// A lease the store refused was never promised: the client hears nothing and
// retransmits, rather than holding an address a restart would forget.
func TestDHCPServerWithholdsAckWhenSaveFails(t *testing.T) {
	harness := startDHCPServer(t, func(context.Context, []dhcp.Lease) error {
		return errors.New("database is locked")
	}, nil)
	harness.exchange(t, dhcpTestPacket(dhcp.Discover))
	harness.waitWrite(t)
	_, sent := harness.conn.snapshot()
	harness.exchange(t, dhcpTestRequest(sent[0].reply))
	harness.waitIdle(t, 2)
	if _, sent = harness.conn.snapshot(); len(sent) != 1 {
		t.Fatalf("sent %d replies; want the OFFER only", len(sent))
	}
	if harness.stats.StoreFailed.Load() != 1 {
		t.Fatalf("store failures = %d; want 1", harness.stats.StoreFailed.Load())
	}
}

// A panic while answering one request loses that request only (AGENTS.md:
// a goroutine that serves packets recovers).
func TestDHCPServerRecoversFromPanic(t *testing.T) {
	calls := 0
	harness := startDHCPServer(t, func(context.Context, []dhcp.Lease) error { return nil },
		func(int) (dhcp.Meta, error) {
			calls++
			if calls == 1 {
				panic("interface vanished")
			}
			return dhcp.Meta{Interface: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.7.2/24")}}, nil
		})
	harness.exchange(t, dhcpTestPacket(dhcp.Discover))
	harness.exchange(t, dhcpTestPacket(dhcp.Discover))
	harness.waitWrite(t)
	if harness.stats.Panics.Load() != 1 {
		t.Fatalf("panics = %d; want 1", harness.stats.Panics.Load())
	}
}

// A relayed request is answered to the relay's server port; a renewing
// client is answered at its own address (RFC 2131 §4.1).
func TestDHCPDestination(t *testing.T) {
	relayed := dhcpTestPacket(dhcp.Request)
	relayed.GIAddr = netip.MustParseAddr("10.0.9.1")
	renewing := dhcpTestPacket(dhcp.Request)
	renewing.CIAddr = netip.MustParseAddr("10.0.7.105")
	for _, test := range []struct {
		request     dhcp.Packet
		destination dhcp.Destination
		want        string
	}{
		{relayed, dhcp.ToRelay, "10.0.9.1:67"},
		{renewing, dhcp.ToClient, "10.0.7.105:68"},
		{renewing, dhcp.ToBroadcast, "255.255.255.255:68"},
		{renewing, dhcp.ToHardware, "255.255.255.255:68"},
	} {
		if got := dhcpDestination(test.request, test.destination); got.String() != test.want {
			t.Errorf("destination %d = %s; want %s", test.destination, got, test.want)
		}
	}
}

type testLogWriter struct{ t *testing.T }

func (writer testLogWriter) Write(data []byte) (int, error) {
	writer.t.Log(string(data))
	return len(data), nil
}

// A client takes only the OFFER for its latest DISCOVER (RFC 2131 §4.4.1),
// so offer_delay holds one OFFER per client, the newest, and at most
// dhcpMaxDelayedOffers clients; a flood can't grow memory without bound (F23).
func TestDHCPServerBoundsDelayedOffers(t *testing.T) {
	conn := newFakeDHCPConn()
	server := &dhcpServer{conn: conn, stats: &dhcpStats{}, logger: slog.New(slog.NewTextHandler(testLogWriter{t}, nil))}
	reply := dhcpTestPacket(dhcp.Offer)
	reply.Op = 2
	for xid := range byte(100) {
		request := dhcpTestPacket(dhcp.Discover)
		request.XID = [4]byte{0, 0, 0, xid}
		answer := reply
		answer.XID = request.XID
		server.send(context.Background(), request, dhcp.Result{Reply: &answer, Delay: 50 * time.Millisecond}, 7)
	}
	if waiting := server.delayed.waiting(); waiting != 1 {
		t.Fatalf("%d OFFERs waiting for one client; want 1", waiting)
	}
	select {
	case <-conn.wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("the delayed OFFER was never sent")
	}
	time.Sleep(100 * time.Millisecond)
	if _, sent := conn.snapshot(); len(sent) != 1 || sent[0].reply.XID != [4]byte{0, 0, 0, 99} {
		t.Fatalf("sent %d OFFERs; want one, for the latest DISCOVER (xid 99)", len(sent))
	}

	for client := range dhcpMaxDelayedOffers + 10 {
		request := dhcpTestPacket(dhcp.Discover)
		request.CHAddr = net.HardwareAddr{0x02, 0, 0, 0, byte(client >> 8), byte(client)}
		server.send(context.Background(), request, dhcp.Result{Reply: &reply, Delay: time.Hour}, 7)
	}
	if waiting, full := server.delayed.waiting(), server.stats.DelayedFull.Load(); waiting != dhcpMaxDelayedOffers || full != 10 {
		t.Fatalf("waiting = %d, dropped = %d; want %d and 10", waiting, full, dhcpMaxDelayedOffers)
	}
	server.delayed.stop()
	if waiting := server.delayed.waiting(); waiting != 0 {
		t.Fatalf("%d OFFERs still waiting after stop", waiting)
	}
}

// A client retransmitting DISCOVER faster than offer_delay keeps its first
// deadline; restarting the clock on each retry would never send (F24).
func TestDHCPServerRetransmitKeepsOfferDeadline(t *testing.T) {
	conn := newFakeDHCPConn()
	conn.wrote = make(chan struct{}, 64)
	server := &dhcpServer{conn: conn, stats: &dhcpStats{}, logger: slog.New(slog.NewTextHandler(testLogWriter{t}, nil))}
	defer server.delayed.stop()
	reply := dhcpTestPacket(dhcp.Offer)
	reply.Op = 2
	for range 12 {
		server.send(context.Background(), dhcpTestPacket(dhcp.Discover), dhcp.Result{Reply: &reply, Delay: 200 * time.Millisecond}, 7)
		time.Sleep(50 * time.Millisecond)
	}
	if _, sent := conn.snapshot(); len(sent) == 0 {
		t.Fatal("no OFFER for a client retrying every 50ms under a 200ms offer_delay")
	}
}

// A datagram longer than dhcpMaxPacket isn't DHCP and isn't parsed
// truncated: it's dropped and counted.
func TestDHCPServerDropsOversizeDatagram(t *testing.T) {
	harness := startDHCPServer(t, func(context.Context, []dhcp.Lease) error { return nil }, nil)
	payload := dhcpTestPacket(dhcp.Discover).Marshal()
	harness.conn.inbound <- append(payload, make([]byte, dhcpMaxPacket+1-len(payload))...)
	harness.waitIdle(t, 1)
	if dropped := harness.stats.Dropped.Load(); dropped != 1 {
		t.Fatalf("dropped = %d; want the oversize datagram dropped", dropped)
	}
	if _, sent := harness.conn.snapshot(); len(sent) != 0 {
		t.Fatalf("answered an oversize datagram with %d replies", len(sent))
	}
}
