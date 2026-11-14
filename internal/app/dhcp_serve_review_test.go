package app

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dhcp"
)

// Blake's review of slice 4's socket core (F18-F21, D27).

// reviewSocketStore is the store as the server leaves it: every save that
// succeeded, applied in order.
type reviewSocketStore struct {
	mutex  sync.Mutex
	rows   map[netip.Addr]dhcp.Lease
	refuse int
	panics int
}

func (store *reviewSocketStore) save(_ context.Context, leases []dhcp.Lease) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.refuse > 0 {
		store.refuse--
		return errors.New("database is locked")
	}
	if store.panics > 0 {
		store.panics--
		panic("driver bug")
	}
	for _, lease := range leases {
		store.rows[lease.Address] = lease
	}
	return nil
}

func (store *reviewSocketStore) load(context.Context) ([]dhcp.Lease, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	leases := make([]dhcp.Lease, 0, len(store.rows))
	for _, lease := range store.rows {
		leases = append(leases, lease)
	}
	return leases, nil
}

// S1. The store refuses one save, the client retransmits (RFC 2131 §4.1), the
// second save goes through. The engine changed its view at the first
// REQUEST, so the retransmit saves only what changed since: the new lease.
// The old lease, released in memory, is still active in the store, and a
// restart loads it back (F8, D19, through a different door).
func TestReviewSocketRefusedSaveThenRetransmitKeepsStoreAndEngineEqual(t *testing.T) {
	reviewSocketMoveAfterFault(t, func(store *reviewSocketStore) { store.refuse = 1 })
}

// F22. The same move, but the save panics instead of failing. The recover
// loses the request; D27 still has to reload the engine before the retransmit.
func TestReviewSocketPanicAfterEngineChangeReloadsFromStore(t *testing.T) {
	reviewSocketMoveAfterFault(t, func(store *reviewSocketStore) { store.panics = 1 })
}

// reviewSocketMoveAfterFault moves a host to its new reservation, faults the
// first save of the REQUEST, lets the client retransmit, and checks the store
// and the engine agree on every lease.
func reviewSocketMoveAfterFault(t *testing.T, arm func(*reviewSocketStore)) {
	t.Helper()
	enabled := true
	scope := config.DHCPScope{
		ID: "lan", Name: "LAN", Subnet: "10.0.7.0/24", Enabled: &enabled,
		Lease: config.Duration{Duration: time.Hour}, Router: "10.0.7.1",
		Ranges: []config.DHCPRange{{Start: "10.0.7.100", End: "10.0.7.119"}},
	}
	link := dhcp.Meta{Interface: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.7.2/24")}}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

	// Yesterday: the host took a pool lease.
	before, err := dhcp.New(config.DHCP{Enabled: true, Scopes: []config.DHCPScope{scope}}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	offer := before.Handle(now, dhcpTestPacket(dhcp.Discover), link)
	if ack := before.Handle(now, dhcpTestRequest(*offer.Reply), link); ack.Reply == nil || ack.Reply.MessageType() != dhcp.Ack {
		t.Fatalf("setup: %+v", ack)
	}
	old := offer.Reply.YIAddr
	store := &reviewSocketStore{rows: map[netip.Addr]dhcp.Lease{}}
	for _, lease := range before.Leases() {
		store.rows[lease.Address] = lease
	}

	// Today: the MAC is reserved elsewhere, and the engine starts from the store.
	scope.Reservations = []config.DHCPReservation{{MAC: dhcpTestMAC.String(), Address: "10.0.7.21", Name: "host"}}
	settings := config.DHCP{Enabled: true, Scopes: []config.DHCPScope{scope}}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	engine, err := dhcp.New(settings, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	engine.Load(before.Leases())

	conn := newFakeDHCPConn()
	stats := &dhcpStats{}
	server := &dhcpServer{
		engine: engine, conn: conn, save: store.save, load: store.load, stats: stats,
		link:   func(int) (dhcp.Meta, error) { return link, nil },
		now:    func() time.Time { return now.Add(30 * time.Minute) },
		logger: slog.New(slog.NewTextHandler(testLogWriter{t}, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.run(ctx) }()
	harness := &dhcpServerHarness{server: server, conn: conn, stats: stats, cancel: cancel, done: done}
	t.Cleanup(harness.stop)

	harness.exchange(t, dhcpTestPacket(dhcp.Discover))
	harness.waitWrite(t)
	_, sent := conn.snapshot()
	if sent[0].reply.YIAddr != netip.MustParseAddr("10.0.7.21") {
		t.Fatalf("setup: offered %s, want the reservation", sent[0].reply.YIAddr)
	}
	store.mutex.Lock()
	arm(store)
	store.mutex.Unlock()
	harness.exchange(t, dhcpTestRequest(sent[0].reply)) // faulted: no ACK
	harness.waitIdle(t, 2)
	harness.exchange(t, dhcpTestRequest(sent[0].reply)) // the retransmit
	harness.waitWrite(t)
	if _, sent = conn.snapshot(); len(sent) != 2 || sent[1].reply.MessageType() != dhcp.Ack {
		t.Fatalf("setup: replies %+v; want the OFFER, then one ACK for the retransmit", sent)
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()
	for _, lease := range engine.Leases() {
		if row := store.rows[lease.Address]; row.State != lease.State {
			t.Errorf("%s: engine says state %v, store says state %v", lease.Address, lease.State, row.State)
		}
	}
	if store.rows[old].State == dhcp.LeaseActive {
		t.Errorf("after the ACK for 10.0.7.21 the store still has %s active for the same host: a restart brings it back", old)
	}
}

// reviewSocketErrConn fails its first read with a real socket error.
type reviewSocketErrConn struct{ closed atomic.Bool }

func (conn *reviewSocketErrConn) ReadPacket([]byte) (int, int, error) {
	return 0, 0, errors.New("recvmsg: network is down")
}
func (conn *reviewSocketErrConn) WritePacket([]byte, int, netip.Addr, netip.AddrPort) error {
	return nil
}
func (conn *reviewSocketErrConn) Close() error { conn.closed.Store(true); return nil }

// S2. run's comment: "serves until ctx ends or the socket fails, then closes
// the socket". On a failed read it returns with the socket open.
func TestReviewSocketRunClosesTheSocketWhenReadFails(t *testing.T) {
	conn := &reviewSocketErrConn{}
	server := &dhcpServer{conn: conn, stats: &dhcpStats{}, logger: slog.Default(), now: time.Now}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := server.run(ctx)
	if err == nil {
		t.Fatal("run returned nil for a failed read")
	}
	if !conn.closed.Load() {
		t.Errorf("run returned %q and left the socket open: with SO_REUSEADDR a restarted listener binds beside it", err)
	}
}

// S3. One client's save hangs (Postgres black-holed, SQLite busy). A second
// client's DISCOVER needs no store, and gets nothing until the save returns.
func TestReviewSocketHungSaveDoesNotStallOtherClients(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	harness := startDHCPServer(t, func(ctx context.Context, _ []dhcp.Lease) error {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return ctx.Err()
	}, nil)
	harness.exchange(t, dhcpTestPacket(dhcp.Discover))
	harness.waitWrite(t)
	_, sent := harness.conn.snapshot()
	harness.exchange(t, dhcpTestRequest(sent[0].reply)) // the save hangs here
	other := dhcpTestPacket(dhcp.Discover)
	other.CHAddr = []byte{2, 0, 0, 0, 0, 9}
	harness.exchange(t, other)
	// A client's first retransmit comes at 4s (RFC 2131 §4.1); the save has
	// to give up before then.
	select {
	case <-harness.conn.wrote:
	case <-time.After(4 * time.Second):
		t.Errorf("no reply to anyone for 4s while one save hangs: the save has no deadline")
	}
}

// S4. A RELEASE that was saved is not a dropped request.
func TestReviewSocketSavedReleaseIsNotCountedAsDropped(t *testing.T) {
	var saves atomic.Int32
	harness := startDHCPServer(t, func(context.Context, []dhcp.Lease) error { saves.Add(1); return nil }, nil)
	harness.exchange(t, dhcpTestPacket(dhcp.Discover))
	harness.waitWrite(t)
	_, sent := harness.conn.snapshot()
	harness.exchange(t, dhcpTestRequest(sent[0].reply))
	harness.waitWrite(t)
	release := dhcpTestPacket(dhcp.Release, dhcp.Option{Code: 54, Data: []byte{10, 0, 7, 2}})
	release.CIAddr = sent[0].reply.YIAddr
	harness.exchange(t, release)
	harness.waitIdle(t, 3)
	if saves.Load() != 2 {
		t.Fatalf("setup: saves = %d, want 2 (the ACK and the RELEASE)", saves.Load())
	}
	if dropped := harness.stats.Dropped.Load(); dropped != 0 {
		t.Errorf("Dropped = %d after a DISCOVER, a REQUEST and a RELEASE that were all handled", dropped)
	}
}

// D27's check: while reloads keep failing the server answers nothing, and the
// first reload that succeeds puts it back in service.
func TestDHCPServerStaysSilentUntilReloadSucceeds(t *testing.T) {
	var loadFailures atomic.Int32
	loadFailures.Store(2)
	saveFailures := atomic.Int32{}
	saveFailures.Store(1)
	harness := startDHCPServer(t, func(context.Context, []dhcp.Lease) error {
		if saveFailures.Add(-1) >= 0 {
			return errors.New("database is locked")
		}
		return nil
	}, nil)
	// Each reading of the clock is a reload interval later, so the limit on
	// stale reloads never holds one back here.
	var tick atomic.Int64
	start := harness.server.now()
	harness.server.now = func() time.Time { return start.Add(time.Duration(tick.Add(1)) * time.Second) }
	harness.server.load = func(context.Context) ([]dhcp.Lease, error) {
		if loadFailures.Add(-1) >= 0 {
			return nil, errors.New("database is locked")
		}
		return nil, nil
	}
	harness.exchange(t, dhcpTestPacket(dhcp.Discover))
	harness.waitWrite(t)
	_, sent := harness.conn.snapshot()
	harness.exchange(t, dhcpTestRequest(sent[0].reply)) // save fails, first reload fails
	harness.exchange(t, dhcpTestPacket(dhcp.Discover))  // second reload fails: silent
	harness.waitIdle(t, 3)
	if stale := harness.stats.Stale.Load(); stale != 1 {
		t.Fatalf("Stale = %d, want 1", stale)
	}
	if _, sent := harness.conn.snapshot(); len(sent) != 1 {
		t.Fatalf("sent %d replies while the engine was stale, want only the first OFFER", len(sent))
	}
	harness.exchange(t, dhcpTestRequest(sent[0].reply)) // reload succeeds, save succeeds
	harness.waitWrite(t)
	if _, sent := harness.conn.snapshot(); sent[len(sent)-1].reply.MessageType() != dhcp.Ack {
		t.Fatalf("last reply %v, want an ACK once the reload succeeded", sent[len(sent)-1].reply.MessageType())
	}
}
