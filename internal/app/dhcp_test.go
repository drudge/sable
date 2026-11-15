package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dhcp"
	"github.com/drudge/sable/internal/store"
)

// dhcpListenLog records each bind and close of the service's socket.
type dhcpListenLog struct {
	mutex  sync.Mutex
	events []string
	conns  []*fakeDHCPConn
}

func (log *dhcpListenLog) listen(context.Context, int) (dhcpConn, error) {
	log.record("listen")
	conn := newFakeDHCPConn()
	log.mutex.Lock()
	log.conns = append(log.conns, conn)
	log.mutex.Unlock()
	return &loggedDHCPConn{fakeDHCPConn: conn, log: log}, nil
}

func (log *dhcpListenLog) record(event string) {
	log.mutex.Lock()
	defer log.mutex.Unlock()
	log.events = append(log.events, event)
}

// loggedDHCPConn records its first Close, as the kernel frees port 67.
type loggedDHCPConn struct {
	*fakeDHCPConn
	log    *dhcpListenLog
	closed sync.Once
}

func (conn *loggedDHCPConn) Close() error {
	conn.closed.Do(func() { conn.log.record("close") })
	return conn.fakeDHCPConn.Close()
}

func (log *dhcpListenLog) snapshot() []string {
	log.mutex.Lock()
	defer log.mutex.Unlock()
	return slices.Clone(log.events)
}

func (log *dhcpListenLog) last() *fakeDHCPConn {
	log.mutex.Lock()
	defer log.mutex.Unlock()
	return log.conns[len(log.conns)-1]
}

func newTestDHCPService(t *testing.T, role string) (*dhcpService, *dhcpListenLog, *store.Store) {
	t.Helper()
	database, err := store.Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	listens := &dhcpListenLog{}
	service := newDHCPService(database, func() string { return "node-a" }, func() string { return role }, slog.New(slog.NewTextHandler(testLogWriter{t}, nil)))
	service.listen = listens.listen
	service.retry = 10 * time.Millisecond
	service.link = func(int) (dhcp.Meta, error) {
		return dhcp.Meta{Interface: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.7.2/24")}}, nil
	}
	service.probe = func(context.Context, netip.Addr, net.HardwareAddr, time.Duration) (string, bool) { return "", false }
	t.Cleanup(service.Stop)
	return service, listens, database
}

func waitDHCPEvents(t *testing.T, listens *dhcpListenLog, want []string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !slices.Equal(listens.snapshot(), want) {
		time.Sleep(time.Millisecond)
	}
	if got := listens.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("socket events = %q; want %q", got, want)
	}
}

// The service follows [dhcp]: enabling binds port 67, unchanged settings
// keep the socket, a change closes the old socket before binding the new
// one (only one process may hold port 67), and disabling closes it.
func TestDHCPServiceFollowsConfiguration(t *testing.T) {
	service, listens, _ := newTestDHCPService(t, "")
	ctx := context.Background()
	settings := dhcpTestSettings(t)
	if err := service.Apply(ctx, ctx, config.DHCP{}); err != nil {
		t.Fatal(err)
	}
	waitDHCPEvents(t, listens, nil)
	if err := service.Apply(ctx, ctx, settings); err != nil {
		t.Fatal(err)
	}
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
		t.Fatal(err)
	}
	waitDHCPEvents(t, listens, []string{"listen"})
	changed := dhcpTestSettings(t)
	changed.Scopes[0].Router = "10.0.7.254"
	if err := service.Apply(ctx, ctx, changed); err != nil {
		t.Fatal(err)
	}
	waitDHCPEvents(t, listens, []string{"listen", "close", "listen"})
	if err := service.Apply(ctx, ctx, config.DHCP{Scopes: changed.Scopes}); err != nil {
		t.Fatal(err)
	}
	waitDHCPEvents(t, listens, []string{"listen", "close", "listen", "close"})
}

// Until leases are mirrored between nodes, a cluster refuses DHCP rather
// than lease one address from two nodes.
func TestDHCPServiceRefusesCluster(t *testing.T) {
	service, listens, _ := newTestDHCPService(t, cluster.RolePrimary)
	ctx := context.Background()
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); !errors.Is(err, errDHCPOnCluster) {
		t.Fatalf("Apply on a cluster = %v; want errDHCPOnCluster", err)
	}
	if err := service.Apply(ctx, ctx, config.DHCP{}); err != nil {
		t.Fatalf("Apply with DHCP off on a cluster = %v", err)
	}
	waitDHCPEvents(t, listens, nil)
}

// A lease acknowledged before a restart is in the store, and the restarted
// server offers the client the same address (RFC 2131 §4.3.1, §2.2).
func TestDHCPServiceKeepsLeasesAcrossRestart(t *testing.T) {
	service, listens, database := newTestDHCPService(t, "")
	ctx := context.Background()
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
		t.Fatal(err)
	}
	conn := listens.last()
	conn.inbound <- dhcpTestPacket(dhcp.Discover).Marshal()
	<-conn.wrote
	_, sent := conn.snapshot()
	conn.inbound <- dhcpTestRequest(sent[0].reply).Marshal()
	<-conn.wrote
	_, sent = conn.snapshot()
	leased := sent[1].reply.YIAddr
	if sent[1].reply.MessageType() != dhcp.Ack {
		t.Fatalf("second reply is %v; want ACK", sent[1].reply.MessageType())
	}
	rows, err := database.DHCPLeases(ctx)
	if err != nil || len(rows) != 1 || rows[0].Address != leased || rows[0].State != store.DHCPLeaseActive {
		t.Fatalf("store holds %+v (%v); want the active lease on %v", rows, err, leased)
	}

	service.Stop()
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
		t.Fatal(err)
	}
	restarted := listens.last()
	discover := dhcpTestPacket(dhcp.Discover)
	discover.XID = [4]byte{1, 2, 3, 4}
	restarted.inbound <- discover.Marshal()
	<-restarted.wrote
	if _, offered := restarted.snapshot(); offered[0].reply.YIAddr != leased {
		t.Fatalf("after a restart the client is offered %v; want its lease %v", offered[0].reply.YIAddr, leased)
	}
}

// Every lease field the engine keeps survives the store and back.
func TestDHCPLeaseStoreConversion(t *testing.T) {
	lease := dhcp.Lease{
		NodeID: "node-a", Address: netip.MustParseAddr("10.0.7.100"), ScopeID: "lan", ClientKey: "id:01",
		MAC: "02:11:22:33:44:55", ClientID: "01", Hostname: "laptop", State: dhcp.LeaseDeclined,
		BoundAt: time.Unix(10, 0), ExpiresAt: time.Unix(20, 0), Relay: "10.0.8.1", VendorClass: "android",
	}
	value := reflect.ValueOf(lease)
	for index := range value.NumField() {
		if value.Field(index).IsZero() {
			t.Fatalf("set %s in this test", value.Type().Field(index).Name)
		}
	}
	if back := dhcpLeaseFromStore(dhcpLeaseToStore(lease)); !reflect.DeepEqual(back, lease) {
		t.Fatalf("round trip = %+v; want %+v", back, lease)
	}
	for _, state := range []dhcp.LeaseState{dhcp.LeaseActive, dhcp.LeaseReleased, dhcp.LeaseExpired, dhcp.LeaseDeclined} {
		if got := store.DHCPLeaseState(state); !slices.Contains([]store.DHCPLeaseState{store.DHCPLeaseActive, store.DHCPLeaseReleased, store.DHCPLeaseExpired, store.DHCPLeaseDeclined}, got) {
			t.Fatalf("engine state %q has no store state", state)
		}
	}
}

// An offered address that answers a probe isn't offered: it's set aside as
// declined for an hour, saved through the store, and the client's next
// DISCOVER gets another address (RFC 2131 §4.4.1, §3.1 step 2).
func TestDHCPServiceSetsAsideProbedConflict(t *testing.T) {
	service, listens, database := newTestDHCPService(t, "")
	var probes sync.Map
	service.probe = func(_ context.Context, address netip.Addr, _ net.HardwareAddr, _ time.Duration) (string, bool) {
		_, again := probes.LoadOrStore(address, true)
		return "echo", !again && address == netip.MustParseAddr("10.0.7.100")
	}
	ctx := context.Background()
	settings := dhcpTestSettings(t)
	settings.Scopes[0].Ranges = []config.DHCPRange{{Start: "10.0.7.100", End: "10.0.7.101"}}
	if err := service.Apply(ctx, ctx, settings); err != nil {
		t.Fatal(err)
	}
	conn := listens.last()
	conn.inbound <- dhcpTestPacket(dhcp.Discover).Marshal()
	deadline := time.Now().Add(5 * time.Second)
	var rows []store.DHCPLease
	for time.Now().Before(deadline) && len(rows) == 0 {
		time.Sleep(time.Millisecond)
		rows, _ = database.DHCPLeases(ctx)
	}
	if len(rows) != 1 || rows[0].Address != netip.MustParseAddr("10.0.7.100") ||
		rows[0].State != store.DHCPLeaseDeclined || rows[0].ClientKey != "conflict:echo" {
		t.Fatalf("store holds %+v; want 10.0.7.100 declined by conflict:echo", rows)
	}
	if _, sent := conn.snapshot(); len(sent) != 0 {
		t.Fatalf("sent %d replies for an address in use", len(sent))
	}
	retry := dhcpTestPacket(dhcp.Discover)
	retry.XID = [4]byte{1, 2, 3, 4}
	conn.inbound <- retry.Marshal()
	<-conn.wrote
	if _, sent := conn.snapshot(); sent[0].reply.YIAddr != netip.MustParseAddr("10.0.7.101") {
		t.Fatalf("offered %v after the conflict; want 10.0.7.101", sent[0].reply.YIAddr)
	}
	if conflicts := service.stats.Conflicts.Load(); conflicts != 1 {
		t.Fatalf("Conflicts = %d; want 1", conflicts)
	}
}

// A replica takes [dhcp] from its primary. It keeps the settings without
// serving them and never refuses them, or every later synchronization from
// the primary fails with it (F29).
func TestDHCPServiceReplicaHoldsPrimarySettings(t *testing.T) {
	service, listens, _ := newTestDHCPService(t, cluster.RoleReplica)
	ctx := context.Background()
	settings := dhcpTestSettings(t)
	if err := service.Check(settings); err != nil {
		t.Fatalf("Check on a replica = %v; want nil", err)
	}
	if err := service.Apply(ctx, ctx, settings); err != nil {
		t.Fatalf("Apply on a replica = %v; want nil", err)
	}
	process := &process{dhcp: service}
	if _, err := process.checkDHCP(config.DHCP{}, settings); err != nil {
		t.Fatalf("checkDHCP taking [dhcp] from the primary = %v; want nil", err)
	}
	waitDHCPEvents(t, listens, nil)
}

// A join that is still applying the primary's state counts as a replica, so
// the primary's [dhcp] isn't served before the join completes (F30).
func TestDHCPClusterRole(t *testing.T) {
	for _, test := range []struct {
		state cluster.State
		want  string
	}{
		{cluster.State{}, ""},
		{cluster.State{Joining: true}, cluster.RoleReplica},
		{cluster.State{Initialized: true, LocalRole: cluster.RolePrimary}, cluster.RolePrimary},
	} {
		if got := dhcpClusterRole(test.state); got != test.want {
			t.Errorf("dhcpClusterRole(%+v) = %q, want %q", test.state, got, test.want)
		}
	}
}
