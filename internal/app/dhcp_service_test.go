package app

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dhcp"
	"github.com/drudge/sable/internal/store"
)

// dhcpReadGapStore runs during, once armed, between a read of the leases and
// its return: what the old server does while the new engine is built.
type dhcpReadGapStore struct {
	dhcpLeaseStore
	mutex  sync.Mutex
	during func()
}

func (gap *dhcpReadGapStore) DHCPLeases(ctx context.Context) ([]store.DHCPLease, error) {
	rows, err := gap.dhcpLeaseStore.DHCPLeases(ctx)
	gap.mutex.Lock()
	during := gap.during
	gap.during = nil
	gap.mutex.Unlock()
	if during != nil {
		during()
	}
	return rows, err
}

// A [dhcp] reload reads leases once the old server has stopped, so a lease
// it acknowledged while the new engine was built isn't offered to another
// client (RFC 2131 §4.3.1, §2.2).
func TestDHCPServiceReloadReadsLeasesAfterOldServerStops(t *testing.T) {
	service, listens, database := newTestDHCPService(t, "")
	gap := &dhcpReadGapStore{dhcpLeaseStore: database}
	service.leases = gap
	ctx := context.Background()
	settings := dhcpTestSettings(t)
	settings.Scopes[0].Ranges = []config.DHCPRange{{Start: "10.0.7.100", End: "10.0.7.101"}}
	if err := service.Apply(ctx, ctx, settings); err != nil {
		t.Fatal(err)
	}
	old := listens.last()
	gap.during = func() {
		select {
		case <-old.closed:
			return // the old server stopped before the read: no gap
		default:
		}
		old.inbound <- dhcpTestPacket(dhcp.Discover).Marshal()
		<-old.wrote
		_, sent := old.snapshot()
		old.inbound <- dhcpTestRequest(sent[0].reply).Marshal()
		<-old.wrote
	}
	changed := settings
	changed.Scopes = []config.DHCPScope{settings.Scopes[0]}
	changed.Scopes[0].Router = "10.0.7.254"
	if err := service.Apply(ctx, ctx, changed); err != nil {
		t.Fatal(err)
	}
	rows, err := database.DHCPLeases(ctx)
	if err != nil || len(rows) > 1 {
		t.Fatalf("store holds %+v (%v)", rows, err)
	}
	if len(rows) == 0 {
		// Nothing could be acknowledged during the read; offer from the pool.
		rows = []store.DHCPLease{{}}
	}
	other := dhcpTestPacket(dhcp.Discover)
	other.XID = [4]byte{5, 5, 5, 5}
	other.CHAddr = net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	current := listens.last()
	current.inbound <- other.Marshal()
	select {
	case <-current.wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("no OFFER after the reload")
	}
	_, sent := current.snapshot()
	if offered := sent[0].reply.YIAddr; offered == rows[0].Address {
		t.Fatalf("after the reload %v was offered to %v; the store holds it as %s's active lease, acknowledged during the reload",
			offered, other.CHAddr, rows[0].MAC)
	}
}

// dhcpReadFailConn fails its first read, as recvmsg does when the link goes
// down, and then behaves like the fake it wraps.
type dhcpReadFailConn struct {
	dhcpConn
	once sync.Once
}

func (conn *dhcpReadFailConn) ReadPacket(buffer []byte) (int, int, error) {
	var failed bool
	conn.once.Do(func() { failed = true })
	if failed {
		return 0, 0, errors.New("recvmsg: network is down")
	}
	return conn.dhcpConn.ReadPacket(buffer)
}

// A server whose socket fails is started again, so DHCP doesn't stay off
// until the process restarts or [dhcp] changes.
func TestDHCPServiceRestartsAfterReadFailure(t *testing.T) {
	service, listens, _ := newTestDHCPService(t, "")
	var mutex sync.Mutex
	binds := 0
	service.listen = func(ctx context.Context, port int) (dhcpConn, error) {
		conn, err := listens.listen(ctx, port)
		mutex.Lock()
		defer mutex.Unlock()
		binds++
		if binds == 1 {
			return &dhcpReadFailConn{dhcpConn: conn}, err
		}
		return conn, err
	}
	ctx := context.Background()
	settings := dhcpTestSettings(t)
	if err := service.Apply(ctx, ctx, settings); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mutex.Lock()
		count := binds
		mutex.Unlock()
		if count >= 2 {
			break
		}
		if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	mutex.Lock()
	count := binds
	mutex.Unlock()
	if count < 2 {
		t.Fatalf("port 67 was bound %d time(s); the server stopped on a read error and nothing started it again", count)
	}
	conn := listens.last()
	conn.inbound <- dhcpTestPacket(dhcp.Discover).Marshal()
	select {
	case <-conn.wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("the restarted server didn't answer")
	}
}

// Port 67 that can't be bound is a condition of the host, not of the
// configuration: Apply accepts the settings, so a change elsewhere in
// sable.toml isn't rejected, and the service binds once it can.
func TestDHCPServiceRetriesUnbindablePort(t *testing.T) {
	service, listens, _ := newTestDHCPService(t, "")
	var mutex sync.Mutex
	attempts := 0
	service.listen = func(ctx context.Context, port int) (dhcpConn, error) {
		mutex.Lock()
		attempts++
		refused := attempts <= 2
		mutex.Unlock()
		if refused {
			return nil, errors.New("listen udp4 0.0.0.0:67: bind: permission denied")
		}
		return listens.listen(ctx, port)
	}
	ctx := context.Background()
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
		t.Fatalf("Apply with port 67 unbindable = %v; want the settings accepted", err)
	}
	if err := service.Apply(ctx, ctx, dhcpTestSettings(t)); err != nil {
		t.Fatalf("Apply with unchanged [dhcp] = %v; want nil", err)
	}
	waitDHCPEvents(t, listens, []string{"listen"})
}
