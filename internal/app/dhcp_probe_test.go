package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/neighbors"
)

// Without a ping socket the probe still reads the neighbor table: another
// host's hardware address on the offered address is a conflict, the
// client's own isn't, and the missing socket is logged once with the sysctl
// that allows it.
func TestDHCPProberNeighborTable(t *testing.T) {
	var logged strings.Builder
	prober := &dhcpProber{
		listen: func() (net.PacketConn, error) { return nil, errors.New("socket: permission denied") },
		neighbors: func() ([]neighbors.Entry, error) {
			return []neighbors.Entry{{Address: netip.MustParseAddr("10.0.7.100"), MAC: net.HardwareAddr{2, 0, 0, 0, 0, 9}}}, nil
		},
		logger: slog.New(slog.NewTextHandler(&logged, nil)),
	}
	ctx := context.Background()
	taken := netip.MustParseAddr("10.0.7.100")
	if holder, found := prober.probe(ctx, taken, dhcpTestMAC, time.Second); !found || holder != "02:00:00:00:00:09" {
		t.Fatalf("probe = %q, %v; want the neighbor's MAC", holder, found)
	}
	if _, found := prober.probe(ctx, taken, net.HardwareAddr{2, 0, 0, 0, 0, 9}, time.Second); found {
		t.Fatal("the client's own neighbor entry counted as a conflict")
	}
	if _, found := prober.probe(ctx, netip.MustParseAddr("10.0.7.101"), dhcpTestMAC, time.Second); found {
		t.Fatal("an address with no neighbor entry counted as a conflict")
	}
	if count := strings.Count(logged.String(), "ping_group_range"); count != 1 {
		t.Fatalf("the missing ping socket was logged %d times; want once", count)
	}
}

// The ping socket gets an echo reply from a host that answers: loopback.
func TestDHCPProberEchoLoopback(t *testing.T) {
	prober := newDHCPProber(slog.New(slog.NewTextHandler(testLogWriter{t}, nil)))
	conn, err := prober.listen()
	if err != nil {
		t.Skipf("no unprivileged ping socket here (net.ipv4.ping_group_range): %v", err)
	}
	_ = conn.Close()
	if !prober.echo(context.Background(), netip.MustParseAddr("127.0.0.1"), 2*time.Second) {
		t.Fatal("127.0.0.1 didn't answer the probe's echo")
	}
}
