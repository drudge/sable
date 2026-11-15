package app

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/dhcp"
	"github.com/drudge/sable/internal/web"
)

// Setup offers each IPv4 network the host is on, with the interface's
// default gateway; a /32 has no room for a pool.
func TestDHCPServiceListsHostNetworks(t *testing.T) {
	service, _, _ := newTestDHCPService(t, "")
	service.links = func() ([]dhcpProbeLink, error) {
		links, _ := dhcpOthersTestLinks()
		links[1].Meta.Addrs = append(links[1].Meta.Addrs, netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("169.254.3.4/16"))
		return links, nil
	}
	service.gateways = func() map[string]netip.Addr { return map[string]netip.Addr{"eth0": netip.MustParseAddr("10.0.7.1")} }
	networks, err := service.Networks()
	want := []web.DHCPNetwork{
		{Interface: "eth0", Prefix: netip.MustParsePrefix("10.0.7.2/24"), Gateway: netip.MustParseAddr("10.0.7.1")},
		{Interface: "eth1", Prefix: netip.MustParsePrefix("192.168.9.2/24")},
	}
	if err != nil || !slices.Equal(networks, want) {
		t.Fatalf("Networks() = %+v, %v; want %+v", networks, err, want)
	}
}

// Turn On's probe reports what answered and which interfaces it couldn't
// go out of, rather than calling a failed probe an all-clear.
func TestDHCPServiceFindOthersReportsWhatAnswered(t *testing.T) {
	service, _, _ := newTestDHCPService(t, "")
	service.links = dhcpOthersTestLinks
	service.seek = func(_ context.Context, _ dhcpProbeLink, discover []byte, _ time.Duration) ([][]byte, error) {
		return [][]byte{dhcpOthersTestReply(t, discover, dhcp.Offer, "10.0.7.1", nil)}, nil
	}
	others, err := service.FindOthers(context.Background(), dhcpTestSettings(t))
	want := []web.DHCPOtherServer{{Interface: "eth0", Server: netip.MustParseAddr("10.0.7.1"), Offered: netip.MustParseAddr("10.0.7.50")}}
	if err != nil || !slices.Equal(others, want) {
		t.Fatalf("FindOthers() = %+v, %v; want %+v", others, err, want)
	}

	service.seek = func(context.Context, dhcpProbeLink, []byte, time.Duration) ([][]byte, error) {
		return nil, errors.New("bind :68: permission denied")
	}
	others, err = service.FindOthers(context.Background(), dhcpTestSettings(t))
	if len(others) != 0 || err == nil || !strings.Contains(err.Error(), "eth0: ") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("FindOthers() with a failing probe = %+v, %v; want the interface and why", others, err)
	}
}

// A cluster node can't enable DHCP yet, so Turn On sends no DISCOVER there.
func TestDHCPServiceFindOthersSkipsClusterNodes(t *testing.T) {
	service, _, _ := newTestDHCPService(t, "")
	service.links = dhcpOthersTestLinks
	service.role = func() string { return cluster.RolePrimary }
	service.seek = func(context.Context, dhcpProbeLink, []byte, time.Duration) ([][]byte, error) {
		t.Fatal("a cluster node probed")
		return nil, nil
	}
	if others, err := service.FindOthers(context.Background(), dhcpTestSettings(t)); len(others) != 0 || err != nil {
		t.Fatalf("FindOthers() on a cluster node = %+v, %v", others, err)
	}
}

func TestParseDefaultGateways(t *testing.T) {
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth0\t00000000\t0107000A\t0003\t0\t0\t100\t00000000\n" +
		"eth0\t0007000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\n" +
		"eth1\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\n" +
		"wg0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\n"
	gateways := parseDefaultGateways(bufio.NewScanner(strings.NewReader(table)))
	if len(gateways) != 2 || gateways["eth0"] != netip.MustParseAddr("10.0.7.1") || gateways["eth1"] != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("gateways = %v", gateways)
	}
}
