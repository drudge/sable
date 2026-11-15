package web

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/store"
)

// The drawer's DHCP Lease is the device's own. The test
// laptop (3c:22:fb:01:02:03) used 10.0.0.5 in the window and holds no lease
// now; whatever sits on 10.0.0.5 today is not its lease.
func TestDeviceDrawerLeaseIsTheDevicesOwn(t *testing.T) {
	t.Parallel()
	now := time.Now()
	tablet := store.DHCPLease{
		NodeID: "node-a", Address: netip.MustParseAddr("10.0.0.5"), ScopeID: "lan", ClientKey: "01a4:83:e7:00:00:09",
		MAC: "a4:83:e7:00:00:09", Hostname: "tablet", Label: "tablet", State: store.DHCPLeaseActive,
		BoundAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	declined := store.DHCPLease{
		NodeID: "node-a", Address: netip.MustParseAddr("10.0.0.5"), ScopeID: "lan", ClientKey: "conflict:aa:bb:cc:00:00:01",
		State: store.DHCPLeaseDeclined, BoundAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	own := store.DHCPLease{
		NodeID: "node-a", Address: netip.MustParseAddr("10.0.0.40"), ScopeID: "lan", ClientKey: "013c:22:fb:01:02:03",
		MAC: "3c:22:fb:01:02:03", Hostname: "laptop", Label: "laptop", State: store.DHCPLeaseActive,
		BoundAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	for _, test := range []struct {
		name   string
		leases []store.DHCPLease
		want   string // the address the drawer shows; empty for no DHCP Lease section
	}{
		{"another device now leases the laptop's old address", []store.DHCPLease{tablet}, ""},
		{"the laptop's old address is held as declined", []store.DHCPLease{declined}, ""},
		{"the laptop has moved and another device took its old address", []store.DHCPLease{tablet, own}, "10.0.0.40"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := newInsightsTestServer(t)
			server.withDeviceLease(t)
			server.SetDHCPController(&testDHCPController{leases: test.leases})
			body := server.get(t, "everything", "/ui/insights/device?range=day&key="+url.QueryEscape(insightsTestLaptop), true).Body.String()
			shown := ""
			if _, after, found := strings.Cut(body, `data-device-reserve="`); found {
				shown, _, _ = strings.Cut(after, `"`)
			} else if strings.Contains(body, `id="insight-device-lease"`) {
				shown = "a lease with no Reserve button"
			}
			if shown != test.want {
				t.Errorf("the laptop's drawer offers to reserve %q, want %q", shown, test.want)
			}
		})
	}
}
