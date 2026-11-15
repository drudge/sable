package app

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/store"
)

// A named reservation is the operator's name for the device: DNS publishes
// it in place of the name the client sends (dhcpScopeNames), so Insights has
// to call the device the same thing. Before, a TV reserved as "living-room"
// that calls itself "android-3f2a" answered to living-room.lan in DNS and
// was shown as android-3f2a in Insights, under a DHCP badge.
func TestDHCPIdentitiesUseTheReservationsName(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	settings := config.DHCP{Scopes: []config.DHCPScope{
		{ID: "lan", Reservations: []config.DHCPReservation{
			{MAC: "3C:22:FB:01:02:03", Address: "10.0.0.100", Name: "Living Room"},
			{MAC: "da:a1:19:00:00:01", Address: "10.0.0.101"},
		}},
		{ID: "guest", Reservations: []config.DHCPReservation{{MAC: "aa:aa:aa:00:00:09", Address: "10.0.9.5", Name: "kiosk"}}},
	}}
	lease := func(scope, address, mac, host string) store.DHCPLease {
		return store.DHCPLease{NodeID: "a", ScopeID: scope, Address: netip.MustParseAddr(address), MAC: mac, Hostname: host,
			Label: dhcpLabel(host, false), State: store.DHCPLeaseActive, ExpiresAt: now.Add(time.Hour)}
	}
	leases := []store.DHCPLease{
		lease("lan", "10.0.0.100", "3c:22:fb:01:02:03", "android-3f2a"), // named reservation: its name wins
		lease("lan", "10.0.0.101", "da:a1:19:00:00:01", "kids-ipad"),    // unnamed reservation: the client's name
		lease("lan", "10.0.0.150", "aa:aa:aa:00:00:09", "walk-in"),      // reserved as kiosk in another scope only
		lease("lan", "10.0.0.151", "aa:aa:aa:00:00:0a", "wpad"),         // no label taken (D39): the raw host name
	}
	var recorded []querylog.ClientIdentity
	err := recordDHCPIdentities(context.Background(), func() bool { return true },
		func(context.Context) ([]store.DHCPLease, error) { return leases, nil }, func() string { return "a" },
		func() config.DHCP { return settings },
		func(_ context.Context, identities []querylog.ClientIdentity) error { recorded = identities; return nil }, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"living-room", "kids-ipad", "walk-in", "wpad"}
	if len(recorded) != len(want) {
		t.Fatalf("recorded = %+v", recorded)
	}
	for i, name := range want {
		if recorded[i].Hostname != name {
			t.Errorf("%s is recorded as %q, want %q", recorded[i].Address, recorded[i].Hostname, name)
		}
	}
}
