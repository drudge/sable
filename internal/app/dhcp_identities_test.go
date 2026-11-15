package app

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/store"
)

// A lease ties an address to a hardware address for as long as it lasts, so
// Insights can follow a device that DHCP moves, without reading the neighbor
// table (design doc §Insights: a lease is the "dhcp" identity source).
func TestDHCPIdentitiesRecordOnlyThisNodesActiveLeases(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	lease := func(node, address, mac, host, label string, state store.DHCPLeaseState, expires time.Time) store.DHCPLease {
		return store.DHCPLease{NodeID: node, Address: netip.MustParseAddr(address), MAC: mac, Hostname: host, Label: label, State: state, ExpiresAt: expires}
	}
	leases := []store.DHCPLease{
		lease("a", "10.0.0.100", "3C:22:FB:01:02:03", "George's MacBook", "georges-macbook", store.DHCPLeaseActive, now.Add(time.Hour)),
		lease("a", "10.0.0.101", "da:a1:19:00:00:01", "kids-ipad", "", store.DHCPLeaseActive, now.Add(time.Hour)),
		lease("a", "10.0.0.102", "aa:aa:aa:00:00:01", "expired", "", store.DHCPLeaseActive, now.Add(-time.Second)),
		lease("a", "10.0.0.103", "aa:aa:aa:00:00:02", "released", "", store.DHCPLeaseReleased, now.Add(time.Hour)),
		lease("b", "10.0.0.150", "aa:aa:aa:00:00:03", "peer", "", store.DHCPLeaseActive, now.Add(time.Hour)),
	}
	var recorded []querylog.ClientIdentity
	record := func(_ context.Context, identities []querylog.ClientIdentity) error { recorded = identities; return nil }
	read := func(context.Context) ([]store.DHCPLease, error) { return leases, nil }

	if err := recordDHCPIdentities(context.Background(), func() bool { return false }, read, func() string { return "a" }, record, now); err != nil {
		t.Fatal(err)
	}
	if recorded != nil {
		t.Fatalf("Insights off recorded %+v", recorded)
	}
	if err := recordDHCPIdentities(context.Background(), func() bool { return true }, read, func() string { return "a" }, record, now); err != nil {
		t.Fatal(err)
	}
	want := []querylog.ClientIdentity{
		{Address: "10.0.0.100", MAC: "3c:22:fb:01:02:03", Source: dhcpIdentitySource, Hostname: "georges-macbook", SeenAt: now},
		{Address: "10.0.0.101", MAC: "da:a1:19:00:00:01", Source: dhcpIdentitySource, Hostname: "kids-ipad", SeenAt: now},
	}
	if len(recorded) != len(want) {
		t.Fatalf("recorded = %+v", recorded)
	}
	for i := range want {
		if recorded[i] != want[i] {
			t.Fatalf("identity %d = %+v, want %+v", i, recorded[i], want[i])
		}
	}
}
