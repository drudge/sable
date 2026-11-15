package app

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/drudge/sable/internal/store"
)

// A lease crosses the cluster with every field it was stored with, so a
// mirror holds what its owner holds.
func TestDHCPLeaseCrossesTheMirrorWhole(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	row := store.DHCPLease{
		NodeID: "node-b", Address: netip.MustParseAddr("10.0.0.150"), ScopeID: "lan", ClientKey: "01:aa:bb:cc:dd:ee:ff",
		MAC: "aa:bb:cc:dd:ee:ff", ClientID: "01aabbccddeeff", Hostname: "Phone", Label: "phone", State: store.DHCPLeaseActive,
		BoundAt: now, ExpiresAt: now.Add(time.Hour), Seq: 42, Relay: "10.0.1.1", VendorClass: "android-dhcp-14",
	}
	for index := range reflect.TypeFor[store.DHCPLease]().NumField() {
		if reflect.ValueOf(row).Field(index).IsZero() {
			t.Fatalf("the test lease leaves %s empty", reflect.TypeFor[store.DHCPLease]().Field(index).Name)
		}
	}
	back, err := storedDHCPLease(sharedDHCPLease(row))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, row) {
		t.Fatalf("after the mirror:\n%+v\nwant\n%+v", back, row)
	}
}
