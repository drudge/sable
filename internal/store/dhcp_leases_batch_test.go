package store

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestDHCPLeasesSaveTogetherSQLite(t *testing.T) {
	t.Parallel()
	testDHCPLeasesSaveTogether(t, openIdentityStore(t))
}

func TestDHCPLeasesSaveTogetherPostgres(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_DSN is not set")
	}
	testDHCPLeasesSaveTogether(t, openPostgresTestStore(t, dsn))
}

// A client that moves releases its old lease and takes a new one in the same
// ACK, so both rows land in one transaction or neither does: a restart must
// never find the old lease still active beside the new one.
func testDHCPLeasesSaveTogether(t *testing.T, storage *Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	old := testDHCPLease("node-a", "10.0.7.100", "c1", DHCPLeaseActive, now.Add(time.Hour))
	if _, err := storage.SaveDHCPLease(ctx, old); err != nil {
		t.Fatal(err)
	}
	released := old
	released.State, released.ExpiresAt = DHCPLeaseReleased, now
	moved := testDHCPLease("node-a", "10.0.7.101", "c1", DHCPLeaseActive, now.Add(time.Hour))
	saved, err := storage.SaveDHCPLeases(ctx, []DHCPLease{released, moved})
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 2 || saved[0].Seq != 2 || saved[1].Seq != 3 {
		t.Fatalf("saved = %+v; want seqs 2 and 3 in order", saved)
	}
	broken := testDHCPLease("node-a", "10.0.7.102", "c2", DHCPLeaseActive, now.Add(time.Hour))
	invalid := testDHCPLease("node-a", "10.0.7.103", "", DHCPLeaseActive, now.Add(time.Hour))
	if _, err := storage.SaveDHCPLeases(ctx, []DHCPLease{broken, invalid}); err == nil {
		t.Fatal("saved a batch holding an invalid lease")
	}
	leases, err := storage.DHCPLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, lease := range leases {
		if lease.Address == broken.Address {
			t.Fatalf("a failed batch left %s behind", lease.Address)
		}
	}
	if len(leases) != 2 {
		t.Fatalf("leases = %+v; want the released and moved rows only", leases)
	}
}
