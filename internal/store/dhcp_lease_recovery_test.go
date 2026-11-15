package store

import (
	"context"
	"os"
	"testing"
)

func TestDHCPLeaseRecoveryOpensOnAFreshCounterSQLite(t *testing.T) {
	t.Parallel()
	testDHCPLeaseRecoveryOpensOnAFreshCounter(t, openIdentityStore(t))
}

func TestDHCPLeaseRecoveryOpensOnAFreshCounterPostgres(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_DSN is not set")
	}
	testDHCPLeaseRecoveryOpensOnAFreshCounter(t, openPostgresTestStore(t, dsn))
}

// A node's first number opens a recovery that only climbs until it ends,
// and a later number never opens another.
func testDHCPLeaseRecoveryOpensOnAFreshCounter(t *testing.T, storage *Store) {
	t.Helper()
	ctx := context.Background()
	if _, open, err := storage.DHCPLeaseRecovery(ctx, "node-w"); err != nil || open {
		t.Fatalf("recovery before any lease = %v, %v; want none", open, err)
	}
	mustSaveDHCPLease(t, storage, mirrorTestLease("node-w", "10.0.9.1", "first", 0))
	assertDHCPLeaseRecovery(t, storage, 0, true)
	if err := storage.AdvanceDHCPLeaseRecovery(ctx, "node-w", 30, false); err != nil {
		t.Fatal(err)
	}
	if err := storage.AdvanceDHCPLeaseRecovery(ctx, "node-w", 12, false); err != nil {
		t.Fatal(err)
	}
	assertDHCPLeaseRecovery(t, storage, 30, true)
	if err := storage.AdvanceDHCPLeaseRecovery(ctx, "node-w", 0, true); err != nil {
		t.Fatal(err)
	}
	mustSaveDHCPLease(t, storage, mirrorTestLease("node-w", "10.0.9.2", "second", 0))
	if err := storage.AdvanceDHCPLeaseRecovery(ctx, "node-w", 40, false); err != nil {
		t.Fatal(err)
	}
	assertDHCPLeaseRecovery(t, storage, 0, false)
}

func TestDHCPLeaseRecoveryOpensBelowWhatAnotherNodeHoldsSQLite(t *testing.T) {
	t.Parallel()
	testDHCPLeaseRecoveryOpensBelowWhatAnotherNodeHolds(t, openIdentityStore(t))
}

func TestDHCPLeaseRecoveryOpensBelowWhatAnotherNodeHoldsPostgres(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_DSN is not set")
	}
	testDHCPLeaseRecoveryOpensBelowWhatAnotherNodeHolds(t, openPostgresTestStore(t, dsn))
}

// A counter below what another node holds of this one, or one that was
// never started, opens a recovery; a counter that has reached it doesn't,
// and an open recovery keeps how far it has come.
func testDHCPLeaseRecoveryOpensBelowWhatAnotherNodeHolds(t *testing.T, storage *Store) {
	t.Helper()
	ctx := context.Background()
	if behind, err := storage.OpenDHCPLeaseRecoveryBelow(ctx, "node-w", 5); err != nil || !behind {
		t.Fatalf("a node with no counter, below 5 = %v, %v; want behind", behind, err)
	}
	assertDHCPLeaseRecovery(t, storage, 0, true)
	if err := storage.AdvanceDHCPLeaseRecovery(ctx, "node-w", 3, false); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.OpenDHCPLeaseRecoveryBelow(ctx, "node-w", 5); err != nil {
		t.Fatal(err)
	}
	assertDHCPLeaseRecovery(t, storage, 3, true)
	if err := storage.AdvanceDHCPLeaseRecovery(ctx, "node-w", 0, true); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.RaiseDHCPLeaseSeq(ctx, "node-w", 5); err != nil {
		t.Fatal(err)
	}
	if behind, err := storage.OpenDHCPLeaseRecoveryBelow(ctx, "node-w", 5); err != nil || behind {
		t.Fatalf("a counter at 5, below 5 = %v, %v; want not behind", behind, err)
	}
	assertDHCPLeaseRecovery(t, storage, 0, false)
	if behind, err := storage.OpenDHCPLeaseRecoveryBelow(ctx, "node-w", 6); err != nil || !behind {
		t.Fatalf("a counter at 5, below 6 = %v, %v; want behind", behind, err)
	}
	assertDHCPLeaseRecovery(t, storage, 0, true)
}

func assertDHCPLeaseRecovery(t *testing.T, storage *Store, seq int64, open bool) {
	t.Helper()
	gotSeq, gotOpen, err := storage.DHCPLeaseRecovery(context.Background(), "node-w")
	if err != nil || gotSeq != seq || gotOpen != open {
		t.Fatalf("recovery = %d, %v, %v; want %d, %v", gotSeq, gotOpen, err, seq, open)
	}
}
