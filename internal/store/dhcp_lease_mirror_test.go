package store

import (
	"context"
	"maps"
	"os"
	"testing"
	"time"
)

func TestDHCPLeaseMirrorSQLite(t *testing.T) {
	t.Parallel()
	testDHCPLeaseMirror(t, openIdentityStore(t))
}

func TestDHCPLeaseMirrorPostgres(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_DSN is not set")
	}
	testDHCPLeaseMirror(t, openPostgresTestStore(t, dsn))
}

func TestDHCPLeaseHeldSQLite(t *testing.T) {
	t.Parallel()
	testDHCPLeaseHeld(t, openIdentityStore(t))
}

func TestDHCPLeaseHeldPostgres(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_DSN is not set")
	}
	testDHCPLeaseHeld(t, openPostgresTestStore(t, dsn))
}

func TestDHCPLeaseRaiseSeqSQLite(t *testing.T) {
	t.Parallel()
	testDHCPLeaseRaiseSeq(t, openIdentityStore(t))
}

func TestDHCPLeaseRaiseSeqPostgres(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_DSN is not set")
	}
	testDHCPLeaseRaiseSeq(t, openPostgresTestStore(t, dsn))
}

func mirrorTestLease(node, address, client string, seq int64) DHCPLease {
	lease := testDHCPLease(node, address, client, DHCPLeaseActive, time.Date(2026, 11, 14, 13, 0, 0, 0, time.UTC))
	lease.Seq = seq
	return lease
}

func mustSaveDHCPLease(t *testing.T, storage *Store, lease DHCPLease) DHCPLease {
	t.Helper()
	saved, err := storage.SaveDHCPLease(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

// A mirrored row keeps the owner's seq and leaves this node's counter alone,
// an older or repeated row is skipped, and a newer one replaces the stored row.
func testDHCPLeaseMirror(t *testing.T, storage *Store) {
	t.Helper()
	ctx := context.Background()
	count, err := storage.MirrorDHCPLeases(ctx, []DHCPLease{
		mirrorTestLease("node-m", "10.0.9.1", "c1", 5), mirrorTestLease("node-m", "10.0.9.2", "c2", 6)})
	if err != nil || count != 2 {
		t.Fatalf("mirror = %d, %v; want 2", count, err)
	}
	held, err := storage.DHCPLeaseHeld(ctx)
	if err != nil || held["node-m"] != 6 {
		t.Fatalf("held = %v, %v; want node-m at 6", held, err)
	}
	// No counter was created: this node's first write for that ID takes 1.
	if saved := mustSaveDHCPLease(t, storage, mirrorTestLease("node-m", "10.0.9.3", "c3", 0)); saved.Seq != 1 {
		t.Fatalf("own write after a mirror took seq %d; want 1", saved.Seq)
	}

	stale := mirrorTestLease("node-n", "10.0.9.10", "old", 4)
	if count, err = storage.MirrorDHCPLeases(ctx, []DHCPLease{mirrorTestLease("node-n", "10.0.9.10", "kept", 4)}); err != nil || count != 1 {
		t.Fatalf("first mirror = %d, %v; want 1", count, err)
	}
	for _, seq := range []int64{4, 3} {
		stale.Seq = seq
		if count, err = storage.MirrorDHCPLeases(ctx, []DHCPLease{stale}); err != nil || count != 0 {
			t.Fatalf("mirror at seq %d = %d, %v; want 0", seq, count, err)
		}
	}
	if got := heldLeaseClient(t, storage, "node-n"); got != "kept" {
		t.Fatalf("stored client = %q after skipped rows; want kept", got)
	}
	newer := mirrorTestLease("node-n", "10.0.9.10", "new", 9)
	if count, err = storage.MirrorDHCPLeases(ctx, []DHCPLease{newer}); err != nil || count != 1 {
		t.Fatalf("newer mirror = %d, %v; want 1", count, err)
	}
	if got := heldLeaseClient(t, storage, "node-n"); got != "new" {
		t.Fatalf("stored client = %q after a newer row; want new", got)
	}
	if held, err = storage.DHCPLeaseHeld(ctx); err != nil || held["node-n"] != 9 {
		t.Fatalf("held = %v, %v; want node-n at 9", held, err)
	}

	bad := mirrorTestLease("node-p", "10.0.9.20", "c", 0)
	invalid := mirrorTestLease("node-p", "10.0.9.21", "", 3)
	for name, batch := range map[string][]DHCPLease{
		"seq 0":   {mirrorTestLease("node-p", "10.0.9.22", "ok", 2), bad},
		"invalid": {mirrorTestLease("node-p", "10.0.9.22", "ok", 2), invalid},
	} {
		if count, err = storage.MirrorDHCPLeases(ctx, batch); err == nil || count != 0 {
			t.Fatalf("mirror with %s = %d, %v; want an error", name, count, err)
		}
	}
	if held, err = storage.DHCPLeaseHeld(ctx); err != nil || held["node-p"] != 0 {
		t.Fatalf("held = %v, %v; want nothing from the refused batches", held, err)
	}
}

func heldLeaseClient(t *testing.T, storage *Store, nodeID string) string {
	t.Helper()
	leases, err := storage.DHCPLeasesSince(context.Background(), nodeID, 0, 10)
	if err != nil || len(leases) != 1 {
		t.Fatalf("leases of %s = %+v, %v; want one", nodeID, leases, err)
	}
	return leases[0].ClientKey
}

// DHCPLeaseHeld reports the highest seq per node over own and mirrored rows.
func testDHCPLeaseHeld(t *testing.T, storage *Store) {
	t.Helper()
	ctx := context.Background()
	held, err := storage.DHCPLeaseHeld(ctx)
	if err != nil || held == nil || len(held) != 0 {
		t.Fatalf("empty held = %#v, %v; want an empty map", held, err)
	}
	mustSaveDHCPLease(t, storage, mirrorTestLease("node-own", "10.0.9.1", "a", 0))
	mustSaveDHCPLease(t, storage, mirrorTestLease("node-own", "10.0.9.2", "b", 0))
	if _, err := storage.MirrorDHCPLeases(ctx, []DHCPLease{
		mirrorTestLease("node-far", "10.0.9.3", "c", 11), mirrorTestLease("node-far", "10.0.9.4", "d", 7)}); err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"node-own": 2, "node-far": 11}
	if held, err = storage.DHCPLeaseHeld(ctx); err != nil || !maps.Equal(held, want) {
		t.Fatalf("held = %v, %v; want %v", held, err, want)
	}
}

// RaiseDHCPLeaseSeq lifts a counter that is behind and renumbers the node's
// rows above it in order, never lowers one, and creates one for a node it
// hasn't seen.
func testDHCPLeaseRaiseSeq(t *testing.T, storage *Store) {
	t.Helper()
	ctx := context.Background()
	mustSaveDHCPLease(t, storage, mirrorTestLease("node-r", "10.0.9.1", "a", 0))
	mustSaveDHCPLease(t, storage, mirrorTestLease("node-r", "10.0.9.2", "b", 0))
	steps := []struct {
		raise   int64
		changed bool
		next    int64
	}{{7, true, 10}, {5, false, 11}}
	for index, step := range steps {
		changed, err := storage.RaiseDHCPLeaseSeq(ctx, "node-r", step.raise)
		if err != nil || changed != step.changed {
			t.Fatalf("raise to %d = %v, %v; want %v", step.raise, changed, err, step.changed)
		}
		if index == 0 {
			renumbered, err := storage.DHCPLeasesSince(ctx, "node-r", 7, 10)
			if err != nil || len(renumbered) != 2 || renumbered[0].Address.String() != "10.0.9.1" ||
				renumbered[0].Seq != 8 || renumbered[1].Seq != 9 {
				t.Fatalf("rows after the raise = %+v, %v; want 10.0.9.1 at 8 and 10.0.9.2 at 9", renumbered, err)
			}
		}
		address := "10.0.9." + string(rune('3'+index))
		if saved := mustSaveDHCPLease(t, storage, mirrorTestLease("node-r", address, address, 0)); saved.Seq != step.next {
			t.Fatalf("save after raise to %d took seq %d; want %d", step.raise, saved.Seq, step.next)
		}
	}
	if changed, err := storage.RaiseDHCPLeaseSeq(ctx, "node-new", 4); err != nil || !changed {
		t.Fatalf("raise on an unknown node = %v, %v; want true", changed, err)
	}
	if saved := mustSaveDHCPLease(t, storage, mirrorTestLease("node-new", "10.0.9.50", "n", 0)); saved.Seq != 5 {
		t.Fatalf("first save on a raised node took seq %d; want 5", saved.Seq)
	}
}
