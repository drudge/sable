package store

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestDHCPLeaseStoreSQLite(t *testing.T) {
	t.Parallel()
	testDHCPLeaseStore(t, openIdentityStore(t))
}

func TestDHCPLeaseStorePostgres(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_DSN is not set")
	}
	storage := openPostgresTestStore(t, dsn)
	testDHCPLeaseStore(t, storage)
	testDHCPLeaseSeqConcurrent(t, storage)
}

// A prune that deletes a node's newest row doesn't hand its sequence number
// out again: a replica already past it would never ask for the next write.
func TestDHCPLeaseSeqSurvivesPrune(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	storage := openIdentityStore(t)
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	if _, err := storage.SaveDHCPLease(ctx, testDHCPLease("node-a", "10.0.7.100", "c1", DHCPLeaseActive, now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	pruned, err := storage.SaveDHCPLease(ctx, testDHCPLease("node-a", "10.0.7.101", "c2", DHCPLeaseExpired, now.Add(-2*dhcpLeaseRetention)))
	if err != nil {
		t.Fatal(err)
	}
	if count, err := storage.PruneDHCPLeases(ctx, now); err != nil || count != 1 {
		t.Fatalf("prune = %d, %v; want 1", count, err)
	}
	next, err := storage.SaveDHCPLease(ctx, testDHCPLease("node-a", "10.0.7.102", "c3", DHCPLeaseActive, now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if next.Seq <= pruned.Seq {
		t.Fatalf("write after the prune took seq %d; want more than the pruned row's %d", next.Seq, pruned.Seq)
	}
	since, err := storage.DHCPLeasesSince(ctx, "node-a", pruned.Seq, 10)
	if err != nil || len(since) != 1 || since[0].Address != next.Address {
		t.Fatalf("since seq %d = %+v, %v; want only the new write", pruned.Seq, since, err)
	}
}

// Writers on one node racing each other each take their own sequence number.
func testDHCPLeaseSeqConcurrent(t *testing.T, storage *Store) {
	t.Helper()
	ctx := context.Background()
	expires := time.Date(2026, 11, 14, 13, 0, 0, 0, time.UTC)
	const writers = 16
	seqs := make(chan int64, writers)
	errs := make(chan error, writers)
	for index := range writers {
		go func() {
			address := netip.AddrFrom4([4]byte{10, 0, 8, byte(index + 1)}).String()
			lease, err := storage.SaveDHCPLease(ctx, testDHCPLease("node-race", address, address, DHCPLeaseActive, expires))
			seqs <- lease.Seq
			errs <- err
		}()
	}
	seen := map[int64]bool{}
	for range writers {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		seq := <-seqs
		if seen[seq] {
			t.Fatalf("two concurrent writes took seq %d", seq)
		}
		seen[seq] = true
	}
}

func testDHCPLease(node, address, client string, state DHCPLeaseState, expires time.Time) DHCPLease {
	return DHCPLease{
		NodeID: node, Address: netip.MustParseAddr(address), ScopeID: "lan", ClientKey: client,
		MAC: "aa:bb:cc:00:00:01", ClientID: "01aabbcc000001", Hostname: "Office-Printer", Label: "office-printer",
		State: state, BoundAt: expires.Add(-24 * time.Hour), ExpiresAt: expires,
		Relay: "0104000a0001", VendorClass: "MSFT 5.0",
	}
}

// A node's leases round-trip, a rewrite of an address replaces its row, each
// write takes the node's next sequence number, and the heartbeat's since query
// pages through one node's writes in order.
func testDHCPLeaseStore(t *testing.T, storage *Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	first, err := storage.SaveDHCPLease(ctx, testDHCPLease("node-a", "10.0.7.100", "01aabbcc000001", DHCPLeaseActive, now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := storage.SaveDHCPLease(ctx, testDHCPLease("node-a", "10.0.7.101", "01aabbcc000002", DHCPLeaseActive, now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	other, err := storage.SaveDHCPLease(ctx, testDHCPLease("node-b", "10.0.7.200", "01aabbcc000003", DHCPLeaseActive, now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq != 1 || second.Seq != 2 || other.Seq != 1 {
		t.Fatalf("sequences = %d, %d, %d; want 1, 2 and node-b's own 1", first.Seq, second.Seq, other.Seq)
	}
	released := first
	released.State, released.ExpiresAt = DHCPLeaseReleased, now
	if released, err = storage.SaveDHCPLease(ctx, released); err != nil || released.Seq != 3 {
		t.Fatalf("release = seq %d, %v; want seq 3", released.Seq, err)
	}
	leases, err := storage.DHCPLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []DHCPLease{second, released, other}; !slices.Equal(leases, want) {
		t.Fatalf("leases = %+v\nwant %+v", leases, want)
	}
	since, err := storage.DHCPLeasesSince(ctx, "node-a", 1, 1)
	if err != nil || len(since) != 1 || since[0] != second {
		t.Fatalf("since seq 1, one row = %+v, %v; want the lease at seq 2", since, err)
	}
	for _, bad := range []DHCPLease{
		testDHCPLease("", "10.0.7.1", "c", DHCPLeaseActive, now),
		testDHCPLease("node-a", "2001:db8::1", "c", DHCPLeaseActive, now),
		testDHCPLease("node-a", "10.0.7.1", "", DHCPLeaseActive, now),
		testDHCPLease("node-a", "10.0.7.1", "c", "offered", now),
	} {
		if _, err := storage.SaveDHCPLease(ctx, bad); err == nil {
			t.Errorf("saved invalid lease %+v", bad)
		}
	}
}

// Leases that stopped holding their address are kept 30 days, so a returning
// client gets its old address; active leases are never pruned.
func TestPruneDHCPLeasesKeepsActiveAndRecent(t *testing.T) {
	t.Parallel()
	storage := openIdentityStore(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	old := now.Add(-31 * 24 * time.Hour)
	for _, lease := range []DHCPLease{
		testDHCPLease("node-a", "10.0.7.10", "stale-active", DHCPLeaseActive, old),
		testDHCPLease("node-a", "10.0.7.11", "old-expired", DHCPLeaseExpired, old),
		testDHCPLease("node-a", "10.0.7.12", "old-declined", DHCPLeaseDeclined, old),
		testDHCPLease("node-a", "10.0.7.13", "recent-released", DHCPLeaseReleased, now.Add(-29*24*time.Hour)),
	} {
		if _, err := storage.SaveDHCPLease(ctx, lease); err != nil {
			t.Fatal(err)
		}
	}
	if pruned, err := storage.PruneDHCPLeases(ctx, now); err != nil || pruned != 2 {
		t.Fatalf("pruned %d, %v; want 2", pruned, err)
	}
	leases, err := storage.DHCPLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, lease := range leases {
		kept = append(kept, lease.ClientKey)
	}
	if !slices.Equal(kept, []string{"stale-active", "recent-released"}) {
		t.Fatalf("kept %v", kept)
	}
}

// A lease is durable once SaveDHCPLease returns: a process that stops right
// after, without closing the store, finds it on the next start.
func TestDHCPLeaseSurvivesRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sable.db")
	first, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := first.SaveDHCPLease(ctx, testDHCPLease("node-a", "10.0.7.100", "01aabbcc000001", DHCPLeaseActive,
		time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	// A second connection reads what the first one committed, the way the
	// next start would, while the first is still open.
	second, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close(); first.Close() })
	leases, err := second.DHCPLeases(ctx)
	if err != nil || len(leases) != 1 || leases[0] != saved {
		t.Fatalf("after restart = %+v, %v; want %+v", leases, err, saved)
	}
}
