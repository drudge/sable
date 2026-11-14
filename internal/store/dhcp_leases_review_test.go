package store

// Load and plan checks on the lease store from the #617 review: a cursor
// reader under concurrent writers, per-node independence, bad input, and the
// prune's index.

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func review617Stores(t *testing.T) map[string]*Store {
	t.Helper()
	stores := map[string]*Store{"sqlite": openIdentityStore(t)}
	if dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN"); dsn != "" {
		stores["postgres"] = openPostgresTestStore(t, dsn)
	}
	return stores
}

func review617Addr(writer, n int) string {
	return netip.AddrFrom4([4]byte{10, 9, byte(writer), byte(n)}).String()
}

// What slice 8 leans on: a reader that pages DHCPLeasesSince with a cursor
// while writers are busy ends up having seen every row at its final seq. If a
// write could commit with a seq below one already visible, the cursor would
// step over it for good.
func TestReview617CursorReaderMissesNothing(t *testing.T) {
	for name, storage := range review617Stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			node := "node-cursor-" + name
			expires := time.Date(2026, 11, 14, 13, 0, 0, 0, time.UTC)
			const writers, each = 8, 60
			var wg sync.WaitGroup
			errs := make(chan error, writers*each)
			for w := range writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for n := range each {
						// 20 addresses per writer, rewritten three times over
						address := review617Addr(w, n%20+1)
						if _, err := storage.SaveDHCPLease(ctx, testDHCPLease(node, address, address, DHCPLeaseActive, expires)); err != nil {
							errs <- err
							return
						}
					}
				}()
			}
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			seen := map[string]int64{}
			var cursor int64
			drain := func() {
				for {
					rows, err := storage.DHCPLeasesSince(ctx, node, cursor, 25)
					if err != nil {
						t.Error(err)
						return
					}
					if len(rows) == 0 {
						return
					}
					for _, row := range rows {
						if row.Seq <= cursor {
							t.Errorf("since %d returned seq %d", cursor, row.Seq)
						}
						cursor = row.Seq
						seen[row.Address.String()] = row.Seq
					}
				}
			}
			for running := true; running; {
				select {
				case <-done:
					running = false
				default:
				}
				drain()
			}
			drain()
			close(errs)
			for err := range errs {
				t.Fatal(err)
			}
			all, err := storage.DHCPLeases(ctx)
			if err != nil {
				t.Fatal(err)
			}
			seqs := map[int64]bool{}
			count := 0
			for _, row := range all {
				if row.NodeID != node {
					continue
				}
				count++
				if seqs[row.Seq] {
					t.Errorf("seq %d is on two rows", row.Seq)
				}
				seqs[row.Seq] = true
				if got := seen[row.Address.String()]; got != row.Seq {
					t.Errorf("%s: cursor reader last saw seq %d, the row is at %d", row.Address, got, row.Seq)
				}
			}
			if count != writers*20 {
				t.Errorf("rows = %d; want %d", count, writers*20)
			}
			if cursor != writers*each {
				t.Errorf("cursor ended at %d; want %d (one number per write, no gaps)", cursor, writers*each)
			}
		})
	}
}

// Two nodes can each hold a row for one address (after a range moves), and
// their counters don't touch.
func TestReview617NodesAreIndependent(t *testing.T) {
	for name, storage := range review617Stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			expires := time.Date(2026, 11, 14, 13, 0, 0, 0, time.UTC)
			a, err := storage.SaveDHCPLease(ctx, testDHCPLease("r617-a-"+name, "10.9.200.1", "c1", DHCPLeaseExpired, expires))
			if err != nil {
				t.Fatal(err)
			}
			b, err := storage.SaveDHCPLease(ctx, testDHCPLease("r617-b-"+name, "10.9.200.1", "c1", DHCPLeaseActive, expires))
			if err != nil {
				t.Fatal(err)
			}
			if a.Seq != 1 || b.Seq != 1 {
				t.Errorf("first seqs = %d, %d; want 1, 1", a.Seq, b.Seq)
			}
			rows, err := storage.DHCPLeasesSince(ctx, "r617-a-"+name, 0, 10)
			if err != nil || len(rows) != 1 || rows[0].State != DHCPLeaseExpired {
				t.Errorf("node a since 0 = %+v, %v", rows, err)
			}
		})
	}
}

// Bad input is refused the same way on both backends.
func TestReview617BadInput(t *testing.T) {
	for name, storage := range review617Stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			expires := time.Date(2026, 11, 14, 13, 0, 0, 0, time.UTC)
			mapped := testDHCPLease("r617-bad", "10.9.201.1", "c1", DHCPLeaseActive, expires)
			mapped.Address = netip.MustParseAddr("::ffff:10.9.201.1")
			if _, err := storage.SaveDHCPLease(ctx, mapped); err == nil {
				t.Error("an IPv4-mapped IPv6 address was saved")
			}
			if _, err := storage.SaveDHCPLease(ctx, testDHCPLease("r617-bad", "10.9.201.1", "c1", "offered", expires)); err == nil {
				t.Error("state offered was saved")
			}
			// A refused lease must not burn or create a counter row.
			if _, err := storage.SaveDHCPLease(ctx, testDHCPLease("r617-bad", "10.9.201.1", "c1", DHCPLeaseActive, expires)); err != nil {
				t.Fatal(err)
			}
			for _, limit := range []int{0, -1} {
				rows, err := storage.DHCPLeasesSince(ctx, "r617-bad", 0, limit)
				t.Logf("%s: limit %d -> %d rows, err %v", name, limit, len(rows), err)
			}
		})
	}
}

// AGENTS.md, Store: "Add an index for every column a query or prune filters
// on." PruneDHCPLeases filters on state and expires_at_ns, and step 2 can't be
// edited once it ships. The statement below is PruneDHCPLeases' own; keep the
// two in step.
func TestReview617PruneUsesAnIndex(t *testing.T) {
	storage := openIdentityStore(t)
	rows, err := storage.database.QueryContext(context.Background(),
		"EXPLAIN QUERY PLAN DELETE FROM sable_dhcp_leases WHERE state <> ? AND expires_at_ns < ?", "active", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		t.Logf("plan: %s", detail)
		if len(detail) >= 4 && detail[:4] == "SCAN" {
			t.Errorf("the prune reads the whole table (%s): no index covers expires_at_ns", detail)
		}
	}
}
