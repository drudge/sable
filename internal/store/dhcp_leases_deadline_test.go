package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// F19's fix on Postgres: does the 2 s deadline on SaveDHCPLeases hold while
// another session has the lease table locked (a long migration, a stuck
// transaction on the other node)? pgx has to cancel the blocked statement.
func TestDHCPLeaseSaveDeadlineUnderPostgresTableLock(t *testing.T) {
	dsn := os.Getenv("SABLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SABLE_TEST_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	storage := openPostgresTestStore(t, dsn)
	holder, err := storage.database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.ExecContext(ctx, `LOCK TABLE sable_dhcp_leases IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	release := time.AfterFunc(8*time.Second, func() { _ = holder.Rollback() })
	defer release.Stop()

	lease := testDHCPLease("node-a", "10.0.7.100", "01aabbcc000001", DHCPLeaseActive, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	saveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	start := time.Now()
	_, err = storage.SaveDHCPLeases(saveCtx, []DHCPLease{lease})
	elapsed := time.Since(start)
	t.Logf("SaveDHCPLeases returned after %s: %v", elapsed.Round(10*time.Millisecond), err)
	if err == nil {
		t.Fatal("save succeeded while the table was locked")
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("save with a 2 s deadline returned after %s", elapsed.Round(10*time.Millisecond))
	}

	// The cancelled save left nothing behind, and the store still works
	// once the lock is gone: the reload after a failed save depends on it.
	if err := holder.Rollback(); err != nil {
		t.Fatal(err)
	}
	afterCtx, cancelAfter := context.WithTimeout(ctx, 2*time.Second)
	defer cancelAfter()
	leases, err := storage.DHCPLeases(afterCtx)
	if err != nil {
		t.Fatalf("load after the cancelled save: %v", err)
	}
	if len(leases) != 0 {
		t.Fatalf("cancelled save left %d leases in the store", len(leases))
	}
	if _, err := storage.SaveDHCPLeases(afterCtx, []DHCPLease{lease}); err != nil {
		t.Fatalf("save after the lock was released: %v", err)
	}
}
