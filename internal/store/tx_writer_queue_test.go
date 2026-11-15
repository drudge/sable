package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Writers in one process wait their turn for SQLite's write lock instead of
// polling for it under busy_timeout, which isn't fair and lets one writer
// lose every round until it fails with SQLITE_BUSY. The short busy_timeout
// makes that loss show up at once.
func TestSQLiteWritersInOneProcessQueueForTheLock(t *testing.T) {
	ctx := context.Background()
	storage, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db")+"?_pragma=busy_timeout(1)")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { storage.Close() })
	expires := time.Date(2026, 11, 14, 13, 0, 0, 0, time.UTC)
	const writers, each = 16, 40
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := range writers {
		wg.Go(func() {
			for n := range each {
				address := review617Addr(w, n%20+1)
				if _, err := storage.SaveDHCPLease(ctx, testDHCPLease("node-queue", address, address, DHCPLeaseActive, expires)); err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	failed := 0
	for err := range errs {
		if failed == 0 {
			t.Errorf("a writer gave up: %v", err)
		}
		failed++
	}
	if failed > 0 {
		t.Fatalf("%d of %d writers failed to save", failed, writers)
	}
}
