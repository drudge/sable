package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// waiters reports how many urgent and normal transactions are waiting.
func (queue *writerQueue) waiters() (urgent, normal int) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return len(queue.urgent), len(queue.normal)
}

// waitForWaiters polls until the queue holds the given waiters.
func waitForWaiters(t *testing.T, queue *writerQueue, urgent, normal int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		gotUrgent, gotNormal := queue.waiters()
		if gotUrgent == urgent && gotNormal == normal {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiters = %d urgent, %d normal; want %d, %d", gotUrgent, gotNormal, urgent, normal)
		}
		time.Sleep(time.Millisecond)
	}
}

// An urgent waiter takes the writer before normal ones that asked earlier,
// and normal ones keep their order.
func TestWriterQueueServesUrgentFirst(t *testing.T) {
	ctx := context.Background()
	queue := &writerQueue{}
	if err := queue.acquire(ctx, writeNormal, time.Minute); err != nil {
		t.Fatal(err)
	}
	order := make(chan string, 3)
	start := func(name string, priority writePriority, urgent, normal int) {
		go func() {
			if err := queue.acquire(ctx, priority, time.Minute); err != nil {
				order <- "error: " + err.Error()
				return
			}
			order <- name
			queue.release()
		}()
		waitForWaiters(t, queue, urgent, normal)
	}
	start("query log 1", writeNormal, 0, 1)
	start("query log 2", writeNormal, 0, 2)
	start("lease", writeUrgent, 1, 2)
	queue.release()
	for _, want := range []string{"lease", "query log 1", "query log 2"} {
		if got := <-order; got != want {
			t.Fatalf("writer went to %q; want %q", got, want)
		}
	}
	if err := queue.acquire(ctx, writeNormal, time.Millisecond); err != nil {
		t.Fatalf("writer still held after every waiter released it: %v", err)
	}
}

// A waiter gives up when its context ends or the limit passes, and leaves
// the queue so the writer still reaches everyone behind it.
func TestWriterQueueWaitEnds(t *testing.T) {
	queue := &writerQueue{}
	if err := queue.acquire(context.Background(), writeNormal, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := queue.acquire(context.Background(), writeNormal, 10*time.Millisecond); !errors.Is(err, errWriterWait) {
		t.Fatalf("acquire past the limit = %v; want errWriterWait", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := queue.acquire(cancelled, writeUrgent, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire with a cancelled context = %v; want context.Canceled", err)
	}
	if urgent, normal := queue.waiters(); urgent != 0 || normal != 0 {
		t.Fatalf("waiters left behind: %d urgent, %d normal", urgent, normal)
	}
	queue.release()
	if err := queue.acquire(context.Background(), writeNormal, time.Millisecond); err != nil {
		t.Fatalf("writer still held after release: %v", err)
	}
}

// A transaction with no deadline of its own stops waiting behind a stuck one
// after the writer wait limit, instead of hanging with it.
func TestSQLiteTransactionWaitIsCapped(t *testing.T) {
	ctx := context.Background()
	storage, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { storage.Close() })
	storage.writerWait = 50 * time.Millisecond

	stuck, unstick := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- storage.withTx(ctx, "stuck", func(*sql.Tx) error {
			close(stuck)
			<-unstick
			return nil
		})
	}()
	<-stuck
	start := time.Now()
	err = storage.withTx(ctx, "behind", func(*sql.Tx) error { return nil })
	if !errors.Is(err, errWriterWait) {
		t.Fatalf("transaction behind a stuck one = %v; want errWriterWait", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("gave up after %s; want about 50ms", elapsed)
	}
	close(unstick)
	if err := <-done; err != nil {
		t.Fatalf("stuck transaction: %v", err)
	}
}

// A DHCP lease save waits as urgent, ahead of query log flushes that queued
// first, so the ACK isn't held behind a backlog of batches.
func TestDHCPLeaseSaveGoesAheadOfQueryLogFlushes(t *testing.T) {
	ctx := context.Background()
	storage, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { storage.Close() })

	held, unhold := make(chan struct{}), make(chan struct{})
	holding := make(chan error, 1)
	go func() {
		holding <- storage.withTx(ctx, "holder", func(*sql.Tx) error {
			close(held)
			<-unhold
			return nil
		})
	}()
	<-held

	const flushes = 3
	flushed := make(chan error, flushes)
	events := benchmarkQueryEvents(64, time.Now())
	for range flushes {
		go func() { flushed <- storage.WriteQueryEvents(ctx, events) }()
	}
	waitForWaiters(t, storage.writer, 0, flushes)
	saved := make(chan error, 1)
	expires := time.Now().Add(time.Hour).UTC()
	go func() {
		_, err := storage.SaveDHCPLease(ctx, testDHCPLease("node-a", "10.0.7.100", "01aabbcc000001", DHCPLeaseActive, expires))
		saved <- err
	}()
	waitForWaiters(t, storage.writer, 1, flushes)

	close(unhold)
	if err := <-holding; err != nil {
		t.Fatalf("holder: %v", err)
	}
	// Had any flush gone first, the first one to finish would find the
	// lease still waiting behind it.
	if err := <-flushed; err != nil {
		t.Fatalf("write query events: %v", err)
	}
	leases, err := storage.DHCPLeases(ctx)
	if err != nil {
		t.Fatalf("read leases: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("leases after the first flush = %d; want the lease saved first", len(leases))
	}
	if err := <-saved; err != nil {
		t.Fatalf("save lease: %v", err)
	}
	for range flushes - 1 {
		if err := <-flushed; err != nil {
			t.Fatalf("write query events: %v", err)
		}
	}
}
