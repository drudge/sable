package store

import (
	"context"
	"database/sql"
	"fmt"
)

// withTx runs fn in a transaction and commits it when fn returns nil. Any
// error from fn, or a panic, rolls the transaction back. what names the work
// for the begin and commit errors, as in "begin <what>" and "commit <what>";
// fn wraps its own errors.
func (store *Store) withTx(ctx context.Context, what string, fn func(*sql.Tx) error) error {
	return store.runTx(ctx, nil, writeNormal, what, fn)
}

// withUrgentTx is withTx for a transaction that goes ahead of every other
// waiting for the SQLite writer; see writeUrgent.
func (store *Store) withUrgentTx(ctx context.Context, what string, fn func(*sql.Tx) error) error {
	return store.runTx(ctx, nil, writeUrgent, what, fn)
}

// withTxOptions is withTx with transaction options, such as a serializable
// isolation level.
func (store *Store) withTxOptions(ctx context.Context, options *sql.TxOptions, what string, fn func(*sql.Tx) error) error {
	return store.runTx(ctx, options, writeNormal, what, fn)
}

// runTx runs fn in a transaction with options.
//
// On SQLite every transaction begins IMMEDIATE and so takes the one write
// lock. Writers that miss it poll under busy_timeout with growing sleeps, and
// the poll is not fair: under load one writer can lose every round for the
// whole timeout and fail with SQLITE_BUSY while the others commit. This
// process's transactions wait their turn on store.writer instead, by priority
// and then in order, for as long as ctx allows and at most writerWaitLimit,
// so busy_timeout is left to cover other processes.
func (store *Store) runTx(ctx context.Context, options *sql.TxOptions, priority writePriority, what string, fn func(*sql.Tx) error) error {
	if store.writer != nil {
		limit := store.writerWait
		if limit <= 0 {
			limit = writerWaitLimit
		}
		if err := store.writer.acquire(ctx, priority, limit); err != nil {
			return fmt.Errorf("begin %s: %w", what, err)
		}
		defer store.writer.release()
	}
	transaction, err := store.database.BeginTx(ctx, options)
	if err != nil {
		return fmt.Errorf("begin %s: %w", what, err)
	}
	// Rollback after a successful Commit is a no-op that returns sql.ErrTxDone.
	defer transaction.Rollback()
	if err := fn(transaction); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit %s: %w", what, err)
	}
	return nil
}
