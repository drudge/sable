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
	return store.withTxOptions(ctx, nil, what, fn)
}

// withTxOptions is withTx with transaction options, such as a serializable
// isolation level.
//
// On SQLite every transaction begins IMMEDIATE and so takes the one write
// lock. Writers that miss it poll under busy_timeout with growing sleeps, and
// the poll is not fair: under load one writer can lose every round for the
// whole timeout and fail with SQLITE_BUSY while the others commit. This
// process's transactions wait their turn on a queue instead, in order and for
// as long as ctx allows, so busy_timeout is left to cover other processes.
func (store *Store) withTxOptions(ctx context.Context, options *sql.TxOptions, what string, fn func(*sql.Tx) error) error {
	if store.writer != nil {
		select {
		case store.writer <- struct{}{}:
			defer func() { <-store.writer }()
		case <-ctx.Done():
			return fmt.Errorf("begin %s: %w", what, ctx.Err())
		}
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
