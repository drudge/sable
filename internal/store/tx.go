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
func (store *Store) withTxOptions(ctx context.Context, options *sql.TxOptions, what string, fn func(*sql.Tx) error) error {
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
