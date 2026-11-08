//go:build faultinject

package faultinject

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"sync"
	"syscall"
)

func diskFullError(what string) error {
	return fmt.Errorf("faultinject: %s: %w", what, syscall.ENOSPC)
}

var registered sync.Map

// SQLDriver registers a driver that wraps the database/sql driver called
// name and returns the wrapper's name. Its connections refuse statements
// and read-write transactions while the disk is full; reads still work.
func SQLDriver(name string) string {
	wrapped := "faultinject-" + name
	if _, loaded := registered.LoadOrStore(wrapped, true); loaded {
		return wrapped
	}
	database, err := sql.Open(name, "")
	if err != nil {
		return name
	}
	inner := database.Driver()
	database.Close()
	sql.Register(wrapped, faultDriver{inner: inner})
	return wrapped
}

type faultDriver struct{ inner driver.Driver }

func (wrapper faultDriver) Open(dsn string) (driver.Conn, error) {
	conn, err := wrapper.inner.Open(dsn)
	if err != nil {
		return nil, err
	}
	return faultConn{Conn: conn}, nil
}

// faultConn passes everything through to the driver's own connection except
// writes. Each optional interface falls back the way database/sql would if
// the inner connection lacks it.
type faultConn struct{ driver.Conn }

func (conn faultConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	if !options.ReadOnly {
		if err := CheckWrite("begin database transaction"); err != nil {
			return nil, err
		}
	}
	if inner, ok := conn.Conn.(driver.ConnBeginTx); ok {
		return inner.BeginTx(ctx, options)
	}
	return conn.Conn.Begin()
}

func (conn faultConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := CheckWrite("database write"); err != nil {
		return nil, err
	}
	if inner, ok := conn.Conn.(driver.ExecerContext); ok {
		return inner.ExecContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (conn faultConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	var statement driver.Stmt
	var err error
	if inner, ok := conn.Conn.(driver.ConnPrepareContext); ok {
		statement, err = inner.PrepareContext(ctx, query)
	} else {
		statement, err = conn.Conn.Prepare(query)
	}
	if err != nil {
		return nil, err
	}
	return faultStmt{Stmt: statement}, nil
}

func (conn faultConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if inner, ok := conn.Conn.(driver.QueryerContext); ok {
		return inner.QueryContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (conn faultConn) Ping(ctx context.Context) error {
	if inner, ok := conn.Conn.(driver.Pinger); ok {
		return inner.Ping(ctx)
	}
	return nil
}

func (conn faultConn) ResetSession(ctx context.Context) error {
	if inner, ok := conn.Conn.(driver.SessionResetter); ok {
		return inner.ResetSession(ctx)
	}
	return nil
}

func (conn faultConn) IsValid() bool {
	if inner, ok := conn.Conn.(driver.Validator); ok {
		return inner.IsValid()
	}
	return true
}

func (conn faultConn) CheckNamedValue(value *driver.NamedValue) error {
	if inner, ok := conn.Conn.(driver.NamedValueChecker); ok {
		return inner.CheckNamedValue(value)
	}
	return driver.ErrSkip
}

// faultStmt refuses a prepared statement's Exec while the disk is full.
type faultStmt struct{ driver.Stmt }

func (statement faultStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if err := CheckWrite("database write"); err != nil {
		return nil, err
	}
	if inner, ok := statement.Stmt.(driver.StmtExecContext); ok {
		return inner.ExecContext(ctx, args)
	}
	values := make([]driver.Value, len(args))
	for index, arg := range args {
		values[index] = arg.Value
	}
	return statement.Stmt.Exec(values)
}

func (statement faultStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if inner, ok := statement.Stmt.(driver.StmtQueryContext); ok {
		return inner.QueryContext(ctx, args)
	}
	values := make([]driver.Value, len(args))
	for index, arg := range args {
		values[index] = arg.Value
	}
	return statement.Stmt.Query(values)
}

func (statement faultStmt) CheckNamedValue(value *driver.NamedValue) error {
	if inner, ok := statement.Stmt.(driver.NamedValueChecker); ok {
		return inner.CheckNamedValue(value)
	}
	return driver.ErrSkip
}
