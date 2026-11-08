//go:build faultinject

package faultinject

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"syscall"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSQLDriverRefusesWritesWhileTheDiskIsFull(t *testing.T) {
	ctx := context.Background()
	write := UseFaults(t, Faults{})
	database, err := sql.Open(SQLDriver("sqlite"), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.ExecContext(ctx, "CREATE TABLE notes (body TEXT)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := database.ExecContext(ctx, "INSERT INTO notes VALUES (?)", "before"); err != nil {
		t.Fatalf("insert before the disk filled: %v", err)
	}

	write(Faults{DiskFull: true})
	if _, err := database.ExecContext(ctx, "INSERT INTO notes VALUES (?)", "during"); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("insert while full = %v, want ENOSPC", err)
	}
	if _, err := database.BeginTx(ctx, nil); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("begin while full = %v, want ENOSPC", err)
	}
	var count int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM notes").Scan(&count); err != nil || count != 1 {
		t.Fatalf("read while full = %d, %v; want 1 row and no error", count, err)
	}
	readOnly, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("read-only begin while full: %v", err)
	}
	readOnly.Rollback()

	write(Faults{})
	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin after the disk cleared: %v", err)
	}
	defer transaction.Rollback()
	statement, err := transaction.PrepareContext(ctx, "INSERT INTO notes VALUES (?)")
	if err != nil {
		t.Fatal(err)
	}
	defer statement.Close()
	write(Faults{DiskFull: true})
	if _, err := statement.ExecContext(ctx, "prepared"); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("prepared insert while full = %v, want ENOSPC", err)
	}
}

func TestSQLDriverRegistersOnce(t *testing.T) {
	if first, second := SQLDriver("sqlite"), SQLDriver("sqlite"); first != second || first == "sqlite" {
		t.Fatalf("SQLDriver(sqlite) = %q then %q, want one wrapped name", first, second)
	}
}
