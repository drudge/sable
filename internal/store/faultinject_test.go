//go:build faultinject

package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/drudge/sable/internal/faultinject"
)

func TestSQLiteWritesFailWhileTheDiskIsFull(t *testing.T) {
	ctx := context.Background()
	write := faultinject.UseFaults(t, faultinject.Faults{})
	opened, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer opened.Close()

	write(faultinject.Faults{DiskFull: true})
	if err := opened.withTx(ctx, "fault test", func(*sql.Tx) error { return nil }); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("withTx() while full = %v, want ENOSPC", err)
	}
	if _, err := opened.database.ExecContext(ctx, "DELETE FROM sable_metadata WHERE key = 'fault-test'"); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("exec while full = %v, want ENOSPC", err)
	}
	var count int
	if err := opened.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sable_metadata").Scan(&count); err != nil {
		t.Fatalf("read while full: %v", err)
	}

	write(faultinject.Faults{})
	if err := opened.withTx(ctx, "fault test", func(*sql.Tx) error { return nil }); err != nil {
		t.Fatalf("withTx() after the disk cleared = %v", err)
	}
}
