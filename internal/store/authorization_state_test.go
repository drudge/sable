package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"modernc.org/sqlite"
)

var errMembershipScan = errors.New("membership scan interrupted")

// A replica replaces its whole authorization state with the export, so an
// export that stops reading memberships partway must fail rather than hand
// over users with missing roles.
func TestAuthorizationStateExportFailsWhenMembershipsStopEarly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sable.db")
	seeded, err := Open(context.Background(), "sqlite", path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { seeded.Close() })
	ctx := context.Background()
	seedAdministrator(t, seeded)
	if _, err := seeded.CreateFederatedUser(ctx, "casey", "Casey", "casey@example.com",
		[]string{"Auditor"}, "pocket-id", "subject-1", "https://id.example.com", time.Now()); err != nil {
		t.Fatalf("provision federated user: %v", err)
	}

	// SQLite cannot fail partway through a sorted result on demand, so the
	// same file is read through a driver whose membership rows break after the
	// first one, the way a dropped connection or cancelled context would.
	database := sql.OpenDB(failingMembershipsConnector{path: path})
	t.Cleanup(func() { database.Close() })
	broken := &Store{database: database, driver: "sqlite"}

	state, err := broken.ExportAuthorizationState(ctx)
	if !errors.Is(err, errMembershipScan) {
		t.Fatalf("export error = %v with users %+v, want the membership scan error", err, state.Users)
	}
}

type failingMembershipsConnector struct{ path string }

func (connector failingMembershipsConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := (&sqlite.Driver{}).Open(connector.path)
	if err != nil {
		return nil, err
	}
	return failingMembershipsConn{Conn: conn}, nil
}

func (connector failingMembershipsConnector) Driver() driver.Driver { return &sqlite.Driver{} }

type failingMembershipsConn struct{ driver.Conn }

func (conn failingMembershipsConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := conn.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	if err != nil || !strings.Contains(query, "FROM sable_user_roles") {
		return rows, err
	}
	return &failingMembershipsRows{Rows: rows}, nil
}

type failingMembershipsRows struct {
	driver.Rows
	read int
}

func (rows *failingMembershipsRows) Next(dest []driver.Value) error {
	if rows.read == 1 {
		return errMembershipScan
	}
	if err := rows.Rows.Next(dest); err != nil {
		return err
	}
	rows.read++
	return nil
}
