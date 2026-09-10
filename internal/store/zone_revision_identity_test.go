package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestZoneRevisionIdentityMigrationPreservesHistoricalOwners(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "history.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`CREATE TABLE sable_zone_revisions (
zone_name TEXT NOT NULL, revision BIGINT NOT NULL, change_kind TEXT NOT NULL,
snapshot_json TEXT NOT NULL, created_at TIMESTAMP NOT NULL, PRIMARY KEY (zone_name, revision));
INSERT INTO sable_zone_revisions VALUES
('example.test', 1, 'created', '{"name":"example.test"}', CURRENT_TIMESTAMP),
('example.test', 2, 'updated', '{"id":"old-zone","name":"example.test"}', CURRENT_TIMESTAMP),
('example.test', 3, 'created', '{"id":"new-zone","name":"example.test"}', CURRENT_TIMESTAMP)`)
	database.Close()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		opened, err := Open(ctx, "sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		revisions, err := opened.ListZoneRevisions(ctx, "example.test", 10)
		opened.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(revisions) != 3 || revisions[0].ZoneID != "new-zone" || revisions[1].ZoneID != "old-zone" || revisions[2].ZoneID != "" {
			t.Fatalf("migrated history=%+v", revisions)
		}
		if revisions[0].Zone.Name != "" {
			t.Fatal("metadata listing loaded a full zone snapshot")
		}
	}
}
