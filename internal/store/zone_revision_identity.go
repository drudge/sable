package store

import "context"

// Historical IDs travel in metadata so listing history does not load record
// snapshots. The migration is atomic: an interrupted backfill must be retried.
func (store *Store) migrateZoneRevisionIdentity(ctx context.Context) error {
	exists, err := store.tableHasColumn(ctx, "sable_zone_revisions", "zone_id")
	if err != nil || exists {
		return err
	}
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, "ALTER TABLE sable_zone_revisions ADD COLUMN zone_id TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	identity := "COALESCE(json_extract(snapshot_json, '$.id'), '')"
	if store.driver == "postgres" {
		identity = "COALESCE(snapshot_json::jsonb ->> 'id', '')"
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE sable_zone_revisions SET zone_id = "+identity); err != nil {
		return err
	}
	return transaction.Commit()
}
