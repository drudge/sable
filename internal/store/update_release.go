package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/drudge/sable/internal/update"
)

const updateReleaseMetadataKey = "update_release"

func (store *Store) LoadUpdateRelease(ctx context.Context) (update.ReleaseInfo, error) {
	var encoded string
	err := store.database.QueryRowContext(ctx,
		"SELECT value FROM sable_metadata WHERE key = "+store.placeholder(1), updateReleaseMetadataKey,
	).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return update.ReleaseInfo{}, nil
	}
	if err != nil {
		return update.ReleaseInfo{}, fmt.Errorf("load update release: %w", err)
	}
	var release update.ReleaseInfo
	if err := json.Unmarshal([]byte(encoded), &release); err != nil {
		return update.ReleaseInfo{}, fmt.Errorf("decode update release: %w", err)
	}
	return release, nil
}

func (store *Store) SaveUpdateRelease(ctx context.Context, release update.ReleaseInfo) error {
	encoded, err := json.Marshal(release)
	if err != nil {
		return fmt.Errorf("encode update release: %w", err)
	}
	_, err = store.database.ExecContext(ctx,
		"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholders(2)+") "+
			"ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		updateReleaseMetadataKey, string(encoded),
	)
	if err != nil {
		return fmt.Errorf("save update release: %w", err)
	}
	return nil
}
