package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/drudge/sable/internal/update"
)

const updateReleaseMetadataKey = "update_release"

func (store *Store) LoadUpdateRelease(ctx context.Context) (update.ReleaseInfo, error) {
	encoded, found, err := store.getMeta(ctx, store.database, updateReleaseMetadataKey)
	if err != nil {
		return update.ReleaseInfo{}, fmt.Errorf("load update release: %w", err)
	}
	if !found {
		return update.ReleaseInfo{}, nil
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
	if err := store.setMeta(ctx, store.database, updateReleaseMetadataKey, string(encoded)); err != nil {
		return fmt.Errorf("save update release: %w", err)
	}
	return nil
}
