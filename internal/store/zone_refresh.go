package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const zoneRefreshesMetadataKey = "zone_refreshes"

// ZoneRefresh is when this node last had a managed zone's content confirmed by
// its primaries, and the SOA serial it held then. RFC 1035 section 4.3.5
// measures a secondary's expire timer from that moment, so it has to outlive
// the process.
type ZoneRefresh struct {
	Serial      uint32    `json:"serial"`
	RefreshedAt time.Time `json:"refreshed_at"`
}

// LoadZoneRefreshes returns the saved refresh of every managed zone, keyed by
// zone name. The marks are node-local: each node times its own transfers.
func (store *Store) LoadZoneRefreshes(ctx context.Context) (map[string]ZoneRefresh, error) {
	encoded, found, err := store.getMeta(ctx, store.database, zoneRefreshesMetadataKey)
	if err != nil {
		return nil, fmt.Errorf("load zone refreshes: %w", err)
	}
	refreshes := make(map[string]ZoneRefresh)
	if !found {
		return refreshes, nil
	}
	if err := json.Unmarshal([]byte(encoded), &refreshes); err != nil {
		return nil, fmt.Errorf("decode zone refreshes: %w", err)
	}
	return refreshes, nil
}

// SaveZoneRefreshes replaces every saved zone refresh.
func (store *Store) SaveZoneRefreshes(ctx context.Context, refreshes map[string]ZoneRefresh) error {
	encoded, err := json.Marshal(refreshes)
	if err != nil {
		return fmt.Errorf("encode zone refreshes: %w", err)
	}
	if err := store.setMeta(ctx, store.database, zoneRefreshesMetadataKey, string(encoded)); err != nil {
		return fmt.Errorf("save zone refreshes: %w", err)
	}
	return nil
}
