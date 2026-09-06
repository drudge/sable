package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/drudge/sable/internal/dynamicdns"
)

const dynamicDNSStateMetadataKey = "dynamic_dns_state"

// LoadDynamicDNSState restores publication history saved by the Dynamic DNS
// manager. A deployment that has never published anything has no row yet.
func (store *Store) LoadDynamicDNSState(ctx context.Context) (dynamicdns.PersistentState, error) {
	var encoded string
	err := store.database.QueryRowContext(
		ctx,
		"SELECT value FROM sable_metadata WHERE key = "+store.placeholder(1),
		dynamicDNSStateMetadataKey,
	).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return dynamicdns.PersistentState{}, nil
	}
	if err != nil {
		return dynamicdns.PersistentState{}, fmt.Errorf("load dynamic DNS state: %w", err)
	}
	var state dynamicdns.PersistentState
	if err := json.Unmarshal([]byte(encoded), &state); err != nil {
		return dynamicdns.PersistentState{}, fmt.Errorf("decode dynamic DNS state: %w", err)
	}
	return state, nil
}

// SaveDynamicDNSState stores the useful publication history independently of
// process lifetime so upgrades and controlled restarts do not reset the UI.
func (store *Store) SaveDynamicDNSState(ctx context.Context, state dynamicdns.PersistentState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode dynamic DNS state: %w", err)
	}
	_, err = store.database.ExecContext(
		ctx,
		"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholders(2)+") "+
			"ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		dynamicDNSStateMetadataKey,
		string(encoded),
	)
	if err != nil {
		return fmt.Errorf("save dynamic DNS state: %w", err)
	}
	return nil
}
