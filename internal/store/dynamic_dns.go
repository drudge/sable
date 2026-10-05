package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/drudge/sable/internal/dynamicdns"
)

const dynamicDNSStateMetadataKey = "dynamic_dns_state"

// LoadDynamicDNSState restores publication history saved by the Dynamic DNS
// manager. A deployment that has never published anything has no row yet.
func (store *Store) LoadDynamicDNSState(ctx context.Context) (dynamicdns.PersistentState, error) {
	encoded, found, err := store.getMeta(ctx, store.database, dynamicDNSStateMetadataKey)
	if err != nil {
		return dynamicdns.PersistentState{}, fmt.Errorf("load dynamic DNS state: %w", err)
	}
	if !found {
		return dynamicdns.PersistentState{}, nil
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
	if err := store.setMeta(ctx, store.database, dynamicDNSStateMetadataKey, string(encoded)); err != nil {
		return fmt.Errorf("save dynamic DNS state: %w", err)
	}
	return nil
}
