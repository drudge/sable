package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const mcpUseMetadataKey = "mcp_last_use"

// MCPUse records the most recent MCP tool call this node answered, so the
// Integrations card can say whether an assistant is actually connected.
type MCPUse struct {
	At       time.Time `json:"at"`
	Username string    `json:"username,omitempty"`
	Client   string    `json:"client,omitempty"`
	Tool     string    `json:"tool,omitempty"`
}

// LoadMCPUse returns the last recorded MCP tool call. A node that has never
// answered one returns the zero value.
func (store *Store) LoadMCPUse(ctx context.Context) (MCPUse, error) {
	var encoded string
	err := store.database.QueryRowContext(
		ctx, "SELECT value FROM sable_metadata WHERE key = "+store.placeholder(1), mcpUseMetadataKey,
	).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return MCPUse{}, nil
	}
	if err != nil {
		return MCPUse{}, fmt.Errorf("load MCP use: %w", err)
	}
	var use MCPUse
	if err := json.Unmarshal([]byte(encoded), &use); err != nil {
		return MCPUse{}, fmt.Errorf("decode MCP use: %w", err)
	}
	return use, nil
}

// SaveMCPUse replaces the last recorded MCP tool call.
func (store *Store) SaveMCPUse(ctx context.Context, use MCPUse) error {
	encoded, err := json.Marshal(use)
	if err != nil {
		return fmt.Errorf("encode MCP use: %w", err)
	}
	if _, err := store.database.ExecContext(ctx,
		"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholders(2)+") "+
			"ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		mcpUseMetadataKey, string(encoded),
	); err != nil {
		return fmt.Errorf("save MCP use: %w", err)
	}
	return nil
}
