package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const mcpUseMetadataKey = "mcp_last_use"

const (
	// Calls are counted in 15-minute buckets because every time zone's
	// midnight falls on one, so "today" can be summed for any operator.
	mcpCallBucket  = 15 * time.Minute
	mcpCallHistory = 48 * time.Hour
)

// MCPUse records the most recent MCP tool call this node answered and how
// many it answered recently, so the Integrations card can say whether an
// assistant is actually connected.
type MCPUse struct {
	At       time.Time      `json:"at"`
	Username string         `json:"username,omitempty"`
	Client   string         `json:"client,omitempty"`
	Tool     string         `json:"tool,omitempty"`
	Calls    []MCPCallCount `json:"calls,omitempty"`
}

// MCPCallCount is the number of tool calls in the bucket that starts at Start.
type MCPCallCount struct {
	Start time.Time `json:"start"`
	Calls int       `json:"calls"`
}

// RecordCall notes one tool call and drops counts older than two days, which
// is more than any time zone's "today" can reach back.
func (use *MCPUse) RecordCall(at time.Time, username, client, tool string) {
	at = at.UTC()
	use.At, use.Username, use.Client, use.Tool = at, username, client, tool
	start := at.Truncate(mcpCallBucket)
	oldest := start.Add(-mcpCallHistory)
	kept := use.Calls[:0]
	for _, count := range use.Calls {
		if count.Start.After(oldest) {
			kept = append(kept, count)
		}
	}
	use.Calls = kept
	if last := len(use.Calls) - 1; last >= 0 && use.Calls[last].Start.Equal(start) {
		use.Calls[last].Calls++
		return
	}
	use.Calls = append(use.Calls, MCPCallCount{Start: start, Calls: 1})
}

// CallsSince totals the calls in buckets starting at or after since.
func (use MCPUse) CallsSince(since time.Time) int {
	total := 0
	for _, count := range use.Calls {
		if !count.Start.Before(since) {
			total += count.Calls
		}
	}
	return total
}

// LoadMCPUse returns the last recorded MCP tool call. A node that has never
// answered one returns the zero value.
func (store *Store) LoadMCPUse(ctx context.Context) (MCPUse, error) {
	encoded, found, err := store.getMeta(ctx, store.database, mcpUseMetadataKey)
	if err != nil {
		return MCPUse{}, fmt.Errorf("load MCP use: %w", err)
	}
	if !found {
		return MCPUse{}, nil
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
	if err := store.setMeta(ctx, store.database, mcpUseMetadataKey, string(encoded)); err != nil {
		return fmt.Errorf("save MCP use: %w", err)
	}
	return nil
}
