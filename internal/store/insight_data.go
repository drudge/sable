package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// insightDataDeletedKey records when an operator last deleted what Insights
// had collected, so a replica can tell whether its own copy predates it.
const insightDataDeletedKey = "insights_data_deleted_at"

// insightDataTables are everything Insights collects about devices. The
// sable_insight_notified ledger is left out on purpose: it records which
// alerts of every group were already sent, not anything about a device.
var insightDataTables = []string{
	"sable_client_seen", "sable_client_domain_seen", "sable_client_identity", "sable_insight_feedback",
	"sable_unifi_network", "sable_unifi_station", "sable_unifi_station_traffic",
}

// InsightData is what Insights holds about the network right now.
type InsightData struct {
	// Addresses is how many client addresses have sightings.
	Addresses int
	// Hardware is how many hardware addresses are tied to a client address.
	Hardware int
	// Since is the oldest sighting, zero when there is none.
	Since time.Time
}

// SetClientTracking turns recording which clients were seen, and what
// hardware they are, on or off. Off, query log batches still write and
// identities handed in are dropped, so nothing about a device is kept.
func (store *Store) SetClientTracking(on bool) {
	store.trackingOff.Store(!on)
}

// ClientTracking reports whether client sightings and identities are recorded.
func (store *Store) ClientTracking() bool {
	return !store.trackingOff.Load()
}

// StopClientTracking stops recording client sightings and identities. It
// also settles the one-time fill from the query log, so turning Insights on
// later starts from that moment instead of from history it was told to skip.
func (store *Store) StopClientTracking(ctx context.Context) error {
	store.SetClientTracking(false)
	return store.skipClientSightingBackfill(ctx, store.database)
}

// ResumeClientTracking starts recording client sightings and identities
// again. Sightings missed while tracking was off are not filled in, so the
// tracking marker moves to now: a device first seen shortly after is treated
// like one that may have been there all along, not as new.
func (store *Store) ResumeClientTracking(ctx context.Context, now time.Time) error {
	if err := store.withTx(ctx, "client tracking resume", func(transaction *sql.Tx) error {
		if err := store.skipClientSightingBackfill(ctx, transaction); err != nil {
			return err
		}
		return store.setMetadata(ctx, transaction, clientSeenSinceKey, now)
	}); err != nil {
		return err
	}
	store.SetClientTracking(true)
	return nil
}

// DeleteInsightData deletes every sighting, identity, and hidden finding
// Insights holds, and restarts tracking from now.
func (store *Store) DeleteInsightData(ctx context.Context, now time.Time) error {
	return store.withTx(ctx, "insight data deletion", func(transaction *sql.Tx) error {
		for _, table := range insightDataTables {
			if _, err := transaction.ExecContext(ctx, "DELETE FROM "+table); err != nil {
				return fmt.Errorf("delete %s: %w", table, err)
			}
		}
		if err := store.skipClientSightingBackfill(ctx, transaction); err != nil {
			return err
		}
		for _, key := range []string{clientSeenSinceKey, insightDataDeletedKey} {
			if err := store.setMetadata(ctx, transaction, key, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// InsightDataDeletedAt is when Insights data was last deleted on this node.
func (store *Store) InsightDataDeletedAt(ctx context.Context) (time.Time, bool, error) {
	return store.rollupMarker(ctx, insightDataDeletedKey)
}

// InsightDataSummary counts what Insights holds.
func (store *Store) InsightDataSummary(ctx context.Context) (InsightData, error) {
	var summary InsightData
	var oldest any
	if err := store.database.QueryRowContext(ctx,
		"SELECT COUNT(*), MIN(first_seen) FROM sable_client_seen",
	).Scan(&summary.Addresses, &oldest); err != nil {
		return InsightData{}, fmt.Errorf("count client sightings: %w", err)
	}
	if oldest != nil {
		since, err := databaseTime(oldest)
		if err != nil {
			return InsightData{}, fmt.Errorf("read oldest sighting: %w", err)
		}
		summary.Since = since
	}
	if err := store.database.QueryRowContext(ctx,
		"SELECT COUNT(DISTINCT mac) FROM sable_client_identity",
	).Scan(&summary.Hardware); err != nil {
		return InsightData{}, fmt.Errorf("count client identities: %w", err)
	}
	return summary, nil
}

type metadataExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (store *Store) skipClientSightingBackfill(ctx context.Context, executor metadataExecutor) error {
	if _, err := executor.ExecContext(ctx,
		"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholders(2)+") ON CONFLICT(key) DO NOTHING",
		clientSeenBackfilledKey, time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("record %s: %w", clientSeenBackfilledKey, err)
	}
	return nil
}

func (store *Store) setMetadata(ctx context.Context, executor metadataExecutor, key string, moment time.Time) error {
	if _, err := executor.ExecContext(ctx,
		"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholders(2)+") ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, moment.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("record %s: %w", key, err)
	}
	return nil
}
