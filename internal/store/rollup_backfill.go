package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// blockedClientBackfilledKey records that blocked-client rollups were filled
// in from the query history written before the dimension existed.
const blockedClientBackfilledKey = "query_log_rollup_blocked_client_backfilled"

// blockedClientBackfillChunk is how much history one backfill transaction
// counts, so the query log writer never waits long for it.
const blockedClientBackfillChunk = 6 * time.Hour

// blockedClientBackfillSettle is how long after the dimension began its first
// minute is left alone, so no query still being written lands in a minute
// after it was counted.
const blockedClientBackfillSettle = 2 * time.Minute

// BackfillBlockedClientRollups counts the blocked queries of each client,
// minute by minute, for the history written before blocked-client rollups
// began, then moves that dimension's marker back to where the other rollups
// begin. Until it has run, every window reaching back past the upgrade counts
// those minutes from the raw log, which is most of a month of rows. It works
// from the newest history back, moving the marker after each chunk, so a
// partial run already helps and an interrupted one resumes where it stopped.
// It runs once per database, in the background, and never on the DNS request
// path.
func (store *Store) BackfillBlockedClientRollups(ctx context.Context) (bool, error) {
	if _, done, err := store.rollupMarker(ctx, blockedClientBackfilledKey); err != nil || done {
		return false, err
	}
	began, found, err := store.blockedClientRollupSince(ctx)
	if err != nil || !found {
		return false, err
	}
	// The minute the dimension began holds both kinds of rows, so it is counted
	// whole, once nothing more can arrive for it.
	end := began.UTC().Truncate(time.Minute).Add(time.Minute)
	if wait := time.Until(end.Add(blockedClientBackfillSettle)); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-timer.C:
		}
	}
	coverage, covered, err := store.queryLogRollupStart(ctx)
	if err != nil {
		return false, err
	}
	filled := false
	if covered && coverage.Before(end) {
		for end.After(coverage) {
			start := maxTime(coverage, end.Add(-blockedClientBackfillChunk))
			if err := store.backfillBlockedClientChunk(ctx, start, end); err != nil {
				return filled, err
			}
			filled, end = true, start
		}
	}
	if _, err := store.database.ExecContext(ctx,
		"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholders(2)+") ON CONFLICT(key) DO NOTHING",
		blockedClientBackfilledKey, time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return filled, fmt.Errorf("record %s: %w", blockedClientBackfilledKey, err)
	}
	return filled, nil
}

// backfillBlockedClientChunk counts one stretch of history into the rollups,
// replacing whatever the stretch held, and marks the dimension complete from
// its start.
func (store *Store) backfillBlockedClientChunk(ctx context.Context, start, end time.Time) error {
	rows, err := store.database.QueryContext(ctx, `
SELECT client_ip_key, occurred_at FROM sable_query_log
WHERE source = `+store.placeholder(1)+` AND occurred_at >= `+store.placeholder(2)+` AND occurred_at < `+store.placeholder(3),
		string(querylog.SourceBlocked), start, end)
	if err != nil {
		return fmt.Errorf("read blocked history: %w", err)
	}
	counts := make(map[queryLogRollupKey]uint64)
	for rows.Next() {
		var client string
		var occurred any
		if err := rows.Scan(&client, &occurred); err != nil {
			rows.Close()
			return fmt.Errorf("scan blocked history: %w", err)
		}
		moment, err := databaseTime(occurred)
		if err != nil {
			rows.Close()
			return fmt.Errorf("read blocked history time: %w", err)
		}
		counts[queryLogRollupKey{bucket: moment.UTC().Truncate(time.Minute), dimension: queryLogRollupBlockedClient, value: client}]++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate blocked history: %w", err)
	}
	rollups := make([]queryLogRollup, 0, len(counts))
	for key, hits := range counts {
		rollups = append(rollups, queryLogRollup{queryLogRollupKey: key, hits: hits})
	}
	sort.Slice(rollups, func(left, right int) bool {
		if !rollups[left].bucket.Equal(rollups[right].bucket) {
			return rollups[left].bucket.Before(rollups[right].bucket)
		}
		return rollups[left].value < rollups[right].value
	})

	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin blocked client backfill: %w", err)
	}
	defer func() { _ = transaction.Rollback() }()
	for index := 0; index < len(rollups); index += queryLogRollupInsertRows {
		if err := store.replaceQueryLogRollups(ctx, transaction, rollups[index:min(index+queryLogRollupInsertRows, len(rollups))]); err != nil {
			return err
		}
	}
	if _, err := transaction.ExecContext(ctx,
		"UPDATE sable_metadata SET value = "+store.placeholder(1)+" WHERE key = "+store.placeholder(2),
		start.UTC().Format(time.RFC3339Nano), blockedClientRollupSinceKey,
	); err != nil {
		return fmt.Errorf("move %s: %w", blockedClientRollupSinceKey, err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit blocked client backfill: %w", err)
	}
	return nil
}
