package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Minute rollups make any window exact, but a month of them is millions of
// rows, and Insights and the dashboard total weeks at a time. Two coarser
// tiers hold the same counts summed by hour and by day. A background pass
// fills them from the minute rollups once each hour has settled, and reads
// take whole days and hours from them, leaving only a window's ragged edges
// to the minute rollups and the raw log.

// rollupTier is one coarser resolution of the query log rollups. Its buckets
// are sums of the finer table's buckets, keyed dimension first so a read of
// one dimension stays inside its own rows.
type rollupTier struct {
	table string
	size  time.Duration
	// source is the finer table the tier's buckets are summed from.
	source string
	// fromKey and untilKey bound the buckets the tier holds complete sums for.
	fromKey, untilKey string
}

const minuteRollupTable = "sable_query_log_rollup"

var (
	hourRollupTier = rollupTier{
		table: "sable_query_log_rollup_hour", size: time.Hour, source: minuteRollupTable,
		fromKey: "query_log_rollup_hour_from", untilKey: "query_log_rollup_hour_until",
	}
	dayRollupTier = rollupTier{
		table: "sable_query_log_rollup_day", size: 24 * time.Hour, source: "sable_query_log_rollup_hour",
		fromKey: "query_log_rollup_day_from", untilKey: "query_log_rollup_day_until",
	}
	// rollupTiers lists the tiers finest first, the order they are filled in:
	// days are summed from hours.
	rollupTiers = []rollupTier{hourRollupTier, dayRollupTier}
)

// queryLogRollupDimensions are every dimension the rollups carry.
var queryLogRollupDimensions = []string{
	queryLogRollupClient, queryLogRollupDomain, queryLogRollupBlocked, queryLogRollupBlockedClient,
	queryLogRollupBlockedSource, queryLogRollupBlockedSoleSource, queryLogRollupRecordType,
	queryLogRollupSource, queryLogRollupResponseCode,
}

const (
	// rollupSettle is how long after a bucket ends before it is summed, so
	// queries still being written land in its minutes first.
	rollupSettle = 10 * time.Minute
	// rollupCompactChunk bounds how much history one transaction sums, so the
	// query log writer never waits long behind the compactor.
	rollupCompactChunk = 6 * time.Hour
)

func rollupTierTables() []string {
	statements := make([]string, 0, len(rollupTiers))
	for _, tier := range rollupTiers {
		statements = append(statements, `
CREATE TABLE IF NOT EXISTS `+tier.table+` (
    dimension TEXT NOT NULL,
    bucket_start TIMESTAMP NOT NULL,
    value TEXT NOT NULL,
    hits BIGINT NOT NULL,
    PRIMARY KEY (dimension, bucket_start, value)
)`)
	}
	return statements
}

// tierCoverage is the span of buckets a tier holds complete sums for.
type tierCoverage struct {
	rollupTier
	from, until time.Time
}

func (store *Store) tierCoverage(ctx context.Context, tier rollupTier) (tierCoverage, bool, error) {
	from, foundFrom, err := store.rollupMarker(ctx, tier.fromKey)
	if err != nil {
		return tierCoverage{}, false, err
	}
	until, foundUntil, err := store.rollupMarker(ctx, tier.untilKey)
	if err != nil {
		return tierCoverage{}, false, err
	}
	coverage := tierCoverage{rollupTier: tier, from: from.UTC(), until: until.UTC()}
	return coverage, foundFrom && foundUntil, nil
}

// rollupSpan is one stretch of a window and the rollup table that counts it.
type rollupSpan struct {
	table      string
	start, end time.Time
}

// rollupSpans covers [start, end), which falls on whole minutes, with the
// coarsest complete rollups no wider than coarsest: whole days in the middle,
// whole hours around them, and minutes at the edges.
func (store *Store) rollupSpans(ctx context.Context, start, end time.Time, coarsest time.Duration) ([]rollupSpan, error) {
	if !start.Before(end) {
		return nil, nil
	}
	tiers := make([]tierCoverage, 0, len(rollupTiers))
	for index := len(rollupTiers) - 1; index >= 0; index-- {
		if rollupTiers[index].size > coarsest {
			continue
		}
		coverage, found, err := store.tierCoverage(ctx, rollupTiers[index])
		if err != nil {
			return nil, err
		}
		if found {
			tiers = append(tiers, coverage)
		}
	}
	return splitRollupSpans(start.UTC(), end.UTC(), tiers), nil
}

// splitRollupSpans takes the widest whole buckets of the first tier that fit
// inside both [start, end) and what the tier holds, then fills either side
// from the finer tiers and finally the minutes.
func splitRollupSpans(start, end time.Time, tiers []tierCoverage) []rollupSpan {
	if !start.Before(end) {
		return nil
	}
	for index, tier := range tiers {
		inner := rollupSpan{
			table: tier.table,
			start: ceilTime(maxTime(start, tier.from), tier.size),
			end:   minTime(end, tier.until).Truncate(tier.size),
		}
		if inner.start.Before(inner.end) {
			spans := splitRollupSpans(start, inner.start, tiers[index+1:])
			spans = append(spans, inner)
			return append(spans, splitRollupSpans(inner.end, end, tiers[index+1:])...)
		}
	}
	return []rollupSpan{{table: minuteRollupTable, start: start, end: end}}
}

// dimensionCondition matches the given dimensions. The coarser tiers lead
// their keys with the dimension, so naming them lets a read range over each.
func (store *Store) dimensionCondition(dimensions []string, bind func(any) string) string {
	placeholders := make([]string, 0, len(dimensions))
	for _, dimension := range dimensions {
		placeholders = append(placeholders, bind(dimension))
	}
	return "dimension IN (" + strings.Join(placeholders, ", ") + ")"
}

// CompactQueryLogRollups sums settled minute rollups into hours and settled
// hours into days. Each tier first catches up to the settled present, summing
// its newest bucket again to take in anything written late, then works back
// through older history until it reaches the oldest minute. It replaces each
// bucket it sums rather than adding to it, so it is safe to run at any time.
// It waits for blocked-client history to be counted, because hours summed
// before then would miss it.
func (store *Store) CompactQueryLogRollups(ctx context.Context, now time.Time) error {
	if _, done, err := store.rollupMarker(ctx, blockedClientBackfilledKey); err != nil || !done {
		return err
	}
	start, found, err := store.queryLogRollupStart(ctx)
	if err != nil || !found {
		return err
	}
	// The first rolled-up minute can hold rows written before rollups existed,
	// and reads count it from the raw log, so sums begin after it.
	sourceFrom, sourceUntil := start.Add(time.Minute), now.UTC().Add(-rollupSettle)
	for _, tier := range rollupTiers {
		coverage, err := store.compactTier(ctx, tier, sourceFrom, sourceUntil)
		if err != nil {
			return err
		}
		sourceFrom, sourceUntil = coverage.from, coverage.until
	}
	return nil
}

// compactTier sums the tier's whole buckets inside [sourceFrom, sourceUntil),
// the span its source holds complete, and reports what the tier then holds.
func (store *Store) compactTier(ctx context.Context, tier rollupTier, sourceFrom, sourceUntil time.Time) (tierCoverage, error) {
	first, last := ceilTime(sourceFrom.UTC(), tier.size), sourceUntil.UTC().Truncate(tier.size)
	coverage, found, err := store.tierCoverage(ctx, tier)
	if err != nil || !first.Before(last) {
		return tierCoverage{}, err
	}
	if !found || coverage.until.After(last) || coverage.from.Before(first) && !coverage.until.After(first) {
		// Nothing yet, or nothing that still lines up with the source: start
		// over from the present and work back.
		coverage.from, coverage.until = last, last
	}
	// Forward: the newest bucket again, then everything since.
	for begin := maxTime(first, maxTime(coverage.from, coverage.until.Add(-tier.size))); begin.Before(last); {
		end := minTime(last, begin.Add(max(rollupCompactChunk, tier.size)))
		if err := store.compactBuckets(ctx, tier, begin, end, minTime(coverage.from, begin), end); err != nil {
			return tierCoverage{}, err
		}
		coverage.from, coverage.until, begin = minTime(coverage.from, begin), end, end
	}
	// Backward: older history, newest first, so recent windows speed up first.
	for coverage.from.After(first) {
		if err := ctx.Err(); err != nil {
			return tierCoverage{}, err
		}
		begin := maxTime(first, coverage.from.Add(-max(rollupCompactChunk, tier.size)))
		if err := store.compactBuckets(ctx, tier, begin, coverage.from, begin, coverage.until); err != nil {
			return tierCoverage{}, err
		}
		coverage.from = begin
	}
	if coverage.from.Before(first) {
		// Older buckets were pruned along with the minutes they summed.
		coverage.from = first
	}
	return coverage, nil
}

// compactBuckets sums every bucket of the tier in [start, end) from its source
// and records that the tier then holds [from, until).
func (store *Store) compactBuckets(ctx context.Context, tier rollupTier, start, end, from, until time.Time) error {
	rollups := make([]queryLogRollup, 0)
	for bucket := start; bucket.Before(end); bucket = bucket.Add(tier.size) {
		summed, err := store.sumRollups(ctx, tier.source, bucket, bucket.Add(tier.size))
		if err != nil {
			return err
		}
		rollups = append(rollups, summed...)
	}
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin %s compaction: %w", tier.table, err)
	}
	defer func() { _ = transaction.Rollback() }()
	var arguments []any
	bind := func(value any) string {
		arguments = append(arguments, value)
		return store.placeholder(len(arguments))
	}
	statement := "DELETE FROM " + tier.table + " WHERE " + store.dimensionCondition(queryLogRollupDimensions, bind) +
		" AND bucket_start >= " + bind(start) + " AND bucket_start < " + bind(end)
	if _, err := transaction.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("clear %s: %w", tier.table, err)
	}
	for index := 0; index < len(rollups); index += queryLogRollupInsertRows {
		if err := store.insertTierRows(ctx, transaction, tier.table, rollups[index:min(index+queryLogRollupInsertRows, len(rollups))]); err != nil {
			return err
		}
	}
	for _, marker := range []struct {
		key    string
		moment time.Time
	}{{tier.fromKey, from}, {tier.untilKey, until}} {
		if _, err := transaction.ExecContext(ctx,
			"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholders(2)+") ON CONFLICT (key) DO UPDATE SET value = excluded.value",
			marker.key, marker.moment.UTC().Format(time.RFC3339Nano),
		); err != nil {
			return fmt.Errorf("record %s: %w", marker.key, err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit %s compaction: %w", tier.table, err)
	}
	return nil
}

// sumRollups totals one bucket's worth of a finer table by dimension and value.
func (store *Store) sumRollups(ctx context.Context, table string, start, end time.Time) ([]queryLogRollup, error) {
	var arguments []any
	bind := func(value any) string {
		arguments = append(arguments, value)
		return store.placeholder(len(arguments))
	}
	statement := "SELECT dimension, value, CAST(SUM(hits) AS BIGINT) FROM " + table +
		" WHERE " + store.dimensionCondition(queryLogRollupDimensions, bind) +
		" AND bucket_start >= " + bind(start) + " AND bucket_start < " + bind(end) +
		" GROUP BY dimension, value"
	rows, err := store.database.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("sum %s: %w", table, err)
	}
	defer rows.Close()
	summed := make([]queryLogRollup, 0)
	for rows.Next() {
		rollup := queryLogRollup{queryLogRollupKey: queryLogRollupKey{bucket: start}}
		if err := rows.Scan(&rollup.dimension, &rollup.value, &rollup.hits); err != nil {
			return nil, fmt.Errorf("scan %s sum: %w", table, err)
		}
		summed = append(summed, rollup)
	}
	return summed, rows.Err()
}

func (store *Store) insertTierRows(ctx context.Context, transaction interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, table string, rollups []queryLogRollup) error {
	if len(rollups) == 0 {
		return nil
	}
	arguments := make([]any, 0, len(rollups)*4)
	values := make([]string, 0, len(rollups))
	for _, rollup := range rollups {
		values = append(values, "("+store.placeholder(len(arguments)+1)+", "+store.placeholder(len(arguments)+2)+", "+
			store.placeholder(len(arguments)+3)+", "+store.placeholder(len(arguments)+4)+")")
		arguments = append(arguments, rollup.dimension, rollup.bucket, rollup.value, rollup.hits)
	}
	if _, err := transaction.ExecContext(ctx, "INSERT INTO "+table+" (dimension, bucket_start, value, hits) VALUES "+strings.Join(values, ", "), arguments...); err != nil {
		return fmt.Errorf("write %s: %w", table, err)
	}
	return nil
}

// pruneRollupTiers drops every coarser bucket that summed a pruned minute and
// moves each tier's start past them, so what survives of a bucket cut in two
// is counted from its remaining minutes.
func (store *Store) pruneRollupTiers(ctx context.Context, transaction *sql.Tx, through time.Time) error {
	for _, tier := range rollupTiers {
		var arguments []any
		bind := func(value any) string {
			arguments = append(arguments, value)
			return store.placeholder(len(arguments))
		}
		statement := "DELETE FROM " + tier.table + " WHERE " + store.dimensionCondition(queryLogRollupDimensions, bind) +
			" AND bucket_start <= " + bind(through)
		if _, err := transaction.ExecContext(ctx, statement, arguments...); err != nil {
			return fmt.Errorf("prune %s: %w", tier.table, err)
		}
		first := through.UTC().Truncate(tier.size).Add(tier.size)
		for _, key := range []string{tier.fromKey, tier.untilKey} {
			var raw string
			err := transaction.QueryRowContext(ctx, "SELECT value FROM sable_metadata WHERE key = "+store.placeholder(1), key).Scan(&raw)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return fmt.Errorf("read %s: %w", key, err)
			}
			if moment, err := time.Parse(time.RFC3339Nano, raw); err == nil && !moment.Before(first) {
				continue
			}
			if _, err := transaction.ExecContext(ctx, "UPDATE sable_metadata SET value = "+store.placeholder(1)+" WHERE key = "+store.placeholder(2),
				first.Format(time.RFC3339Nano), key); err != nil {
				return fmt.Errorf("move %s: %w", key, err)
			}
		}
	}
	return nil
}

func ceilTime(value time.Time, size time.Duration) time.Time {
	truncated := value.Truncate(size)
	if truncated.Equal(value) {
		return truncated
	}
	return truncated.Add(size)
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
