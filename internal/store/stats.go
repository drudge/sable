package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// QueryStatsDelta holds the charted counters accumulated inside one bucket.
// Rows are deltas rather than cumulative counters so a restart, which zeroes
// the in-process counters, never rewrites history.
type QueryStatsDelta struct {
	Queries        uint64
	NoError        uint64
	ServerFailures uint64
	NXDomain       uint64
	Refused        uint64
	Blocked        uint64
	CacheHits      uint64
	CacheMisses    uint64
}

// QueryStatsBucket is a fixed-width slice of query activity. Start is the
// inclusive UTC start of the bucket.
type QueryStatsBucket struct {
	Start time.Time
	QueryStatsDelta
}

// QueryStatsTotals are lifetime counters kept independently of the buckets so
// retention pruning never lowers them.
type QueryStatsTotals struct {
	Queries              uint64
	NoError              uint64
	ServerFailures       uint64
	NXDomain             uint64
	Refused              uint64
	Blocked              uint64
	Failures             uint64
	UpstreamErrors       uint64
	CacheHits            uint64
	CacheMisses          uint64
	RoutedQueries        uint64
	LocalAnswers         uint64
	AuthoritativeAnswers uint64
	DNSSECSecure         uint64
	DNSSECInsecure       uint64
	DNSSECBogus          uint64
}

// Buckets are keyed by epoch seconds. Integer division buckets the rows on
// both SQLite and PostgreSQL without dialect-specific date functions.
const queryStatsColumns = "queries, no_error, server_failures, nx_domain, refused, blocked, cache_hits, cache_misses"

const queryStatsTotalColumns = queryStatsColumns + `, failures, upstream_errors, routed_queries, local_answers,
authoritative_answers, dnssec_secure, dnssec_insecure, dnssec_bogus`

func queryStatsTables() []string {
	return []string{`
CREATE TABLE IF NOT EXISTS sable_query_stats (
    bucket_start BIGINT PRIMARY KEY,
    queries BIGINT NOT NULL DEFAULT 0,
    no_error BIGINT NOT NULL DEFAULT 0,
    server_failures BIGINT NOT NULL DEFAULT 0,
    nx_domain BIGINT NOT NULL DEFAULT 0,
    refused BIGINT NOT NULL DEFAULT 0,
    blocked BIGINT NOT NULL DEFAULT 0,
    cache_hits BIGINT NOT NULL DEFAULT 0,
    cache_misses BIGINT NOT NULL DEFAULT 0
)`, `
CREATE TABLE IF NOT EXISTS sable_query_stats_totals (
    id INTEGER PRIMARY KEY,
    queries BIGINT NOT NULL DEFAULT 0,
    no_error BIGINT NOT NULL DEFAULT 0,
    server_failures BIGINT NOT NULL DEFAULT 0,
    nx_domain BIGINT NOT NULL DEFAULT 0,
    refused BIGINT NOT NULL DEFAULT 0,
    blocked BIGINT NOT NULL DEFAULT 0,
    failures BIGINT NOT NULL DEFAULT 0,
    upstream_errors BIGINT NOT NULL DEFAULT 0,
    cache_hits BIGINT NOT NULL DEFAULT 0,
    cache_misses BIGINT NOT NULL DEFAULT 0,
    routed_queries BIGINT NOT NULL DEFAULT 0,
    local_answers BIGINT NOT NULL DEFAULT 0,
    authoritative_answers BIGINT NOT NULL DEFAULT 0,
    dnssec_secure BIGINT NOT NULL DEFAULT 0,
    dnssec_insecure BIGINT NOT NULL DEFAULT 0,
    dnssec_bogus BIGINT NOT NULL DEFAULT 0
)`}
}

// RecordQueryStats adds bucket deltas and replaces the lifetime totals in one
// transaction. Buckets accumulate on conflict so a partially written bucket can
// be topped up later, and so clustered nodes sharing a database sum instead of
// overwriting each other.
func (store *Store) RecordQueryStats(ctx context.Context, buckets []QueryStatsBucket, totals QueryStatsTotals) error {
	if len(buckets) == 0 {
		return store.replaceQueryStatsTotals(ctx, totals)
	}
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin query statistics write: %w", err)
	}
	statement, err := transaction.PrepareContext(ctx, store.queryStatsInsert())
	if err != nil {
		_ = transaction.Rollback()
		return fmt.Errorf("prepare query statistics insert: %w", err)
	}
	defer statement.Close()
	for _, bucket := range buckets {
		if _, err := statement.ExecContext(
			ctx,
			bucket.Start.UTC().Unix(),
			bucket.Queries, bucket.NoError, bucket.ServerFailures, bucket.NXDomain,
			bucket.Refused, bucket.Blocked, bucket.CacheHits, bucket.CacheMisses,
		); err != nil {
			_ = transaction.Rollback()
			return fmt.Errorf("insert query statistics bucket: %w", err)
		}
	}
	if _, err := transaction.ExecContext(ctx, store.queryStatsTotalsUpsert(), queryStatsTotalValues(totals)...); err != nil {
		_ = transaction.Rollback()
		return fmt.Errorf("write query statistics totals: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit query statistics write: %w", err)
	}
	return nil
}

func (store *Store) replaceQueryStatsTotals(ctx context.Context, totals QueryStatsTotals) error {
	if _, err := store.database.ExecContext(ctx, store.queryStatsTotalsUpsert(), queryStatsTotalValues(totals)...); err != nil {
		return fmt.Errorf("write query statistics totals: %w", err)
	}
	return nil
}

func (store *Store) queryStatsInsert() string {
	return `INSERT INTO sable_query_stats (bucket_start, ` + queryStatsColumns + `)
VALUES (` + store.placeholders(9) + `)
ON CONFLICT (bucket_start) DO UPDATE SET
    queries = sable_query_stats.queries + excluded.queries,
    no_error = sable_query_stats.no_error + excluded.no_error,
    server_failures = sable_query_stats.server_failures + excluded.server_failures,
    nx_domain = sable_query_stats.nx_domain + excluded.nx_domain,
    refused = sable_query_stats.refused + excluded.refused,
    blocked = sable_query_stats.blocked + excluded.blocked,
    cache_hits = sable_query_stats.cache_hits + excluded.cache_hits,
    cache_misses = sable_query_stats.cache_misses + excluded.cache_misses`
}

func (store *Store) queryStatsTotalsUpsert() string {
	return `INSERT INTO sable_query_stats_totals (id, ` + queryStatsTotalColumns + `)
VALUES (` + store.placeholders(17) + `)
ON CONFLICT (id) DO UPDATE SET
    queries = excluded.queries,
    no_error = excluded.no_error,
    server_failures = excluded.server_failures,
    nx_domain = excluded.nx_domain,
    refused = excluded.refused,
    blocked = excluded.blocked,
    failures = excluded.failures,
    upstream_errors = excluded.upstream_errors,
    cache_hits = excluded.cache_hits,
    cache_misses = excluded.cache_misses,
    routed_queries = excluded.routed_queries,
    local_answers = excluded.local_answers,
    authoritative_answers = excluded.authoritative_answers,
    dnssec_secure = excluded.dnssec_secure,
    dnssec_insecure = excluded.dnssec_insecure,
    dnssec_bogus = excluded.dnssec_bogus`
}

func queryStatsTotalValues(totals QueryStatsTotals) []any {
	return []any{
		1,
		totals.Queries, totals.NoError, totals.ServerFailures, totals.NXDomain,
		totals.Refused, totals.Blocked, totals.CacheHits, totals.CacheMisses,
		totals.Failures, totals.UpstreamErrors, totals.RoutedQueries, totals.LocalAnswers,
		totals.AuthoritativeAnswers, totals.DNSSECSecure, totals.DNSSECInsecure, totals.DNSSECBogus,
	}
}

// QueryStats aggregates stored buckets into fixed slots of the requested width
// covering [start, end). Slots without stored activity are omitted; callers
// zero-fill so gaps stay visible.
func (store *Store) QueryStats(ctx context.Context, start, end time.Time, width time.Duration) ([]QueryStatsBucket, error) {
	if width <= 0 {
		return nil, errors.New("query statistics width must be positive")
	}
	if !start.Before(end) {
		return []QueryStatsBucket{}, nil
	}
	seconds := int64(width / time.Second)
	if seconds <= 0 {
		seconds = 1
	}
	// The width is bound twice because a positional placeholder cannot be
	// reused across two positions on PostgreSQL.
	slot := "(bucket_start / " + store.placeholder(1) + ") * " + store.placeholder(2)
	// PostgreSQL sums BIGINT columns as NUMERIC, which will not scan into a
	// uint64, so every sum is cast back to an integer.
	rows, err := store.database.QueryContext(ctx, `
SELECT `+slot+` AS slot,
       CAST(SUM(queries) AS BIGINT), CAST(SUM(no_error) AS BIGINT),
       CAST(SUM(server_failures) AS BIGINT), CAST(SUM(nx_domain) AS BIGINT),
       CAST(SUM(refused) AS BIGINT), CAST(SUM(blocked) AS BIGINT),
       CAST(SUM(cache_hits) AS BIGINT), CAST(SUM(cache_misses) AS BIGINT)
FROM sable_query_stats
WHERE bucket_start >= `+store.placeholder(3)+` AND bucket_start < `+store.placeholder(4)+`
GROUP BY slot
ORDER BY slot`, seconds, seconds, start.UTC().Unix(), end.UTC().Unix())
	if err != nil {
		return nil, fmt.Errorf("read query statistics: %w", err)
	}
	defer rows.Close()
	buckets := make([]QueryStatsBucket, 0, 160)
	for rows.Next() {
		var slotStart int64
		var bucket QueryStatsBucket
		if err := rows.Scan(
			&slotStart,
			&bucket.Queries, &bucket.NoError, &bucket.ServerFailures, &bucket.NXDomain,
			&bucket.Refused, &bucket.Blocked, &bucket.CacheHits, &bucket.CacheMisses,
		); err != nil {
			return nil, fmt.Errorf("scan query statistics: %w", err)
		}
		bucket.Start = time.Unix(slotStart, 0).UTC()
		buckets = append(buckets, bucket)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate query statistics: %w", err)
	}
	return buckets, nil
}

// QueryStatsTotals reads the lifetime counters, returning zeroes before the
// first write.
func (store *Store) QueryStatsTotals(ctx context.Context) (QueryStatsTotals, error) {
	var totals QueryStatsTotals
	err := store.database.QueryRowContext(ctx, `
SELECT `+queryStatsTotalColumns+`
FROM sable_query_stats_totals WHERE id = `+store.placeholder(1), 1).Scan(
		&totals.Queries, &totals.NoError, &totals.ServerFailures, &totals.NXDomain,
		&totals.Refused, &totals.Blocked, &totals.CacheHits, &totals.CacheMisses,
		&totals.Failures, &totals.UpstreamErrors, &totals.RoutedQueries, &totals.LocalAnswers,
		&totals.AuthoritativeAnswers, &totals.DNSSECSecure, &totals.DNSSECInsecure, &totals.DNSSECBogus,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return QueryStatsTotals{}, nil
	}
	if err != nil {
		return QueryStatsTotals{}, fmt.Errorf("read query statistics totals: %w", err)
	}
	return totals, nil
}

// PruneQueryStats drops buckets older than the retention window. Lifetime
// totals live in their own row and are unaffected.
func (store *Store) PruneQueryStats(ctx context.Context, before time.Time) error {
	if _, err := store.database.ExecContext(
		ctx,
		"DELETE FROM sable_query_stats WHERE bucket_start < "+store.placeholder(1),
		before.UTC().Unix(),
	); err != nil {
		return fmt.Errorf("prune query statistics: %w", err)
	}
	return nil
}
