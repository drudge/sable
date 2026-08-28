package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// maximumInsightRanks is how many entries each ranking keeps. The dashboard
// dialog offers a top thousand, so anything past that would be counted and
// then thrown away.
const maximumInsightRanks = 1_000

// queryLogDomainExpression folds a logged name into the key the rankings and
// the query log filter both use. Names arrive fully qualified and in whatever
// case the client sent, so "Example.COM." and "example.com" have to land on
// one row rather than three.
const queryLogDomainExpression = "name_key"

func queryLogDomainKey(name string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".")
}

// QueryLogInsights counts the query log over a window. The dashboard used to
// rank a fixed sample of the newest rows, which told an operator nothing about
// the range they had selected and never matched the totals the query log page
// reported for the same client. Counting in the database instead means the
// rankings describe exactly the window on screen.
func (store *Store) QueryLogInsights(ctx context.Context, since, until time.Time) (querylog.Insights, error) {
	insights := emptyQueryLogInsights()
	rollupStart, found, err := store.queryLogRollupStart(ctx)
	if err != nil {
		return querylog.Insights{}, err
	}
	if !found || since.IsZero() || until.IsZero() || !since.Before(until) {
		if err := store.queryRawLogInsights(ctx, since, until, true, &insights); err != nil {
			return querylog.Insights{}, err
		}
		return insights, nil
	}

	// The first rolled-up minute may also contain rows written before an
	// existing database was upgraded. Read that boundary minute from the raw
	// log so those legacy rows and the first new rows are each counted once.
	fullStart := ceilMinute(maxTime(since.UTC(), rollupStart.Add(time.Minute)))
	fullEnd := until.UTC().Truncate(time.Minute)
	if !fullStart.Before(fullEnd) {
		if err := store.queryRawLogInsights(ctx, since, until, true, &insights); err != nil {
			return querylog.Insights{}, err
		}
		return insights, nil
	}
	if err := store.queryMixedLogInsights(ctx, since, fullStart, fullEnd, until, &insights); err != nil {
		return querylog.Insights{}, err
	}
	return insights, nil
}

func emptyQueryLogInsights() querylog.Insights {
	return querylog.Insights{
		Clients:       map[string]uint64{},
		Domains:       map[string]uint64{},
		Blocked:       map[string]uint64{},
		RecordTypes:   map[uint16]uint64{},
		Sources:       map[string]uint64{},
		ResponseCodes: map[int]uint64{},
	}
}

func (store *Store) queryRawLogInsights(
	ctx context.Context,
	since, until time.Time,
	includeUntil bool,
	insights *querylog.Insights,
) error {
	window, arguments := store.queryLogWindow(since, until, includeUntil)

	if err := store.rankQueryLog(ctx, "client_ip_key", window, arguments, func(key string, count uint64) {
		insights.Clients[key] += count
	}); err != nil {
		return err
	}
	if err := store.rankQueryLog(ctx, queryLogDomainExpression, window, arguments, func(key string, count uint64) {
		insights.Domains[key] += count
	}); err != nil {
		return err
	}

	blockedWindow, blockedArguments := window, arguments
	blockedArguments = append(append([]any(nil), blockedArguments...), string(querylog.SourceBlocked))
	blockedWindow = joinConditions(blockedWindow, "source = "+store.placeholder(len(blockedArguments)))
	if err := store.rankQueryLog(ctx, queryLogDomainExpression, blockedWindow, blockedArguments, func(key string, count uint64) {
		insights.Blocked[key] += count
	}); err != nil {
		return err
	}

	// The distributions plot every bucket rather than a leaderboard, and the
	// three columns they read are low cardinality, so they are grouped whole.
	if err := store.tallyQueryLog(ctx, "record_type", window, arguments, func(value any, count uint64) error {
		recordType, err := scanUint16(value)
		if err != nil {
			return err
		}
		insights.RecordTypes[recordType] += count
		return nil
	}); err != nil {
		return err
	}
	if err := store.tallyQueryLog(ctx, "source", window, arguments, func(value any, count uint64) error {
		insights.Sources[asString(value)] += count
		return nil
	}); err != nil {
		return err
	}
	if err := store.tallyQueryLog(ctx, "response_code", window, arguments, func(value any, count uint64) error {
		responseCode, err := scanUint16(value)
		if err != nil {
			return err
		}
		insights.ResponseCodes[int(responseCode)] += count
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (store *Store) queryLogWindow(since, until time.Time, includeUntil bool) (string, []any) {
	conditions := make([]string, 0, 2)
	arguments := make([]any, 0, 2)
	if !since.IsZero() {
		arguments = append(arguments, since.UTC())
		conditions = append(conditions, "occurred_at >= "+store.placeholder(len(arguments)))
	}
	if !until.IsZero() {
		arguments = append(arguments, until.UTC())
		operator := "<"
		if includeUntil {
			operator = "<="
		}
		conditions = append(conditions, "occurred_at "+operator+" "+store.placeholder(len(arguments)))
	}
	if len(conditions) == 0 {
		return "", arguments
	}
	return " WHERE " + strings.Join(conditions, " AND "), arguments
}

func (store *Store) queryLogRollupStart(ctx context.Context) (time.Time, bool, error) {
	var raw any
	if err := store.database.QueryRowContext(ctx, "SELECT MIN(bucket_start) FROM sable_query_log_rollup").Scan(&raw); err != nil {
		return time.Time{}, false, fmt.Errorf("read query log rollup coverage: %w", err)
	}
	if raw == nil {
		return time.Time{}, false, nil
	}
	start, err := databaseTime(raw)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("read query log rollup coverage: %w", err)
	}
	return start.UTC(), true, nil
}

func databaseTime(value any) (time.Time, error) {
	if moment, ok := value.(time.Time); ok {
		return moment, nil
	}
	raw, ok := value.(string)
	if !ok {
		return time.Time{}, fmt.Errorf("unexpected timestamp type %T", value)
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05",
	} {
		if moment, err := time.Parse(layout, raw); err == nil {
			return moment, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp %q", raw)
}

func (store *Store) queryMixedLogInsights(
	ctx context.Context,
	since, fullStart, fullEnd, until time.Time,
	insights *querylog.Insights,
) error {
	arguments := []any{
		since.UTC(), fullStart.UTC(), fullEnd.UTC(), until.UTC(),
		fullStart.UTC(), fullEnd.UTC(), string(querylog.SourceBlocked), maximumInsightRanks,
	}
	rows, err := store.database.QueryContext(ctx, `
WITH boundary AS (
    SELECT client_ip_key, name_key, record_type, source, response_code
    FROM sable_query_log
    WHERE (occurred_at >= `+store.placeholder(1)+` AND occurred_at < `+store.placeholder(2)+`)
       OR (occurred_at >= `+store.placeholder(3)+` AND occurred_at <= `+store.placeholder(4)+`)
), combined (dimension, value, hits) AS (
    SELECT dimension, value, hits
    FROM sable_query_log_rollup
    WHERE bucket_start >= `+store.placeholder(5)+` AND bucket_start < `+store.placeholder(6)+`
    UNION ALL
    SELECT '`+queryLogRollupClient+`', client_ip_key, COUNT(*) FROM boundary GROUP BY client_ip_key
    UNION ALL
    SELECT '`+queryLogRollupDomain+`', name_key, COUNT(*) FROM boundary GROUP BY name_key
    UNION ALL
    SELECT '`+queryLogRollupBlocked+`', name_key, COUNT(*) FROM boundary
        WHERE source = `+store.placeholder(7)+` GROUP BY name_key
    UNION ALL
    SELECT '`+queryLogRollupRecordType+`', CAST(record_type AS TEXT), COUNT(*) FROM boundary GROUP BY record_type
    UNION ALL
    SELECT '`+queryLogRollupSource+`', source, COUNT(*) FROM boundary GROUP BY source
    UNION ALL
    SELECT '`+queryLogRollupResponseCode+`', CAST(response_code AS TEXT), COUNT(*) FROM boundary GROUP BY response_code
), totals AS (
    -- PostgreSQL promotes SUM(BIGINT) to NUMERIC, so cast it back to the
    -- bounded integer type used by both supported drivers.
    SELECT dimension, value, CAST(SUM(hits) AS BIGINT) AS hits
    FROM combined
    GROUP BY dimension, value
), ranked AS (
    SELECT dimension, value, hits,
           ROW_NUMBER() OVER (PARTITION BY dimension ORDER BY hits DESC, value ASC) AS position
    FROM totals
)
SELECT dimension, value, hits
FROM ranked
WHERE position <= `+store.placeholder(8), arguments...)
	if err != nil {
		return fmt.Errorf("read query log rollups: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var dimension, value string
		var hits uint64
		if err := rows.Scan(&dimension, &value, &hits); err != nil {
			return fmt.Errorf("scan query log rollup: %w", err)
		}
		if err := addQueryLogInsight(insights, dimension, value, hits); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate query log rollups: %w", err)
	}
	return nil
}

func addQueryLogInsight(insights *querylog.Insights, dimension, value string, hits uint64) error {
	switch dimension {
	case queryLogRollupClient:
		insights.Clients[value] += hits
	case queryLogRollupDomain:
		insights.Domains[value] += hits
	case queryLogRollupBlocked:
		insights.Blocked[value] += hits
	case queryLogRollupRecordType:
		number, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("parse query log record type %q: %w", value, err)
		}
		insights.RecordTypes[uint16(number)] += hits
	case queryLogRollupSource:
		insights.Sources[value] += hits
	case queryLogRollupResponseCode:
		number, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse query log response code %q: %w", value, err)
		}
		insights.ResponseCodes[number] += hits
	}
	return nil
}

func ceilMinute(value time.Time) time.Time {
	truncated := value.Truncate(time.Minute)
	if truncated.Equal(value) {
		return truncated
	}
	return truncated.Add(time.Minute)
}

func maxTime(left, right time.Time) time.Time {
	if left.After(right) {
		return left
	}
	return right
}

func joinConditions(where, condition string) string {
	if where == "" {
		return " WHERE " + condition
	}
	return where + " AND " + condition
}

// rankQueryLog returns the busiest values of one column, highest count first.
func (store *Store) rankQueryLog(ctx context.Context, column, where string, arguments []any, collect func(string, uint64)) error {
	rows, err := store.database.QueryContext(ctx, `
SELECT `+column+` AS bucket, COUNT(*) AS hits
FROM sable_query_log`+where+`
GROUP BY bucket
ORDER BY hits DESC, bucket ASC
LIMIT `+store.placeholder(len(arguments)+1), append(append([]any(nil), arguments...), maximumInsightRanks)...)
	if err != nil {
		return fmt.Errorf("rank query log by %s: %w", column, err)
	}
	defer rows.Close()
	for rows.Next() {
		var bucket sql.NullString
		var hits uint64
		if err := rows.Scan(&bucket, &hits); err != nil {
			return fmt.Errorf("scan query log ranking: %w", err)
		}
		collect(bucket.String, hits)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate query log ranking: %w", err)
	}
	return nil
}

// tallyQueryLog counts every distinct value of one column.
func (store *Store) tallyQueryLog(ctx context.Context, column, where string, arguments []any, collect func(any, uint64) error) error {
	rows, err := store.database.QueryContext(ctx, `
SELECT `+column+` AS bucket, COUNT(*) AS hits
FROM sable_query_log`+where+`
GROUP BY bucket`, arguments...)
	if err != nil {
		return fmt.Errorf("tally query log by %s: %w", column, err)
	}
	defer rows.Close()
	for rows.Next() {
		var bucket any
		var hits uint64
		if err := rows.Scan(&bucket, &hits); err != nil {
			return fmt.Errorf("scan query log tally: %w", err)
		}
		if err := collect(bucket, hits); err != nil {
			return fmt.Errorf("collect query log tally for %s: %w", column, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate query log tally: %w", err)
	}
	return nil
}

// scanUint16 normalizes the numeric column types the two drivers hand back.
func scanUint16(value any) (uint16, error) {
	switch typed := value.(type) {
	case int64:
		return uint16(typed), nil
	case int32:
		return uint16(typed), nil
	case int16:
		return uint16(typed), nil
	case int:
		return uint16(typed), nil
	case nil:
		return 0, nil
	default:
		return 0, fmt.Errorf("unexpected numeric column type %T", value)
	}
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}
