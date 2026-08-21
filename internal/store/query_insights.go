package store

import (
	"context"
	"database/sql"
	"fmt"
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
const queryLogDomainExpression = "RTRIM(LOWER(name), '.')"

func queryLogDomainKey(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// QueryLogInsights counts the query log over a window. The dashboard used to
// rank a fixed sample of the newest rows, which told an operator nothing about
// the range they had selected and never matched the totals the query log page
// reported for the same client. Counting in the database instead means the
// rankings describe exactly the window on screen.
func (store *Store) QueryLogInsights(ctx context.Context, since, until time.Time) (querylog.Insights, error) {
	insights := querylog.Insights{
		Clients:       map[string]uint64{},
		Domains:       map[string]uint64{},
		Blocked:       map[string]uint64{},
		RecordTypes:   map[uint16]uint64{},
		Sources:       map[string]uint64{},
		ResponseCodes: map[int]uint64{},
	}
	window, arguments := store.queryLogWindow(since, until)

	if err := store.rankQueryLog(ctx, "client_ip", window, arguments, func(key string, count uint64) {
		insights.Clients[key] = count
	}); err != nil {
		return querylog.Insights{}, err
	}
	if err := store.rankQueryLog(ctx, queryLogDomainExpression, window, arguments, func(key string, count uint64) {
		insights.Domains[key] = count
	}); err != nil {
		return querylog.Insights{}, err
	}

	blockedWindow, blockedArguments := window, arguments
	blockedArguments = append(append([]any(nil), blockedArguments...), string(querylog.SourceBlocked))
	blockedWindow = joinConditions(blockedWindow, "source = "+store.placeholder(len(blockedArguments)))
	if err := store.rankQueryLog(ctx, queryLogDomainExpression, blockedWindow, blockedArguments, func(key string, count uint64) {
		insights.Blocked[key] = count
	}); err != nil {
		return querylog.Insights{}, err
	}

	// The distributions plot every bucket rather than a leaderboard, and the
	// three columns they read are low cardinality, so they are grouped whole.
	if err := store.tallyQueryLog(ctx, "record_type", window, arguments, func(value any, count uint64) error {
		recordType, err := scanUint16(value)
		if err != nil {
			return err
		}
		insights.RecordTypes[recordType] = count
		return nil
	}); err != nil {
		return querylog.Insights{}, err
	}
	if err := store.tallyQueryLog(ctx, "source", window, arguments, func(value any, count uint64) error {
		insights.Sources[asString(value)] = count
		return nil
	}); err != nil {
		return querylog.Insights{}, err
	}
	if err := store.tallyQueryLog(ctx, "response_code", window, arguments, func(value any, count uint64) error {
		responseCode, err := scanUint16(value)
		if err != nil {
			return err
		}
		insights.ResponseCodes[int(responseCode)] = count
		return nil
	}); err != nil {
		return querylog.Insights{}, err
	}
	return insights, nil
}

func (store *Store) queryLogWindow(since, until time.Time) (string, []any) {
	conditions := make([]string, 0, 2)
	arguments := make([]any, 0, 2)
	if !since.IsZero() {
		arguments = append(arguments, since.UTC())
		conditions = append(conditions, "occurred_at >= "+store.placeholder(len(arguments)))
	}
	if !until.IsZero() {
		arguments = append(arguments, until.UTC())
		conditions = append(conditions, "occurred_at <= "+store.placeholder(len(arguments)))
	}
	if len(conditions) == 0 {
		return "", arguments
	}
	return " WHERE " + strings.Join(conditions, " AND "), arguments
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
