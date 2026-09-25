package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

const (
	// Repeated lookups need at least one an hour to show a schedule, and more
	// than a few thousand a day is a busy app rather than a check-in.
	minimumRepeatedLookups = 24
	maximumRepeatedLookups = 5_000
	// repeatedLookupCandidates bounds how many busy pairs are considered, and
	// maximumRepeatedLookupPairs how many have their times read.
	repeatedLookupCandidates   = 200
	maximumRepeatedLookupPairs = 40
)

// RepeatedLookups returns, for the client and name pairs looked up many times
// in [since, until) by exactly one client, every moment each lookup happened.
// A name only one device looks up again and again is where a scheduled
// check-in shows itself. It reads the window's raw rows twice: once to find
// the busiest pairs and which names only one client used, and once for the
// times of the pairs that qualify.
func (store *Store) RepeatedLookups(ctx context.Context, since, until time.Time) ([]querylog.LookupTimes, error) {
	// The distinct clients per name are counted over every row in the window,
	// then the busiest pairs are ranked, so the result is the same as asking
	// about each busy pair's name separately.
	rows, err := store.database.QueryContext(ctx, `
WITH pairs AS (
    SELECT client_ip_key, name_key, COUNT(*) AS hits
    FROM sable_query_log`+store.queryLogTimeIndex()+`
    WHERE occurred_at >= `+store.placeholder(1)+` AND occurred_at < `+store.placeholder(2)+`
    GROUP BY client_ip_key, name_key
), counted AS (
    SELECT client_ip_key, name_key, hits, COUNT(*) OVER (PARTITION BY name_key) AS clients
    FROM pairs
), busiest AS (
    SELECT client_ip_key, name_key, hits, clients
    FROM counted
    WHERE client_ip_key <> '' AND hits >= `+store.placeholder(3)+` AND hits <= `+store.placeholder(4)+`
    ORDER BY hits DESC, client_ip_key ASC, name_key ASC
    LIMIT `+store.placeholder(5)+`
)
SELECT client_ip_key, name_key FROM busiest
WHERE clients = 1
ORDER BY hits DESC, client_ip_key ASC, name_key ASC
LIMIT `+store.placeholder(6),
		since.UTC(), until.UTC(), minimumRepeatedLookups, maximumRepeatedLookups, repeatedLookupCandidates, maximumRepeatedLookupPairs)
	if err != nil {
		return nil, fmt.Errorf("find repeated lookups: %w", err)
	}
	lookups := make([]querylog.LookupTimes, 0)
	// A private name has exactly one client in the window, so every row for it
	// there belongs to its pair.
	byName := make(map[string]int)
	for rows.Next() {
		var lookup querylog.LookupTimes
		if err := rows.Scan(&lookup.Client, &lookup.Name); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan repeated lookup: %w", err)
		}
		byName[lookup.Name] = len(lookups)
		lookups = append(lookups, lookup)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(lookups) == 0 {
		return nil, err
	}

	arguments := []any{since.UTC(), until.UTC()}
	placeholders := make([]string, 0, len(lookups))
	for _, lookup := range lookups {
		arguments = append(arguments, lookup.Name)
		placeholders = append(placeholders, store.placeholder(len(arguments)))
	}
	rows, err = store.database.QueryContext(ctx, `
SELECT name_key, occurred_at FROM sable_query_log`+store.queryLogTimeIndex()+`
WHERE occurred_at >= `+store.placeholder(1)+` AND occurred_at < `+store.placeholder(2)+`
  AND name_key IN (`+strings.Join(placeholders, ", ")+`)
ORDER BY occurred_at`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("read lookup times: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var moment any
		if err := rows.Scan(&name, &moment); err != nil {
			return nil, fmt.Errorf("scan lookup time: %w", err)
		}
		parsed, err := databaseTime(moment)
		if err != nil {
			return nil, fmt.Errorf("read lookup time: %w", err)
		}
		if index, found := byName[name]; found {
			lookups[index].Times = append(lookups[index].Times, parsed.UTC())
		}
	}
	return lookups, rows.Err()
}

// queryLogTimeIndex steers SQLite to the time index for reads bounded to a
// short window. Without table statistics it prefers the name or client index
// for any equality, and those walk that name's or client's whole history.
// PostgreSQL keeps statistics and chooses well on its own.
func (store *Store) queryLogTimeIndex() string {
	if store.driver == "postgres" {
		return ""
	}
	return " INDEXED BY sable_query_log_occurred_at_idx"
}
