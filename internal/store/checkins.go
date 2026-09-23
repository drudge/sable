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
// check-in shows itself. It reads the raw query log in three bounded steps.
func (store *Store) RepeatedLookups(ctx context.Context, since, until time.Time) ([]querylog.LookupTimes, error) {
	type pair struct{ client, name string }
	rows, err := store.database.QueryContext(ctx, `
SELECT client_ip_key, name_key, COUNT(*) AS hits
FROM sable_query_log
WHERE occurred_at >= `+store.placeholder(1)+` AND occurred_at < `+store.placeholder(2)+` AND client_ip_key <> ''
GROUP BY client_ip_key, name_key
HAVING COUNT(*) >= `+store.placeholder(3)+` AND COUNT(*) <= `+store.placeholder(4)+`
ORDER BY hits DESC
LIMIT `+store.placeholder(5), since.UTC(), until.UTC(), minimumRepeatedLookups, maximumRepeatedLookups, repeatedLookupCandidates)
	if err != nil {
		return nil, fmt.Errorf("find repeated lookups: %w", err)
	}
	candidates := make([]pair, 0)
	names := make(map[string]bool)
	for rows.Next() {
		var candidate pair
		var hits uint64
		if err := rows.Scan(&candidate.client, &candidate.name, &hits); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan repeated lookup: %w", err)
		}
		candidates = append(candidates, candidate)
		names[candidate.name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(candidates) == 0 {
		return nil, err
	}

	// Keep the names exactly one client looked up.
	arguments := []any{since.UTC(), until.UTC()}
	placeholders := make([]string, 0, len(names))
	for name := range names {
		arguments = append(arguments, name)
		placeholders = append(placeholders, store.placeholder(len(arguments)))
	}
	rows, err = store.database.QueryContext(ctx, `
SELECT name_key FROM sable_query_log
WHERE occurred_at >= `+store.placeholder(1)+` AND occurred_at < `+store.placeholder(2)+` AND name_key IN (`+strings.Join(placeholders, ", ")+`)
GROUP BY name_key
HAVING COUNT(DISTINCT client_ip_key) = 1`, arguments...)
	if err != nil {
		return nil, fmt.Errorf("count repeated lookup clients: %w", err)
	}
	private := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan repeated lookup name: %w", err)
		}
		private[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	lookups := make([]querylog.LookupTimes, 0)
	for _, candidate := range candidates {
		if !private[candidate.name] || len(lookups) == maximumRepeatedLookupPairs {
			continue
		}
		times, err := store.lookupTimes(ctx, candidate.client, candidate.name, since, until)
		if err != nil {
			return nil, err
		}
		lookups = append(lookups, querylog.LookupTimes{Client: candidate.client, Name: candidate.name, Times: times})
	}
	return lookups, nil
}

func (store *Store) lookupTimes(ctx context.Context, client, name string, since, until time.Time) ([]time.Time, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT occurred_at FROM sable_query_log
WHERE client_ip_key = `+store.placeholder(1)+` AND name_key = `+store.placeholder(2)+`
  AND occurred_at >= `+store.placeholder(3)+` AND occurred_at < `+store.placeholder(4)+`
ORDER BY occurred_at`, client, name, since.UTC(), until.UTC())
	if err != nil {
		return nil, fmt.Errorf("read lookup times: %w", err)
	}
	defer rows.Close()
	times := make([]time.Time, 0)
	for rows.Next() {
		var moment any
		if err := rows.Scan(&moment); err != nil {
			return nil, fmt.Errorf("scan lookup time: %w", err)
		}
		parsed, err := databaseTime(moment)
		if err != nil {
			return nil, fmt.Errorf("read lookup time: %w", err)
		}
		times = append(times, parsed.UTC())
	}
	return times, rows.Err()
}
