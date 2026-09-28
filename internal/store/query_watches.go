package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/drudge/sable/internal/querylog"
)

// LatestQueryID returns the ID of the newest query log row, or 0 when there
// is none. Reading from it on sees only what is logged afterward.
func (store *Store) LatestQueryID(ctx context.Context) (int64, error) {
	var latest int64
	if err := store.database.QueryRowContext(ctx, "SELECT COALESCE(MAX(id), 0) FROM sable_query_log").Scan(&latest); err != nil {
		return 0, fmt.Errorf("read the newest query log row: %w", err)
	}
	return latest, nil
}

// WatchedLookups returns up to limit queries logged after the row with ID
// after for any of domains or a name under one, oldest first, and the ID to
// read after next time. It reads only rows past after by their primary key,
// so a minute's reading costs a minute's rows however long the log is kept.
func (store *Store) WatchedLookups(ctx context.Context, after int64, domains []string, limit int) ([]querylog.WatchedLookup, int64, error) {
	latest, err := store.LatestQueryID(ctx)
	if err != nil || latest <= after || len(domains) == 0 || limit < 1 {
		return nil, max(latest, after), err
	}
	arguments := []any{after, latest}
	exact := make([]string, 0, len(domains))
	conditions := make([]string, 0, len(domains)+1)
	for _, domain := range domains {
		arguments = append(arguments, strings.ToLower(domain))
		exact = append(exact, store.placeholder(len(arguments)))
	}
	conditions = append(conditions, "name_key IN ("+strings.Join(exact, ", ")+")")
	for _, domain := range domains {
		arguments = append(arguments, "%."+strings.ToLower(domain))
		conditions = append(conditions, "name_key LIKE "+store.placeholder(len(arguments)))
	}
	arguments = append(arguments, limit)
	rows, err := store.database.QueryContext(ctx, `
SELECT id, occurred_at, client_ip, name_key, source FROM sable_query_log
WHERE id > `+store.placeholder(1)+` AND id <= `+store.placeholder(2)+` AND (`+strings.Join(conditions, " OR ")+`)
ORDER BY id
LIMIT `+store.placeholder(len(arguments)), arguments...)
	if err != nil {
		return nil, after, fmt.Errorf("read watched lookups: %w", err)
	}
	defer rows.Close()
	lookups := make([]querylog.WatchedLookup, 0)
	for rows.Next() {
		var lookup querylog.WatchedLookup
		var source string
		if err := rows.Scan(&lookup.ID, &lookup.OccurredAt, &lookup.ClientIP, &lookup.Name, &source); err != nil {
			return nil, after, fmt.Errorf("scan watched lookup: %w", err)
		}
		lookup.Blocked = querylog.Source(source) == querylog.SourceBlocked
		lookups = append(lookups, lookup)
	}
	if err := rows.Err(); err != nil {
		return nil, after, fmt.Errorf("iterate watched lookups: %w", err)
	}
	// A full page leaves the rest for next time, which starts where it ended.
	if len(lookups) == limit {
		return lookups, lookups[len(lookups)-1].ID, nil
	}
	return lookups, latest, nil
}
