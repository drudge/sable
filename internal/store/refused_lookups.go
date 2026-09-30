package store

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

// maximumRefusedLookups bounds one RefusedLookups read. A server open to the
// internet can be refused thousands of times a day by scanners; the newest
// rows are enough to find the local devices among them.
const maximumRefusedLookups = 20_000

// RefusedLookups lists the lookups the recursion policy refused since a
// moment, newest first.
func (store *Store) RefusedLookups(ctx context.Context, since time.Time) ([]querylog.RefusedLookup, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT client_ip, name, occurred_at
FROM sable_query_log`+store.queryLogTimeIndex()+`
WHERE occurred_at >= `+store.placeholder(1)+` AND response_code = `+store.placeholder(2)+`
  AND decision LIKE `+store.placeholder(3)+`
ORDER BY occurred_at DESC
LIMIT `+store.placeholder(4),
		since.UTC(), dns.RcodeRefused, `%"resolver":"`+string(querylog.ResolverNotAllowed)+`"%`, maximumRefusedLookups)
	if err != nil {
		return nil, fmt.Errorf("read refused lookups: %w", err)
	}
	defer rows.Close()
	refused := make([]querylog.RefusedLookup, 0)
	for rows.Next() {
		var lookup querylog.RefusedLookup
		var at any
		if err := rows.Scan(&lookup.Client, &lookup.Name, &at); err != nil {
			return nil, fmt.Errorf("scan refused lookup: %w", err)
		}
		if lookup.At, err = databaseTime(at); err != nil {
			return nil, fmt.Errorf("read refused lookup time: %w", err)
		}
		refused = append(refused, lookup)
	}
	return refused, rows.Err()
}
