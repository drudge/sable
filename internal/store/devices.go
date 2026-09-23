package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// clientSeenSinceKey records when this database began tracking when clients
// and client-domain pairs were first seen. A client first seen at that moment
// may simply predate the tracking.
const clientSeenSinceKey = "query_log_client_seen_since"

const (
	clientSightingInsertRows = 128
	// maximumClientActivity bounds how many clients one report ranks.
	maximumClientActivity = 1_000
	// deviceBaselineDays is the history a client's recent traffic is compared
	// against.
	deviceBaselineDays = 7
)

func clientSightingTables() []string {
	return []string{`
CREATE TABLE IF NOT EXISTS sable_client_seen (
    client_key TEXT PRIMARY KEY,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL
)`, `
CREATE TABLE IF NOT EXISTS sable_client_domain_seen (
    client_key TEXT NOT NULL,
    name_key TEXT NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    PRIMARY KEY (client_key, name_key)
)`, `
CREATE INDEX IF NOT EXISTS sable_client_domain_seen_first_idx
ON sable_client_domain_seen (first_seen)`, `
CREATE TABLE IF NOT EXISTS sable_client_identity (
    address TEXT NOT NULL,
    mac TEXT NOT NULL,
    source TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    PRIMARY KEY (address, mac, source)
)`}
}

type sightingSpan struct{ first, last time.Time }

func (span *sightingSpan) include(moment time.Time) {
	if span.first.IsZero() || moment.Before(span.first) {
		span.first = moment
	}
	if moment.After(span.last) {
		span.last = moment
	}
}

type clientDomainKey struct{ client, name string }

// writeClientSightings extends the first- and last-seen spans of every client
// and client-domain pair in a batch. It runs in the query log writer's
// transaction, never on the DNS request path.
func (store *Store) writeClientSightings(ctx context.Context, transaction *sql.Tx, events []querylog.Event) error {
	clients := make(map[string]*sightingSpan)
	pairs := make(map[clientDomainKey]*sightingSpan)
	for _, event := range events {
		moment := event.OccurredAt.UTC().Truncate(time.Second)
		client := queryLogClientKey(event.ClientIP)
		if client == "" {
			continue
		}
		if clients[client] == nil {
			clients[client] = &sightingSpan{}
		}
		clients[client].include(moment)
		key := clientDomainKey{client: client, name: queryLogDomainKey(event.Name)}
		if pairs[key] == nil {
			pairs[key] = &sightingSpan{}
		}
		pairs[key].include(moment)
	}

	clientKeys := make([]string, 0, len(clients))
	for client := range clients {
		clientKeys = append(clientKeys, client)
	}
	sort.Strings(clientKeys)
	for start := 0; start < len(clientKeys); start += clientSightingInsertRows {
		chunk := clientKeys[start:min(start+clientSightingInsertRows, len(clientKeys))]
		rows := make([][]any, 0, len(chunk))
		for _, client := range chunk {
			rows = append(rows, []any{client, clients[client].first, clients[client].last})
		}
		if err := store.upsertSightings(ctx, transaction, "sable_client_seen", []string{"client_key"}, rows); err != nil {
			return err
		}
	}

	pairKeys := make([]clientDomainKey, 0, len(pairs))
	for key := range pairs {
		pairKeys = append(pairKeys, key)
	}
	sort.Slice(pairKeys, func(left, right int) bool {
		if pairKeys[left].client != pairKeys[right].client {
			return pairKeys[left].client < pairKeys[right].client
		}
		return pairKeys[left].name < pairKeys[right].name
	})
	for start := 0; start < len(pairKeys); start += clientSightingInsertRows {
		chunk := pairKeys[start:min(start+clientSightingInsertRows, len(pairKeys))]
		rows := make([][]any, 0, len(chunk))
		for _, key := range chunk {
			rows = append(rows, []any{key.client, key.name, pairs[key].first, pairs[key].last})
		}
		if err := store.upsertSightings(ctx, transaction, "sable_client_domain_seen", []string{"client_key", "name_key"}, rows); err != nil {
			return err
		}
	}
	return nil
}

// upsertSightings inserts rows whose last two columns are first_seen and
// last_seen, widening the stored span on conflict. The comparison is written
// with CASE because SQLite and PostgreSQL name their two-argument minimum and
// maximum functions differently.
func (store *Store) upsertSightings(ctx context.Context, executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, table string, keys []string, rows [][]any) error {
	if len(rows) == 0 {
		return nil
	}
	return store.upsertSpans(ctx, executor, table, keys, nil, rows)
}

// upsertSpans is upsertSightings with extra value columns between the keys and
// the span, which keep the values from whichever sighting is newest.
func (store *Store) upsertSpans(ctx context.Context, executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, table string, keys, values []string, rows [][]any) error {
	columns := append(append(append([]string(nil), keys...), values...), "first_seen", "last_seen")
	arguments := make([]any, 0, len(rows)*len(columns))
	tuples := make([]string, 0, len(rows))
	for _, row := range rows {
		placeholders := make([]string, len(row))
		for index := range row {
			placeholders[index] = store.placeholder(len(arguments) + index + 1)
		}
		arguments = append(arguments, row...)
		tuples = append(tuples, "("+strings.Join(placeholders, ", ")+")")
	}
	updates := make([]string, 0, len(values)+2)
	for _, column := range values {
		updates = append(updates, column+" = CASE WHEN excluded.last_seen >= "+table+".last_seen THEN excluded."+column+" ELSE "+table+"."+column+" END")
	}
	updates = append(updates,
		"first_seen = CASE WHEN excluded.first_seen < "+table+".first_seen THEN excluded.first_seen ELSE "+table+".first_seen END",
		"last_seen = CASE WHEN excluded.last_seen > "+table+".last_seen THEN excluded.last_seen ELSE "+table+".last_seen END",
	)
	statement := "INSERT INTO " + table + " (" + strings.Join(columns, ", ") + ") VALUES " + strings.Join(tuples, ", ") +
		" ON CONFLICT (" + strings.Join(keys, ", ") + ") DO UPDATE SET " + strings.Join(updates, ", ")
	if _, err := executor.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("upsert %s: %w", table, err)
	}
	return nil
}

// pruneClientSightings drops spans that ended before the query log retention
// cutoff, so first-seen history never outlives the queries behind it.
func (store *Store) pruneClientSightings(ctx context.Context, transaction *sql.Tx, before time.Time) error {
	for _, table := range []string{"sable_client_seen", "sable_client_domain_seen", "sable_client_identity"} {
		if _, err := transaction.ExecContext(ctx, "DELETE FROM "+table+" WHERE last_seen < "+store.placeholder(1), before.UTC()); err != nil {
			return fmt.Errorf("prune %s: %w", table, err)
		}
	}
	return nil
}

// ClientActivity reports every client with traffic in [since, until]: exact
// query and blocked counts from the rollups, first and last sightings, how many
// names it queried for the first time, and its last day of traffic against the
// week before, for change detection.
func (store *Store) ClientActivity(ctx context.Context, since, until time.Time) (querylog.ClientActivityReport, error) {
	report := querylog.ClientActivityReport{}
	if since.IsZero() || until.IsZero() || !since.Before(until) {
		return report, errors.New("client activity needs a bounded window")
	}
	clientDimension := rollupDimension{name: queryLogRollupClient, column: "client_ip_key"}
	queries, err := store.summarizeRollupDimension(ctx, since, until, clientDimension, maximumClientActivity, nil)
	if err != nil {
		return report, err
	}
	blocked, err := store.summarizeRollupDimension(ctx, since, until, rollupDimension{
		name: queryLogRollupBlockedClient, column: "client_ip_key", blockedOnly: true, since: store.blockedClientRollupSince,
	}, maximumClientActivity, nil)
	if err != nil {
		return report, err
	}
	recentStart := until.Add(-24 * time.Hour)
	recent, err := store.summarizeRollupDimension(ctx, recentStart, until, clientDimension, maximumClientActivity, nil)
	if err != nil {
		return report, err
	}
	baseline, err := store.summarizeRollupDimension(ctx, recentStart.Add(-deviceBaselineDays*24*time.Hour), recentStart, clientDimension, maximumClientActivity, nil)
	if err != nil {
		return report, err
	}
	newDomains, err := store.countNewClientDomains(ctx, since, until)
	if err != nil {
		return report, err
	}
	seen, err := store.clientSightings(ctx)
	if err != nil {
		return report, err
	}
	if report.SeenSince, _, err = store.rollupMarker(ctx, clientSeenSinceKey); err != nil {
		return report, err
	}

	clients := make(map[string]*querylog.ClientActivity)
	entry := func(client string) *querylog.ClientActivity {
		if clients[client] == nil {
			clients[client] = &querylog.ClientActivity{Client: client}
			if span, found := seen[client]; found {
				clients[client].FirstSeen, clients[client].LastSeen = span.first, span.last
			}
		}
		return clients[client]
	}
	for client, hits := range queries.ranks {
		entry(client).Queries = hits
	}
	// A client that was busy last week and silent since is exactly the kind of
	// change worth reporting, so it is included even with no traffic now.
	for client, hits := range baseline.ranks {
		entry(client).Baseline = hits
	}
	for client, hits := range recent.ranks {
		entry(client).Recent = hits
	}
	for client, hits := range blocked.ranks {
		entry(client).Blocked = hits
	}
	for client, count := range newDomains {
		if existing, found := clients[client]; found {
			existing.NewDomains = count
		}
	}
	report.Clients = make([]querylog.ClientActivity, 0, len(clients))
	for _, activity := range clients {
		report.Clients = append(report.Clients, *activity)
	}
	sort.Slice(report.Clients, func(left, right int) bool {
		if report.Clients[left].Queries != report.Clients[right].Queries {
			return report.Clients[left].Queries > report.Clients[right].Queries
		}
		return report.Clients[left].Client < report.Clients[right].Client
	})
	return report, nil
}

func (store *Store) countNewClientDomains(ctx context.Context, since, until time.Time) (map[string]uint64, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT client_key, COUNT(*)
FROM sable_client_domain_seen
WHERE first_seen >= `+store.placeholder(1)+` AND first_seen <= `+store.placeholder(2)+`
GROUP BY client_key`, since.UTC(), until.UTC())
	if err != nil {
		return nil, fmt.Errorf("count new client domains: %w", err)
	}
	defer rows.Close()
	counts := make(map[string]uint64)
	for rows.Next() {
		var client string
		var count uint64
		if err := rows.Scan(&client, &count); err != nil {
			return nil, fmt.Errorf("scan new client domains: %w", err)
		}
		counts[client] = count
	}
	return counts, rows.Err()
}

func (store *Store) clientSightings(ctx context.Context) (map[string]sightingSpan, error) {
	rows, err := store.database.QueryContext(ctx, "SELECT client_key, first_seen, last_seen FROM sable_client_seen")
	if err != nil {
		return nil, fmt.Errorf("read client sightings: %w", err)
	}
	defer rows.Close()
	spans := make(map[string]sightingSpan)
	for rows.Next() {
		var client string
		var first, last any
		if err := rows.Scan(&client, &first, &last); err != nil {
			return nil, fmt.Errorf("scan client sighting: %w", err)
		}
		span, err := scanSpan(first, last)
		if err != nil {
			return nil, err
		}
		spans[client] = span
	}
	return spans, rows.Err()
}

func scanSpan(first, last any) (sightingSpan, error) {
	firstSeen, err := databaseTime(first)
	if err != nil {
		return sightingSpan{}, fmt.Errorf("read first seen: %w", err)
	}
	lastSeen, err := databaseTime(last)
	if err != nil {
		return sightingSpan{}, fmt.Errorf("read last seen: %w", err)
	}
	return sightingSpan{first: firstSeen.UTC(), last: lastSeen.UTC()}, nil
}

// ClientNewDomains lists the names the given client addresses queried for the
// first time in [since, until], newest first.
func (store *Store) ClientNewDomains(ctx context.Context, clients []string, since, until time.Time, limit int) ([]querylog.ClientDomain, error) {
	if len(clients) == 0 {
		return nil, nil
	}
	arguments := make([]any, 0, len(clients)+3)
	placeholders := make([]string, 0, len(clients))
	for _, client := range clients {
		arguments = append(arguments, queryLogClientKey(client))
		placeholders = append(placeholders, store.placeholder(len(arguments)))
	}
	arguments = append(arguments, since.UTC(), until.UTC(), max(1, limit))
	rows, err := store.database.QueryContext(ctx, `
SELECT name_key, MIN(first_seen) AS first_seen
FROM sable_client_domain_seen
WHERE client_key IN (`+strings.Join(placeholders, ", ")+`)
GROUP BY name_key
HAVING MIN(first_seen) >= `+store.placeholder(len(clients)+1)+` AND MIN(first_seen) <= `+store.placeholder(len(clients)+2)+`
ORDER BY first_seen DESC, name_key ASC
LIMIT `+store.placeholder(len(clients)+3), arguments...)
	if err != nil {
		return nil, fmt.Errorf("read client new domains: %w", err)
	}
	defer rows.Close()
	domains := make([]querylog.ClientDomain, 0)
	for rows.Next() {
		var domain querylog.ClientDomain
		var first any
		if err := rows.Scan(&domain.Name, &first); err != nil {
			return nil, fmt.Errorf("scan client new domain: %w", err)
		}
		if domain.FirstSeen, err = databaseTime(first); err != nil {
			return nil, fmt.Errorf("read client new domain time: %w", err)
		}
		domains = append(domains, domain)
	}
	return domains, rows.Err()
}

// ClientNewDomainCount counts the distinct names the given client addresses
// queried for the first time in [since, until]. A device with several
// addresses can meet the same name on each, so its per-address counts do not
// simply add up.
func (store *Store) ClientNewDomainCount(ctx context.Context, clients []string, since, until time.Time) (uint64, error) {
	if len(clients) == 0 {
		return 0, nil
	}
	arguments := make([]any, 0, len(clients)+2)
	placeholders := make([]string, 0, len(clients))
	for _, client := range clients {
		arguments = append(arguments, queryLogClientKey(client))
		placeholders = append(placeholders, store.placeholder(len(arguments)))
	}
	arguments = append(arguments, since.UTC(), until.UTC())
	var count uint64
	err := store.database.QueryRowContext(ctx, `
SELECT COUNT(*) FROM (
    SELECT name_key
    FROM sable_client_domain_seen
    WHERE client_key IN (`+strings.Join(placeholders, ", ")+`)
    GROUP BY name_key
    HAVING MIN(first_seen) >= `+store.placeholder(len(clients)+1)+` AND MIN(first_seen) <= `+store.placeholder(len(clients)+2)+`
) AS first_time`, arguments...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count client new domains: %w", err)
	}
	return count, nil
}

// ClientTopDomains ranks the names the given client addresses queried in
// [since, until] with the same inclusive bounds and exact client match the
// query log page applies, so a link carrying this window reproduces each count.
func (store *Store) ClientTopDomains(ctx context.Context, clients []string, since, until time.Time, limit int) ([]querylog.ClientDomain, error) {
	if len(clients) == 0 {
		return nil, nil
	}
	arguments := []any{string(querylog.SourceBlocked)}
	placeholders := make([]string, 0, len(clients))
	for _, client := range clients {
		arguments = append(arguments, queryLogClientKey(client))
		placeholders = append(placeholders, store.placeholder(len(arguments)))
	}
	arguments = append(arguments, since.UTC(), until.UTC(), max(1, limit))
	count := len(arguments)
	rows, err := store.database.QueryContext(ctx, `
SELECT name_key, COUNT(*) AS hits, SUM(CASE WHEN source = `+store.placeholder(1)+` THEN 1 ELSE 0 END) AS blocked
FROM sable_query_log
WHERE client_ip_key IN (`+strings.Join(placeholders, ", ")+`)
  AND occurred_at >= `+store.placeholder(count-2)+` AND occurred_at <= `+store.placeholder(count-1)+`
GROUP BY name_key
ORDER BY hits DESC, name_key ASC
LIMIT `+store.placeholder(count), arguments...)
	if err != nil {
		return nil, fmt.Errorf("rank client domains: %w", err)
	}
	defer rows.Close()
	domains := make([]querylog.ClientDomain, 0)
	for rows.Next() {
		var domain querylog.ClientDomain
		if err := rows.Scan(&domain.Name, &domain.Queries, &domain.Blocked); err != nil {
			return nil, fmt.Errorf("scan client domain: %w", err)
		}
		domains = append(domains, domain)
	}
	return domains, rows.Err()
}

// RecordClientIdentities remembers which hardware address each client address
// belonged to, so history can be tied to a device after its address changes.
func (store *Store) RecordClientIdentities(ctx context.Context, identities []querylog.ClientIdentity) error {
	rows := make([][]any, 0, len(identities))
	for _, identity := range identities {
		address := queryLogClientKey(identity.Address)
		mac := strings.ToLower(strings.TrimSpace(identity.MAC))
		if address == "" || mac == "" || identity.Source == "" {
			continue
		}
		seen := identity.SeenAt.UTC().Truncate(time.Second)
		rows = append(rows, []any{address, mac, identity.Source, identity.Hostname, seen, seen})
	}
	for start := 0; start < len(rows); start += clientSightingInsertRows {
		if err := store.upsertSpans(ctx, store.database, "sable_client_identity",
			[]string{"address", "mac", "source"}, []string{"hostname"}, rows[start:min(start+clientSightingInsertRows, len(rows))]); err != nil {
			return err
		}
	}
	return nil
}

// ClientIdentities returns the address-to-hardware sightings still current at
// or after since, most recent first.
func (store *Store) ClientIdentities(ctx context.Context, since time.Time) ([]querylog.ClientIdentity, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT address, mac, source, hostname, first_seen, last_seen
FROM sable_client_identity
WHERE last_seen >= `+store.placeholder(1)+`
ORDER BY last_seen DESC, address ASC`, since.UTC())
	if err != nil {
		return nil, fmt.Errorf("read client identities: %w", err)
	}
	defer rows.Close()
	identities := make([]querylog.ClientIdentity, 0)
	for rows.Next() {
		var identity querylog.ClientIdentity
		var first, last any
		if err := rows.Scan(&identity.Address, &identity.MAC, &identity.Source, &identity.Hostname, &first, &last); err != nil {
			return nil, fmt.Errorf("scan client identity: %w", err)
		}
		span, err := scanSpan(first, last)
		if err != nil {
			return nil, err
		}
		identity.FirstSeen, identity.LastSeen, identity.SeenAt = span.first, span.last, span.last
		identities = append(identities, identity)
	}
	return identities, rows.Err()
}

// ClientDomainHistory lists every name the given client addresses have
// queried, with when each was first queried, newest first. It reads at most
// limit names, so a caller that gets exactly limit back cannot tell whether
// older history was cut off.
func (store *Store) ClientDomainHistory(ctx context.Context, clients []string, limit int) ([]querylog.ClientDomain, error) {
	if len(clients) == 0 {
		return nil, nil
	}
	arguments := make([]any, 0, len(clients)+1)
	placeholders := make([]string, 0, len(clients))
	for _, client := range clients {
		arguments = append(arguments, queryLogClientKey(client))
		placeholders = append(placeholders, store.placeholder(len(arguments)))
	}
	arguments = append(arguments, max(1, limit))
	rows, err := store.database.QueryContext(ctx, `
SELECT name_key, MIN(first_seen) AS first_seen
FROM sable_client_domain_seen
WHERE client_key IN (`+strings.Join(placeholders, ", ")+`)
GROUP BY name_key
ORDER BY first_seen DESC, name_key ASC
LIMIT `+store.placeholder(len(arguments)), arguments...)
	if err != nil {
		return nil, fmt.Errorf("read client domain history: %w", err)
	}
	defer rows.Close()
	domains := make([]querylog.ClientDomain, 0)
	for rows.Next() {
		var domain querylog.ClientDomain
		var first any
		if err := rows.Scan(&domain.Name, &first); err != nil {
			return nil, fmt.Errorf("scan client domain history: %w", err)
		}
		if domain.FirstSeen, err = databaseTime(first); err != nil {
			return nil, fmt.Errorf("read client domain history time: %w", err)
		}
		domains = append(domains, domain)
	}
	return domains, rows.Err()
}
