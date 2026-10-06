package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// blockedClientRollupSinceKey records when this database started writing the
// blocked-client rollup dimension. Rollup minutes from before then were
// written without it, so a window reaching further back reads those minutes
// from the raw log instead of undercounting them.
const blockedClientRollupSinceKey = "query_log_rollup_blocked_client_since"

// blockedSourceRollupSinceKey records when blocked queries began carrying the
// block lists that supplied their rule.
const blockedSourceRollupSinceKey = "query_log_rollup_blocked_source_since"

// maximumBlockingRanks bounds the Insights rankings the same way the dashboard
// rankings are bounded.
const maximumBlockingRanks = maximumInsightRanks

// maximumBlockedNameRules bounds how many allow rules share one statement.
// Every rule is bound twice, once for the rollup and once for the raw minutes.
const maximumBlockedNameRules = 500

// maximumBlockedNameEvidence bounds how many names a rule match reports.
const maximumBlockedNameEvidence = 100

// rollupDimension describes one query log dimension that is counted in the
// minute rollups and can be recounted from the raw log for the partial minutes
// at either end of a window.
type rollupDimension struct {
	name string
	// column is the raw query log column the rollup value was taken from.
	column string
	// only limits the raw recount to queries from one source, matching the
	// rollup dimensions that are only written for them, such as blocked ones.
	only querylog.Source
	// since reports when the rollups began carrying this dimension. Nil means
	// the dimension has always been written alongside the others.
	since func(context.Context) (time.Time, bool, error)
}

// rollupValueFilter narrows a dimension to values matching allow rules: whole
// names and the subdomains of wildcard rules.
type rollupValueFilter struct {
	exact    []string
	suffixes []string
}

type rollupSummary struct {
	ranks    map[string]uint64
	total    uint64
	distinct uint64
}

// BlockingActivity counts the blocked queries in [since, until] exactly, from
// the minute rollups plus the raw log at the window's ragged edges, so every
// number agrees with the query log page filtered to the same window.
func (store *Store) BlockingActivity(ctx context.Context, since, until time.Time) (querylog.BlockingActivity, error) {
	if since.IsZero() || until.IsZero() || !since.Before(until) {
		return querylog.BlockingActivity{}, errors.New("blocking activity needs a bounded window")
	}
	all, err := store.summarizeRollupDimension(ctx, since, until, rollupDimension{
		name: queryLogRollupSource, column: "source",
	}, 1, nil)
	if err != nil {
		return querylog.BlockingActivity{}, err
	}
	domains, err := store.summarizeRollupDimension(ctx, since, until, rollupDimension{
		name: queryLogRollupBlocked, column: queryLogDomainExpression, only: querylog.SourceBlocked,
	}, maximumBlockingRanks, nil)
	if err != nil {
		return querylog.BlockingActivity{}, err
	}
	clients, err := store.summarizeRollupDimension(ctx, since, until, rollupDimension{
		name: queryLogRollupBlockedClient, column: "client_ip_key", only: querylog.SourceBlocked,
		since: store.blockedClientRollupSince,
	}, maximumBlockingRanks, nil)
	if err != nil {
		return querylog.BlockingActivity{}, err
	}
	sources, sourcesSince, err := store.blockedSourceActivity(ctx, since, until)
	if err != nil {
		return querylog.BlockingActivity{}, err
	}
	return querylog.BlockingActivity{
		Queries:        all.total,
		Blocked:        domains.total,
		BlockedDomains: domains.distinct,
		BlockedClients: clients.distinct,
		TopDomains:     domains.ranks,
		TopClients:     clients.ranks,
		Sources:        sources,
		SourcesSince:   sourcesSince,
	}, nil
}

// blockedSourceActivity counts blocked queries per block list in [since,
// until]. Queries written before blocked queries recorded their source carry
// none, so counting starts at that moment and reports it when it falls inside
// the window. Whole minutes come from the rollups; the ragged edges are read
// from the raw log and their recorded decisions decoded, which is at most a
// couple of minutes of blocked rows.
func (store *Store) blockedSourceActivity(ctx context.Context, since, until time.Time) (map[string]querylog.SourceActivity, time.Time, error) {
	activity := map[string]querylog.SourceActivity{}
	since, until = since.UTC(), until.UTC()
	began, found, err := store.blockedSourceRollupSince(ctx)
	if err != nil || !found {
		return activity, time.Time{}, err
	}
	began = began.UTC()
	start := maxTime(since, began.Truncate(time.Minute))
	reported := time.Time{}
	if began.After(since) {
		reported = began
	}
	if !start.Before(until) {
		return activity, reported, nil
	}
	fullStart, fullEnd := ceilMinute(start), until.Truncate(time.Minute)
	if !fullStart.Before(fullEnd) {
		fullStart, fullEnd = until, until
	}

	spans, err := store.rollupSpans(ctx, fullStart, fullEnd, dayRollupTier.size)
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(spans) > 0 {
		builder := store.newSQLBuilder()
		arms := make([]string, 0, len(spans))
		for _, span := range spans {
			arms = append(arms, "SELECT dimension, value, hits FROM "+span.table+
				" WHERE "+store.dimensionCondition([]string{queryLogRollupBlockedSource, queryLogRollupBlockedSoleSource}, builder.Bind)+
				" AND bucket_start >= "+builder.Bind(span.start)+" AND bucket_start < "+builder.Bind(span.end))
		}
		rows, err := store.database.QueryContext(ctx, `
SELECT dimension, value, CAST(SUM(hits) AS BIGINT)
FROM (`+strings.Join(arms, "\n    UNION ALL\n    ")+`) AS rolled
GROUP BY dimension, value`, builder.Args()...)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("read blocked source rollups: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var dimension, source string
			var hits uint64
			if err := rows.Scan(&dimension, &source, &hits); err != nil {
				return nil, time.Time{}, fmt.Errorf("scan blocked source rollup: %w", err)
			}
			counts := activity[source]
			if dimension == queryLogRollupBlockedSoleSource {
				counts.Sole += hits
			} else {
				counts.Blocked += hits
			}
			activity[source] = counts
		}
		if err := rows.Err(); err != nil {
			return nil, time.Time{}, fmt.Errorf("iterate blocked source rollups: %w", err)
		}
	}

	edges, err := store.database.QueryContext(ctx, `
SELECT decision FROM sable_query_log
WHERE source = `+store.placeholder(1)+`
  AND ((occurred_at >= `+store.placeholder(2)+` AND occurred_at < `+store.placeholder(3)+`)
    OR (occurred_at >= `+store.placeholder(4)+` AND occurred_at <= `+store.placeholder(5)+`))`,
		string(querylog.SourceBlocked), start, fullStart, fullEnd, until)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("read blocked source edges: %w", err)
	}
	defer edges.Close()
	for edges.Next() {
		var raw string
		if err := edges.Scan(&raw); err != nil {
			return nil, time.Time{}, fmt.Errorf("scan blocked source edge: %w", err)
		}
		var decision querylog.Decision
		if err := json.Unmarshal([]byte(raw), &decision); err != nil {
			continue
		}
		for _, source := range decision.PolicySources {
			counts := activity[source]
			counts.Blocked++
			if len(decision.PolicySources) == 1 {
				counts.Sole++
			}
			activity[source] = counts
		}
	}
	if err := edges.Err(); err != nil {
		return nil, time.Time{}, fmt.Errorf("iterate blocked source edges: %w", err)
	}
	return activity, reported, nil
}

// BlockedNamesMatching counts the blocked queries in [since, until] whose name
// an allow rule now matches. Exact rules match one name; suffix rules match
// every name below the suffix but not the suffix itself, which is how a
// wildcard allow rule is applied at query time.
func (store *Store) BlockedNamesMatching(ctx context.Context, since, until time.Time, exact, suffixes []string) (map[string]uint64, error) {
	if since.IsZero() || until.IsZero() || !since.Before(until) {
		return nil, errors.New("blocked name counts need a bounded window")
	}
	matched := make(map[string]uint64)
	dimension := rollupDimension{name: queryLogRollupBlocked, column: queryLogDomainExpression, only: querylog.SourceBlocked}
	// A name can match an exact rule in one chunk and a wildcard in another.
	// Its count is the same either way, so the chunks merge by maximum rather
	// than by sum.
	merge := func(filter rollupValueFilter) error {
		summary, err := store.summarizeRollupDimension(ctx, since, until, dimension, maximumBlockedNameEvidence, &filter)
		if err != nil {
			return err
		}
		for name, hits := range summary.ranks {
			matched[name] = max(matched[name], hits)
		}
		return nil
	}
	for start := 0; start < len(exact); start += maximumBlockedNameRules {
		if err := merge(rollupValueFilter{exact: exact[start:min(start+maximumBlockedNameRules, len(exact))]}); err != nil {
			return nil, err
		}
	}
	for start := 0; start < len(suffixes); start += maximumBlockedNameRules {
		if err := merge(rollupValueFilter{suffixes: suffixes[start:min(start+maximumBlockedNameRules, len(suffixes))]}); err != nil {
			return nil, err
		}
	}
	return matched, nil
}

// BlockedNameEvidence reads what the raw query log retained about one blocked
// name in [since, until]. It counts with the same inclusive bounds and exact
// name match the query log page applies, so a link carrying this window
// reproduces the count.
func (store *Store) BlockedNameEvidence(ctx context.Context, since, until time.Time, name string, clientLimit int) (querylog.BlockedNameEvidence, error) {
	evidence := querylog.BlockedNameEvidence{Name: queryLogDomainKey(name), Clients: map[string]uint64{}}
	if since.IsZero() || until.IsZero() || !since.Before(until) {
		return evidence, errors.New("blocked name evidence needs a bounded window")
	}
	clientLimit = max(1, clientLimit)
	arguments := []any{evidence.Name, string(querylog.SourceBlocked), since.UTC(), until.UTC(), clientLimit}
	rows, err := store.database.QueryContext(ctx, `
WITH blocked AS (
    SELECT client_ip_key, occurred_at
    FROM sable_query_log
    WHERE name_key = `+store.placeholder(1)+` AND source = `+store.placeholder(2)+`
      AND occurred_at >= `+store.placeholder(3)+` AND occurred_at <= `+store.placeholder(4)+`
), clients AS (
    SELECT client_ip_key, COUNT(*) AS hits FROM blocked GROUP BY client_ip_key
), ranked AS (
    SELECT client_ip_key, hits,
           ROW_NUMBER() OVER (ORDER BY hits DESC, client_ip_key ASC) AS position,
           COUNT(*) OVER () AS client_count
    FROM clients
)
SELECT ranked.client_ip_key, ranked.hits, ranked.client_count, totals.total, totals.first_blocked, totals.last_blocked
FROM ranked
CROSS JOIN (SELECT COUNT(*) AS total, MIN(occurred_at) AS first_blocked, MAX(occurred_at) AS last_blocked FROM blocked) AS totals
WHERE ranked.position <= `+store.placeholder(5), arguments...)
	if err != nil {
		return evidence, fmt.Errorf("read blocked name evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var client string
		var hits, clientCount, total uint64
		var first, last any
		if err := rows.Scan(&client, &hits, &clientCount, &total, &first, &last); err != nil {
			return evidence, fmt.Errorf("scan blocked name evidence: %w", err)
		}
		evidence.Clients[client] = hits
		evidence.Blocked, evidence.ClientCount = total, clientCount
		if evidence.FirstBlocked, err = databaseTime(first); err != nil {
			return evidence, fmt.Errorf("read first blocked time: %w", err)
		}
		if evidence.LastBlocked, err = databaseTime(last); err != nil {
			return evidence, fmt.Errorf("read last blocked time: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return evidence, fmt.Errorf("iterate blocked name evidence: %w", err)
	}
	return evidence, nil
}

// summarizeRollupDimension totals one rollup dimension over [since, until]. Whole
// minutes come from the rollups and the partial minutes at either end come from
// the raw log, the same split QueryLogInsights uses. It returns the busiest
// values along with the exact total and the number of distinct values.
func (store *Store) summarizeRollupDimension(
	ctx context.Context,
	since, until time.Time,
	dimension rollupDimension,
	limit int,
	filter *rollupValueFilter,
) (rollupSummary, error) {
	summary := rollupSummary{ranks: map[string]uint64{}}
	since, until = since.UTC(), until.UTC()
	fullStart, fullEnd, err := store.rollupSummaryRange(ctx, since, until, dimension)
	if err != nil {
		return summary, err
	}
	spans, err := store.rollupSpans(ctx, fullStart, fullEnd, dayRollupTier.size)
	if err != nil {
		return summary, err
	}
	statement, arguments := store.rollupSummaryStatement(since, until, fullStart, fullEnd, spans, dimension, limit, filter)

	rows, err := store.database.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return summary, fmt.Errorf("summarize query log %s: %w", dimension.name, err)
	}
	defer rows.Close()
	for rows.Next() {
		var value sql.NullString
		var hits, distinct, total uint64
		if err := rows.Scan(&value, &hits, &distinct, &total); err != nil {
			return summary, fmt.Errorf("scan query log %s summary: %w", dimension.name, err)
		}
		summary.distinct, summary.total = distinct, total
		summary.ranks[value.String] += hits
	}
	if err := rows.Err(); err != nil {
		return summary, fmt.Errorf("iterate query log %s summary: %w", dimension.name, err)
	}
	return summary, nil
}

// rollupSummaryRange returns the whole minutes of [since, until] the rollups
// cover for a dimension. With no usable rollups the range is empty at until, so
// the whole window is read from the raw log.
func (store *Store) rollupSummaryRange(ctx context.Context, since, until time.Time, dimension rollupDimension) (time.Time, time.Time, error) {
	coverage, covered, err := store.queryLogRollupStart(ctx)
	if err != nil {
		return until, until, err
	}
	if covered && dimension.since != nil {
		began, found, err := dimension.since(ctx)
		if err != nil {
			return until, until, err
		}
		covered = found
		coverage = maxTime(coverage, began.UTC().Truncate(time.Minute))
	}
	if !covered {
		return until, until, nil
	}
	fullStart := ceilMinute(maxTime(since, coverage.Add(time.Minute)))
	fullEnd := until.Truncate(time.Minute)
	if !fullStart.Before(fullEnd) {
		return until, until, nil
	}
	return fullStart, fullEnd, nil
}

// rollupSummaryStatement builds the query that adds the raw edges of the window
// to the rollup spans in [fullStart, fullEnd) and ranks the combined values.
func (store *Store) rollupSummaryStatement(
	since, until, fullStart, fullEnd time.Time,
	spans []rollupSpan,
	dimension rollupDimension,
	limit int,
	filter *rollupValueFilter,
) (string, []any) {
	builder := store.newSQLBuilder()
	var statement strings.Builder
	// The raw edges are read by time even when a filter names clients or
	// domains: those indexes would walk the named values' whole history.
	statement.WriteString(`
WITH boundary AS (
    SELECT ` + dimension.column + ` AS value
    FROM sable_query_log` + store.queryLogTimeIndex() + `
    WHERE ((occurred_at >= ` + builder.Bind(since) + ` AND occurred_at < ` + builder.Bind(fullStart) + `)
        OR (occurred_at >= ` + builder.Bind(fullEnd) + ` AND occurred_at <= ` + builder.Bind(until) + `))`)
	if dimension.only != "" {
		statement.WriteString(` AND source = ` + builder.Bind(string(dimension.only)))
	}
	if filter != nil {
		statement.WriteString(` AND ` + store.rollupValueCondition(dimension.column, *filter, builder.Bind))
	}
	statement.WriteString(`
), combined (value, hits) AS (`)
	for _, span := range spans {
		statement.WriteString(`
    SELECT value, hits
    FROM ` + span.table + `
    WHERE dimension = ` + builder.Bind(dimension.name) + ` AND bucket_start >= ` + builder.Bind(span.start) + ` AND bucket_start < ` + builder.Bind(span.end))
		if filter != nil {
			statement.WriteString(` AND ` + store.rollupValueCondition("value", *filter, builder.Bind))
		}
		statement.WriteString(`
    UNION ALL`)
	}
	statement.WriteString(`
    SELECT value, COUNT(*) FROM boundary GROUP BY value
), totals AS (
    -- PostgreSQL promotes SUM(BIGINT) to NUMERIC, so cast it back to the
    -- bounded integer type used by both supported drivers.
    SELECT value, CAST(SUM(hits) AS BIGINT) AS hits
    FROM combined
    GROUP BY value
), ranked AS (
    SELECT value, hits,
           ROW_NUMBER() OVER (ORDER BY hits DESC, value ASC) AS position,
           COUNT(*) OVER () AS distinct_values,
           CAST(SUM(hits) OVER () AS BIGINT) AS total_hits
    FROM totals
)
SELECT value, hits, distinct_values, total_hits
FROM ranked
WHERE position <= ` + builder.Bind(max(1, limit)))
	return statement.String(), builder.Args()
}

// rollupValueCondition matches a column against exact names and the strict
// subdomains of suffixes. The LIKE patterns escape the wildcard characters a
// DNS label can legitimately contain, such as the underscore in _dmarc.
func (store *Store) rollupValueCondition(column string, filter rollupValueFilter, bind func(any) string) string {
	conditions := make([]string, 0, len(filter.suffixes)+1)
	if len(filter.exact) > 0 {
		placeholders := make([]string, 0, len(filter.exact))
		for _, name := range filter.exact {
			placeholders = append(placeholders, bind(queryLogDomainKey(name)))
		}
		conditions = append(conditions, column+" IN ("+strings.Join(placeholders, ", ")+")")
	}
	for _, suffix := range filter.suffixes {
		conditions = append(conditions, column+" LIKE "+bind("%."+escapeLike(queryLogDomainKey(suffix)))+` ESCAPE '\'`)
	}
	if len(conditions) == 0 {
		return "1 = 0"
	}
	return "(" + strings.Join(conditions, " OR ") + ")"
}

func escapeLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

// blockedClientRollupSince reports when the blocked-client dimension started
// being written, as recorded by the migration that introduced it.
func (store *Store) blockedClientRollupSince(ctx context.Context) (time.Time, bool, error) {
	return store.rollupMarker(ctx, blockedClientRollupSinceKey)
}

// blockedSourceRollupSince reports when blocked queries began carrying the
// block lists behind them. Older queries never recorded their source.
func (store *Store) blockedSourceRollupSince(ctx context.Context) (time.Time, bool, error) {
	return store.rollupMarker(ctx, blockedSourceRollupSinceKey)
}

func (store *Store) rollupMarker(ctx context.Context, key string) (time.Time, bool, error) {
	raw, found, err := store.getMeta(ctx, store.database, key)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("read %s: %w", key, err)
	}
	if !found {
		return time.Time{}, false, nil
	}
	since, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("parse %s: %w", key, err)
	}
	return since, true, nil
}

// migrateActivityMarkers marks the moment this database began writing the
// blocked-client, blocked-source, and app rollups and client sightings. The
// first migration wins, so a marker never moves forward over data written
// with it.
func (store *Store) migrateActivityMarkers(ctx context.Context) error {
	now := metaTime(time.Now())
	for _, key := range []string{blockedClientRollupSinceKey, blockedSourceRollupSinceKey, clientSeenSinceKey, appRollupSinceKey, appFailedSinceKey} {
		if _, err := store.setMetaIfAbsent(ctx, store.database, key, now); err != nil {
			return fmt.Errorf("record %s: %w", key, err)
		}
	}
	return nil
}
