package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/drudge/sable/internal/insights/services"
	"github.com/drudge/sable/internal/querylog"
)

// appRollupSinceKey records when this database started writing the app
// dimensions. The backfill moves it back as it counts older history, and reads
// count from it, so a window reaching past it is reported as partial rather
// than undercounted.
const appRollupSinceKey = "query_log_rollup_app_since"

// appBackfilledKey records that the app dimensions were filled in from the
// query history written before they existed.
const appBackfilledKey = "query_log_rollup_app_backfilled"

// appBackfillChunk is how much history one backfill transaction counts, so the
// query log writer never waits long for it.
const appBackfillChunk = 6 * time.Hour

// maximumAppDomains bounds how many of an app's names its drawer reads.
const maximumAppDomains = 100

// AppActivity counts the queries in [since, until] to every app in the service
// catalog, by client, with the ones that failed and were blocked. Whole minutes
// come from the rollups and the ragged edges from the raw log, whose names are
// matched to apps here, so the counts cover every name rather than the busiest.
func (store *Store) AppActivity(ctx context.Context, since, until time.Time) (querylog.AppActivity, error) {
	activity := querylog.AppActivity{Clients: map[string]map[string]querylog.AppCounts{}}
	if since.IsZero() || until.IsZero() || !since.Before(until) {
		return activity, errors.New("app activity needs a bounded window")
	}
	since, until = since.UTC(), until.UTC()
	start, fullStart, fullEnd, reported, counted, err := store.appWindow(ctx, since, until)
	if err != nil || !counted {
		activity.Since = reported
		return activity, err
	}
	activity.Since = reported
	add := func(app, client string, counts querylog.AppCounts) {
		clients := activity.Clients[app]
		if clients == nil {
			clients = map[string]querylog.AppCounts{}
			activity.Clients[app] = clients
		}
		total := clients[client]
		total.Queries += counts.Queries
		total.Failed += counts.Failed
		total.Blocked += counts.Blocked
		clients[client] = total
	}

	spans, err := store.rollupSpans(ctx, fullStart, fullEnd, dayRollupTier.size)
	if err != nil {
		return activity, err
	}
	if len(spans) > 0 {
		var arguments []any
		bind := func(value any) string {
			arguments = append(arguments, value)
			return store.placeholder(len(arguments))
		}
		dimensions := []string{queryLogRollupAppClient, queryLogRollupAppClientFailed, queryLogRollupAppClientBlocked}
		arms := make([]string, 0, len(spans))
		for _, span := range spans {
			arms = append(arms, "SELECT dimension, value, hits FROM "+span.table+
				" WHERE "+store.dimensionCondition(dimensions, bind)+
				" AND bucket_start >= "+bind(span.start)+" AND bucket_start < "+bind(span.end))
		}
		rows, err := store.database.QueryContext(ctx, `
SELECT dimension, value, CAST(SUM(hits) AS BIGINT)
FROM (`+strings.Join(arms, "\n    UNION ALL\n    ")+`) AS rolled
GROUP BY dimension, value`, arguments...)
		if err != nil {
			return activity, fmt.Errorf("read app rollups: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var dimension, value string
			var hits uint64
			if err := rows.Scan(&dimension, &value, &hits); err != nil {
				return activity, fmt.Errorf("scan app rollup: %w", err)
			}
			app, client, ok := splitAppClientValue(value)
			if !ok {
				continue
			}
			switch dimension {
			case queryLogRollupAppClient:
				add(app, client, querylog.AppCounts{Queries: hits})
			case queryLogRollupAppClientFailed:
				add(app, client, querylog.AppCounts{Failed: hits})
			case queryLogRollupAppClientBlocked:
				add(app, client, querylog.AppCounts{Blocked: hits})
			}
		}
		if err := rows.Err(); err != nil {
			return activity, fmt.Errorf("iterate app rollups: %w", err)
		}
	}

	edges, err := store.database.QueryContext(ctx, `
SELECT client_ip_key, name_key, source FROM sable_query_log`+store.queryLogTimeIndex()+`
WHERE (occurred_at >= `+store.placeholder(1)+` AND occurred_at < `+store.placeholder(2)+`)
   OR (occurred_at >= `+store.placeholder(3)+` AND occurred_at <= `+store.placeholder(4)+`)`,
		start, fullStart, fullEnd, until)
	if err != nil {
		return activity, fmt.Errorf("read app edges: %w", err)
	}
	defer edges.Close()
	for edges.Next() {
		var client, name, source string
		if err := edges.Scan(&client, &name, &source); err != nil {
			return activity, fmt.Errorf("scan app edge: %w", err)
		}
		service, found := services.Lookup(name)
		if !found {
			continue
		}
		event := querylog.Event{Source: querylog.Source(source)}
		counts := querylog.AppCounts{Queries: 1}
		if event.Failed() {
			counts.Failed = 1
		}
		if event.Source == querylog.SourceBlocked {
			counts.Blocked = 1
		}
		add(service.ID, client, counts)
	}
	if err := edges.Err(); err != nil {
		return activity, fmt.Errorf("iterate app edges: %w", err)
	}
	return activity, nil
}

// appWindow splits [since, until] for the app dimensions: counting starts at
// start, whole minutes run from fullStart to fullEnd, and the raw log covers
// the rest. reported is when counting began, if that is inside the window, and
// counted is false when it began after the window ended.
func (store *Store) appWindow(ctx context.Context, since, until time.Time) (start, fullStart, fullEnd, reported time.Time, counted bool, err error) {
	began, found, err := store.rollupMarker(ctx, appRollupSinceKey)
	if err != nil {
		return
	}
	coverage, covered, err := store.queryLogRollupStart(ctx)
	if err != nil {
		return
	}
	start = since
	if found {
		// The minute counting began holds rows written both ways, so it is
		// read from the raw log.
		start = maxTime(since, began.UTC().Truncate(time.Minute))
		// Counting that began with the oldest history kept misses nothing.
		if began.After(since) && (!covered || began.After(coverage)) {
			reported = began.UTC()
		}
	}
	if !start.Before(until) {
		return
	}
	counted = true
	fullStart, fullEnd = until, until
	if !covered {
		return
	}
	first := coverage.Add(time.Minute)
	if found {
		first = maxTime(first, began.UTC().Truncate(time.Minute).Add(time.Minute))
	}
	fullStart, fullEnd = ceilMinute(maxTime(start, first)), until.Truncate(time.Minute)
	if !fullStart.Before(fullEnd) {
		fullStart, fullEnd = until, until
	}
	return
}

// AppDomains counts the queries in [since, until] to the names under the given
// suffixes, which are one app's, with how many failed, busiest first. Only
// names below a suffix or equal to it count, so "tv.apple.com" never takes in
// "apple.com".
func (store *Store) AppDomains(ctx context.Context, since, until time.Time, suffixes []string) ([]querylog.AppDomain, error) {
	if since.IsZero() || until.IsZero() || !since.Before(until) {
		return nil, errors.New("app domains need a bounded window")
	}
	if len(suffixes) == 0 {
		return nil, nil
	}
	filter := rollupValueFilter{exact: suffixes, suffixes: suffixes}
	queries, err := store.summarizeRollupDimension(ctx, since, until, rollupDimension{
		name: queryLogRollupDomain, column: queryLogDomainExpression,
	}, maximumAppDomains, &filter)
	if err != nil {
		return nil, err
	}
	failed, err := store.summarizeRollupDimension(ctx, since, until, rollupDimension{
		name: queryLogRollupFailed, column: queryLogDomainExpression, only: querylog.SourceError,
		since: func(ctx context.Context) (time.Time, bool, error) { return store.rollupMarker(ctx, appRollupSinceKey) },
	}, maximumAppDomains, &filter)
	if err != nil {
		return nil, err
	}
	domains := make([]querylog.AppDomain, 0, len(queries.ranks))
	for name, hits := range queries.ranks {
		domains = append(domains, querylog.AppDomain{Name: name, Queries: hits, Failed: failed.ranks[name]})
	}
	return domains, nil
}

// AppSightings reads when each app was first and last looked up, across all
// retained history, from the names every client has queried.
func (store *Store) AppSightings(ctx context.Context) (querylog.AppSightings, error) {
	sightings := querylog.AppSightings{Apps: map[string]querylog.AppSighting{}}
	seenSince, _, err := store.rollupMarker(ctx, clientSeenSinceKey)
	if err != nil {
		return sightings, err
	}
	sightings.SeenSince = seenSince
	rows, err := store.database.QueryContext(ctx,
		"SELECT name_key, MIN(first_seen), MAX(last_seen) FROM sable_client_domain_seen GROUP BY name_key")
	if err != nil {
		return sightings, fmt.Errorf("read app sightings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var first, last any
		if err := rows.Scan(&name, &first, &last); err != nil {
			return sightings, fmt.Errorf("scan app sighting: %w", err)
		}
		service, found := services.Lookup(name)
		if !found {
			continue
		}
		firstSeen, err := databaseTime(first)
		if err != nil {
			return sightings, fmt.Errorf("read app first seen: %w", err)
		}
		lastSeen, err := databaseTime(last)
		if err != nil {
			return sightings, fmt.Errorf("read app last seen: %w", err)
		}
		sighting, seen := sightings.Apps[service.ID]
		if !seen || firstSeen.Before(sighting.FirstSeen) {
			sighting.FirstSeen = firstSeen
		}
		if lastSeen.After(sighting.LastSeen) {
			sighting.LastSeen = lastSeen
		}
		sightings.Apps[service.ID] = sighting
	}
	if err := rows.Err(); err != nil {
		return sightings, fmt.Errorf("iterate app sightings: %w", err)
	}
	return sightings, nil
}

// BackfillAppRollups counts the app dimensions, minute by minute, for the
// history written before they existed, then sums them into the hours and days
// that history already fills. It works from the newest history back, moving
// the app marker after each chunk, so a partial run already helps and an
// interrupted one resumes where it stopped. It runs once per database, in the
// background, and never on the DNS request path.
func (store *Store) BackfillAppRollups(ctx context.Context) (bool, error) {
	if _, done, err := store.rollupMarker(ctx, appBackfilledKey); err != nil || done {
		return false, err
	}
	began, found, err := store.rollupMarker(ctx, appRollupSinceKey)
	if err != nil || !found {
		return false, err
	}
	// The minute the dimensions began holds both kinds of rows, so it is
	// counted whole, once nothing more can arrive for it.
	end := began.UTC().Truncate(time.Minute).Add(time.Minute)
	if wait := time.Until(end.Add(blockedClientBackfillSettle)); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-timer.C:
		}
	}
	coverage, covered, err := store.queryLogRollupStart(ctx)
	if err != nil {
		return false, err
	}
	filled := false
	if covered && coverage.Before(end) {
		for end.After(coverage) {
			start := maxTime(coverage, end.Add(-appBackfillChunk))
			if err := store.backfillAppChunk(ctx, start, end); err != nil {
				return filled, err
			}
			filled, end = true, start
		}
	}
	if _, err := store.database.ExecContext(ctx,
		"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholders(2)+") ON CONFLICT(key) DO NOTHING",
		appBackfilledKey, time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return filled, fmt.Errorf("record %s: %w", appBackfilledKey, err)
	}
	return filled, nil
}

// backfillAppChunk counts one stretch of history into the app dimensions,
// replacing whatever the stretch held, sums it into the tiers, and marks the
// dimensions complete from its start.
func (store *Store) backfillAppChunk(ctx context.Context, start, end time.Time) error {
	rows, err := store.database.QueryContext(ctx, `
SELECT client_ip_key, name_key, source, occurred_at FROM sable_query_log
WHERE occurred_at >= `+store.placeholder(1)+` AND occurred_at < `+store.placeholder(2), start, end)
	if err != nil {
		return fmt.Errorf("read app history: %w", err)
	}
	counts := make(map[queryLogRollupKey]uint64)
	for rows.Next() {
		var client, name, source string
		var occurred any
		if err := rows.Scan(&client, &name, &source, &occurred); err != nil {
			rows.Close()
			return fmt.Errorf("scan app history: %w", err)
		}
		moment, err := databaseTime(occurred)
		if err != nil {
			rows.Close()
			return fmt.Errorf("read app history time: %w", err)
		}
		countAppEvent(counts, moment.UTC().Truncate(time.Minute), client, name, querylog.Event{Source: querylog.Source(source)})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate app history: %w", err)
	}
	rollups := sortedRollups(counts)

	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin app backfill: %w", err)
	}
	defer func() { _ = transaction.Rollback() }()
	for index := 0; index < len(rollups); index += queryLogRollupInsertRows {
		if err := store.replaceQueryLogRollups(ctx, transaction, rollups[index:min(index+queryLogRollupInsertRows, len(rollups))]); err != nil {
			return err
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit app backfill: %w", err)
	}
	if err := store.resumTierDimensions(ctx, appRollupDimensions, start, end); err != nil {
		return err
	}
	// The marker moves only once the tiers hold the chunk too, so a read never
	// takes an hour or day from before it that was summed without it.
	if _, err := store.database.ExecContext(ctx,
		"UPDATE sable_metadata SET value = "+store.placeholder(1)+" WHERE key = "+store.placeholder(2),
		start.UTC().Format(time.RFC3339Nano), appRollupSinceKey,
	); err != nil {
		return fmt.Errorf("move %s: %w", appRollupSinceKey, err)
	}
	return nil
}
