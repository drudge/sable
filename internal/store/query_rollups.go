package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/insights/services"
	"github.com/drudge/sable/internal/querylog"
)

const (
	queryLogRollupClient  = "client"
	queryLogRollupDomain  = "domain"
	queryLogRollupBlocked = "blocked"
	// queryLogRollupBlockedClient counts blocked queries per client so the
	// Insights page can rank affected clients without scanning raw history.
	queryLogRollupBlockedClient = "blocked_client"
	// queryLogRollupBlockedSource counts blocked queries per block list that
	// contained the matching rule, and queryLogRollupBlockedSoleSource counts
	// the ones no other list would have blocked.
	queryLogRollupBlockedSource     = "blocked_source"
	queryLogRollupBlockedSoleSource = "blocked_sole_source"
	queryLogRollupRecordType        = "record_type"
	queryLogRollupSource            = "source"
	queryLogRollupResponseCode      = "response_code"
	// queryLogRollupFailed counts the queries Sable could not answer per name,
	// so an app's drawer can say which of its names failed.
	queryLogRollupFailed = "failed"
	// queryLogRollupAppClient counts the queries each client made to each app
	// in the service catalog, valued as appClientValue writes them, and the
	// two dimensions after it count the ones that failed and were blocked.
	// Every name counts, so an app too quiet for the domain rankings still
	// shows up.
	queryLogRollupAppClient        = "app_client"
	queryLogRollupAppClientFailed  = "app_client_failed"
	queryLogRollupAppClientBlocked = "app_client_blocked"
	queryLogRollupInsertRows       = 128
)

// appRollupDimensions are the dimensions written for app activity, which
// began after the others and are filled in from history on their own.
var appRollupDimensions = []string{
	queryLogRollupFailed, queryLogRollupAppClient, queryLogRollupAppClientFailed, queryLogRollupAppClientBlocked,
}

// appClientValue keys an app and a client in one rollup value. Service IDs and
// client addresses never contain a space.
func appClientValue(app, client string) string {
	return app + " " + client
}

// splitAppClientValue reverses appClientValue.
func splitAppClientValue(value string) (app, client string, ok bool) {
	return strings.Cut(value, " ")
}

type queryLogRollupKey struct {
	bucket    time.Time
	dimension string
	value     string
}

type queryLogRollup struct {
	queryLogRollupKey
	hits uint64
}

func queryLogClientKey(clientIP string) string {
	return strings.ToLower(strings.TrimSpace(clientIP))
}

func (store *Store) queryLogRollupTable() string {
	return `
CREATE TABLE IF NOT EXISTS sable_query_log_rollup (
    bucket_start TIMESTAMP NOT NULL,
    dimension TEXT NOT NULL,
    value TEXT NOT NULL,
    hits BIGINT NOT NULL,
    PRIMARY KEY (bucket_start, dimension, value)
)`
}

func (store *Store) writeQueryLogRollups(ctx context.Context, transaction *sql.Tx, events []querylog.Event) error {
	rollups := aggregateQueryLogEvents(events)
	for start := 0; start < len(rollups); start += queryLogRollupInsertRows {
		end := min(start+queryLogRollupInsertRows, len(rollups))
		if err := store.upsertQueryLogRollups(ctx, transaction, rollups[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func aggregateQueryLogEvents(events []querylog.Event) []queryLogRollup {
	counts := make(map[queryLogRollupKey]uint64, len(events)*4)
	for _, event := range events {
		bucket := event.OccurredAt.UTC().Truncate(time.Minute)
		client := queryLogClientKey(event.ClientIP)
		domain := queryLogDomainKey(event.Name)
		values := [...]struct{ dimension, value string }{
			{queryLogRollupClient, client},
			{queryLogRollupDomain, domain},
			{queryLogRollupRecordType, strconv.Itoa(int(event.RecordType))},
			{queryLogRollupSource, string(event.Source)},
			{queryLogRollupResponseCode, strconv.Itoa(event.ResponseCode)},
		}
		for _, value := range values {
			counts[queryLogRollupKey{bucket: bucket, dimension: value.dimension, value: value.value}]++
		}
		countAppEvent(counts, bucket, client, domain, event)
		if event.Source == querylog.SourceBlocked {
			counts[queryLogRollupKey{bucket: bucket, dimension: queryLogRollupBlocked, value: domain}]++
			counts[queryLogRollupKey{bucket: bucket, dimension: queryLogRollupBlockedClient, value: client}]++
			for _, source := range event.Decision.PolicySources {
				counts[queryLogRollupKey{bucket: bucket, dimension: queryLogRollupBlockedSource, value: source}]++
			}
			if len(event.Decision.PolicySources) == 1 {
				counts[queryLogRollupKey{bucket: bucket, dimension: queryLogRollupBlockedSoleSource, value: event.Decision.PolicySources[0]}]++
			}
		}
	}
	return sortedRollups(counts)
}

// countAppEvent adds one query to the app dimensions: its failure by name, and
// its app, when the catalog names one, by client.
func countAppEvent(counts map[queryLogRollupKey]uint64, bucket time.Time, client, domain string, event querylog.Event) {
	if event.Failed() {
		counts[queryLogRollupKey{bucket: bucket, dimension: queryLogRollupFailed, value: domain}]++
	}
	service, found := services.Lookup(domain)
	if !found {
		return
	}
	value := appClientValue(service.ID, client)
	counts[queryLogRollupKey{bucket: bucket, dimension: queryLogRollupAppClient, value: value}]++
	if event.Failed() {
		counts[queryLogRollupKey{bucket: bucket, dimension: queryLogRollupAppClientFailed, value: value}]++
	}
	if event.Source == querylog.SourceBlocked {
		counts[queryLogRollupKey{bucket: bucket, dimension: queryLogRollupAppClientBlocked, value: value}]++
	}
}

// sortedRollups lists counts in bucket, dimension, and value order.
func sortedRollups(counts map[queryLogRollupKey]uint64) []queryLogRollup {
	rollups := make([]queryLogRollup, 0, len(counts))
	for key, hits := range counts {
		rollups = append(rollups, queryLogRollup{queryLogRollupKey: key, hits: hits})
	}
	sort.Slice(rollups, func(left, right int) bool {
		if !rollups[left].bucket.Equal(rollups[right].bucket) {
			return rollups[left].bucket.Before(rollups[right].bucket)
		}
		if rollups[left].dimension != rollups[right].dimension {
			return rollups[left].dimension < rollups[right].dimension
		}
		return rollups[left].value < rollups[right].value
	})
	return rollups
}

func (store *Store) upsertQueryLogRollups(ctx context.Context, transaction *sql.Tx, rollups []queryLogRollup) error {
	return store.writeRollupRows(ctx, transaction, rollups, "sable_query_log_rollup.hits + excluded.hits")
}

// replaceQueryLogRollups writes counts that already cover whole minutes, such
// as ones recounted from the raw log, over whatever those minutes held.
func (store *Store) replaceQueryLogRollups(ctx context.Context, transaction *sql.Tx, rollups []queryLogRollup) error {
	return store.writeRollupRows(ctx, transaction, rollups, "excluded.hits")
}

func (store *Store) writeRollupRows(ctx context.Context, transaction *sql.Tx, rollups []queryLogRollup, hits string) error {
	if len(rollups) == 0 {
		return nil
	}
	arguments := make([]any, 0, len(rollups)*4)
	values := make([]string, 0, len(rollups))
	for _, rollup := range rollups {
		placeholders := make([]string, 4)
		for index := range placeholders {
			placeholders[index] = store.placeholder(len(arguments) + index + 1)
		}
		values = append(values, "("+strings.Join(placeholders, ", ")+")")
		arguments = append(arguments, rollup.bucket, rollup.dimension, rollup.value, rollup.hits)
	}
	statement := `INSERT INTO sable_query_log_rollup (bucket_start, dimension, value, hits) VALUES ` +
		strings.Join(values, ", ") + `
ON CONFLICT (bucket_start, dimension, value) DO UPDATE
SET hits = ` + hits
	if _, err := transaction.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("upsert query log rollups: %w", err)
	}
	return nil
}
