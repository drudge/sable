package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

const (
	queryLogRollupClient       = "client"
	queryLogRollupDomain       = "domain"
	queryLogRollupBlocked      = "blocked"
	queryLogRollupRecordType   = "record_type"
	queryLogRollupSource       = "source"
	queryLogRollupResponseCode = "response_code"
	queryLogRollupInsertRows   = 128
)

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
		if event.Source == querylog.SourceBlocked {
			counts[queryLogRollupKey{bucket: bucket, dimension: queryLogRollupBlocked, value: domain}]++
		}
	}
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
SET hits = sable_query_log_rollup.hits + excluded.hits`
	if _, err := transaction.ExecContext(ctx, statement, arguments...); err != nil {
		return fmt.Errorf("upsert query log rollups: %w", err)
	}
	return nil
}
