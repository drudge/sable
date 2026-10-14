package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/querylog"
)

// rollupCount is a filter the rollups can count: one dimension and value,
// and the log column and value the same filter tests on a raw row.
type rollupCount struct {
	dimension, value string
	column           string
	raw              any
}

// rollupCountFilter says which rollup counts a filter that narrows the log by
// exactly one thing the rollups count and the log has no index for: the
// source, the response code, or one record type. Any other part of a filter,
// such as a search or a time window, has no rollup to answer it.
func rollupCountFilter(filter querylog.Filter) (rollupCount, bool) {
	if filter.Search != "" || filter.Name != "" || filter.Protocol != "" ||
		!filter.Since.IsZero() || !filter.Until.IsZero() || len(filter.RecordTypes) > 1 {
		return rollupCount{}, false
	}
	// A client has its own index, which counts one as fast as the rollups.
	if strings.TrimSpace(filter.ClientIP) != "" {
		return rollupCount{}, false
	}
	var count rollupCount
	set := 0
	if len(filter.RecordTypes) == 1 {
		recordType := filter.RecordTypes[0]
		count, set = rollupCount{queryLogRollupRecordType, strconv.Itoa(int(recordType)), "record_type", recordType}, set+1
	}
	if filter.ResponseCode != nil {
		code := *filter.ResponseCode
		count, set = rollupCount{queryLogRollupResponseCode, strconv.Itoa(code), "response_code", code}, set+1
	}
	if filter.Source != "" {
		count, set = rollupCount{queryLogRollupSource, string(filter.Source), "source", string(filter.Source)}, set+1
	}
	return count, set == 1
}

// countFromRollups counts a one-dimension filter from the minute rollups and
// their hour and day tiers instead of scanning the log. A filter on a column
// the log has no index for, such as source=blocked, otherwise reads every
// retained row: about 270 ms warm on a month of 5.4M queries, where the
// rollups need a few hundred rows. Rollups are written in the same
// transaction as the rows they count, so the sum is the count. The minutes
// at the old end that a prune or the rollups' arrival left partly counted
// are read from the raw log, as Insights does. Only the moment between a
// prune's deletes from the log and from the rollups can leave it off, so the
// total is still marked an estimate; paging copes with one that runs high or
// low.
// It reports false when the rollups aren't compacted yet or don't reach back
// to the oldest row, as after an upgrade from before rollups, so the caller
// counts the log itself.
func (store *Store) countFromRollups(ctx context.Context, count rollupCount) (int, bool, error) {
	// Until the hour tier fills, every bucket is a minute, and summing a
	// month of them is no faster than counting the log.
	if _, compacted, err := store.tierCoverage(ctx, hourRollupTier); err != nil || !compacted {
		return 0, false, err
	}
	start, covered, err := store.queryLogRollupStart(ctx)
	if err != nil || !covered {
		return 0, false, err
	}
	// Each end is its own subquery so SQLite seeks both ends of the
	// occurred_at index rather than scanning it.
	var rawOldest, rawNewest any
	if err := store.database.QueryRowContext(ctx,
		"SELECT (SELECT MIN(occurred_at) FROM sable_query_log), (SELECT MAX(occurred_at) FROM sable_query_log)",
	).Scan(&rawOldest, &rawNewest); err != nil {
		return 0, false, fmt.Errorf("read query log time span: %w", err)
	}
	if rawOldest == nil || rawNewest == nil {
		return 0, false, nil
	}
	oldest, err := databaseTime(rawOldest)
	if err != nil {
		return 0, false, fmt.Errorf("read query log time span: %w", err)
	}
	newest, err := databaseTime(rawNewest)
	if err != nil {
		return 0, false, fmt.Errorf("read query log time span: %w", err)
	}
	// A prune drops the rollups of its cutoff minute, whose rows can outlive
	// it, so the oldest row may sit one minute before the rollups begin.
	// Anything older predates the rollups and only a count of the log sees it.
	if oldest.UTC().Before(start.Add(-time.Minute)) {
		return 0, false, nil
	}
	fullStart := start.Add(time.Minute)
	spans, err := store.rollupSpans(ctx, fullStart, newest.UTC().Truncate(time.Minute).Add(time.Minute), dayRollupTier.size)
	if err != nil {
		return 0, false, err
	}
	builder := store.newSQLBuilder()
	var statement strings.Builder
	statement.WriteString("SELECT CAST(COALESCE(SUM(hits), 0) AS BIGINT) FROM (\n")
	for _, span := range spans {
		statement.WriteString(`    SELECT hits FROM ` + span.table + `
    WHERE dimension = ` + builder.Bind(count.dimension) + ` AND value = ` + builder.Bind(count.value) + `
      AND bucket_start >= ` + builder.Bind(span.start) + ` AND bucket_start < ` + builder.Bind(span.end) + `
    UNION ALL
`)
	}
	// The raw edge is read by time: an index on the filtered column would
	// walk that value's whole history.
	statement.WriteString(`    SELECT COUNT(*) FROM sable_query_log` + store.queryLogTimeIndex() + `
    WHERE occurred_at < ` + builder.Bind(fullStart) + ` AND ` + count.column + ` = ` + builder.Bind(count.raw) + `
) rolled`)
	var total sql.NullInt64
	if err := store.database.QueryRowContext(ctx, statement.String(), builder.Args()...).Scan(&total); err != nil {
		return 0, false, fmt.Errorf("count query events from rollups: %w", err)
	}
	return int(total.Int64), true, nil
}
