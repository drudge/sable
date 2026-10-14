package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/drudge/sable/internal/querylog"
)

type Store struct {
	database *sql.DB
	driver   string
	// trackingOff stops client sightings and identities from being recorded
	// while Insights is off.
	trackingOff atomic.Bool
	// searchIndexed reports that the SQLite query log search index covers
	// the whole log; see query_log_search.go.
	searchIndexed atomic.Bool
	// postgresSearchTried keeps the PostgreSQL trigram indexes to one
	// attempt per start.
	postgresSearchTried atomic.Bool
	// pruneChunk overrides how many rows one prune statement deletes; zero
	// means pruneChunkRows. Tests set it to force several chunks.
	pruneChunk int
	// exactCountRows overrides how large the query log may be before an
	// unfiltered count is estimated; zero means exactCountRowsLimit.
	exactCountRows int
	// queryLogRows is the query log's row count as of its last prune; see
	// queryLogCount.
	queryLogRows queryLogCount
}

const maximumRecentQueryEvents = 1_000

func Open(ctx context.Context, driver, dsn string) (*Store, error) {
	databaseDriver, err := databaseDriverName(driver)
	if err != nil {
		return nil, err
	}
	if driver == "sqlite" {
		if err := prepareSQLitePath(dsn); err != nil {
			return nil, err
		}
		dsn = sqliteDSN(dsn)
	}
	database, err := sql.Open(databaseDriver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", driver, err)
	}
	store := &Store{database: database, driver: driver}
	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("ping %s database: %w", driver, err)
	}
	if err := store.migrate(ctx); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) Close() error {
	return store.database.Close()
}

func (store *Store) Driver() string {
	return store.driver
}

// sqlitePragmas are the settings every connection to the database needs. Only
// journal_mode is a property of the file; busy_timeout and foreign_keys belong
// to a connection and start at their defaults on each new one.
var sqlitePragmas = [][2]string{
	{"journal_mode", "WAL"},
	{"busy_timeout", "5000"},
	{"foreign_keys", "1"},
}

// sqliteDSN carries the pragmas on the connection string. Running them once
// against the pool only reaches whichever connection happened to serve them,
// and database/sql opens more on demand: those arrived with busy_timeout at
// zero, so a writer that met another writer failed immediately with
// SQLITE_BUSY instead of waiting for the lock, and foreign keys went
// unenforced. The driver applies DSN pragmas to every connection it opens.
// Anything the operator configured already wins, under either the _pragma form
// or the driver's shorthand keys.
//
// Transactions begin IMMEDIATE. A DEFERRED transaction that reads first and
// writes later cannot wait for the write lock: WAL mode answers its upgrade
// with SQLITE_BUSY at once, whatever busy_timeout says. Taking the lock at
// BEGIN makes every writer wait its turn under busy_timeout instead.
func sqliteDSN(dsn string) string {
	query := ""
	if separator := strings.IndexByte(dsn, '?'); separator >= 0 {
		query = dsn[separator+1:]
	}
	configured, err := url.ParseQuery(query)
	if err != nil {
		configured = nil
	}
	settings := make([]string, 0, len(sqlitePragmas))
	for _, pragma := range sqlitePragmas {
		if sqlitePragmaConfigured(configured, pragma[0]) {
			continue
		}
		settings = append(settings, "_pragma="+url.QueryEscape(pragma[0]+"("+pragma[1]+")"))
	}
	if !configured.Has("_txlock") {
		settings = append(settings, "_txlock=immediate")
	}
	if len(settings) == 0 {
		return dsn
	}
	if query != "" {
		return dsn + "&" + strings.Join(settings, "&")
	}
	return dsn + "?" + strings.Join(settings, "&")
}

// sqlitePragmaShorthand maps a pragma to the driver's mattn-compatible keys for
// it, so a DSN that sets one of those is left alone.
var sqlitePragmaShorthand = map[string][]string{
	"journal_mode": {"_journal_mode", "_journal"},
	"busy_timeout": {"_busy_timeout", "_timeout"},
	"foreign_keys": {"_foreign_keys", "_fk"},
}

func sqlitePragmaConfigured(configured url.Values, name string) bool {
	for _, key := range sqlitePragmaShorthand[name] {
		if configured.Has(key) {
			return true
		}
	}
	for _, pragma := range configured["_pragma"] {
		setting, _, _ := strings.Cut(pragma, "(")
		setting, _, _ = strings.Cut(setting, "=")
		if strings.EqualFold(strings.TrimSpace(setting), name) {
			return true
		}
	}
	return false
}

// WriteQueryEvents stores a batch in one transaction. A batch that meets
// SQLITE_BUSY after busy_timeout runs out is retried once, since a failed
// batch is dropped by the recorder.
func (store *Store) WriteQueryEvents(ctx context.Context, events []querylog.Event) error {
	if len(events) == 0 {
		return nil
	}
	err := store.writeQueryEvents(ctx, events)
	if store.driver == "sqlite" && sqliteBusy(err) && ctx.Err() == nil {
		err = store.writeQueryEvents(ctx, events)
	}
	return err
}

func (store *Store) writeQueryEvents(ctx context.Context, events []querylog.Event) error {
	return store.withTx(ctx, "query log batch", func(transaction *sql.Tx) error {
		statement, err := transaction.PrepareContext(ctx, store.queryLogInsert())
		if err != nil {
			return fmt.Errorf("prepare query log insert: %w", err)
		}
		defer statement.Close()
		var first, last int64
		for index, event := range events {
			decision, err := json.Marshal(event.Decision)
			if err != nil {
				return fmt.Errorf("encode query decision: %w", err)
			}
			result, err := statement.ExecContext(
				ctx,
				event.OccurredAt.UTC(),
				event.ClientIP,
				queryLogClientKey(event.ClientIP),
				event.Name,
				queryLogDomainKey(event.Name),
				event.RecordType,
				event.Class,
				event.ResponseCode,
				event.Source,
				event.Protocol,
				event.Answer,
				string(decision),
				event.Duration.Microseconds(),
			)
			if err != nil {
				return fmt.Errorf("insert query log event: %w", err)
			}
			if store.driver == "sqlite" {
				if last, err = result.LastInsertId(); err != nil {
					return fmt.Errorf("read query log event ID: %w", err)
				}
				if index == 0 {
					first = last
				}
			}
		}
		if err := store.indexQueryLogBatch(ctx, transaction, first, last); err != nil {
			return err
		}
		if err := store.writeQueryLogRollups(ctx, transaction, events); err != nil {
			return err
		}
		if err := store.writeClientSightings(ctx, transaction, events); err != nil {
			return err
		}
		return nil
	})
}

// PruneQueryEvents removes query log history from before the cutoff: the raw
// rows, the minute rollups and their tiers, and client sightings. Each table is
// pruned on its own, in chunks that each commit on their own, so a large
// backlog never holds the write lock for long and never meets one statement
// timeout. The query log writer lands its batches between chunks.
func (store *Store) PruneQueryEvents(ctx context.Context, before time.Time) error {
	before = before.UTC()
	deleted, err := store.deleteInChunks(ctx, "sable_query_log", "occurred_at < "+store.placeholder(1), before)
	if err != nil {
		store.queryLogRows.forget()
		return fmt.Errorf("prune query log: %w", err)
	}
	counted := store.queryLogRows.pruned(deleted)
	// Drop the cutoff minute as well because its aggregate can include rows
	// from before the exact cutoff. Surviving rows in that partial minute remain
	// available through the raw log boundary query.
	bucket := before.Truncate(time.Minute)
	if _, err := store.deleteInChunks(ctx, minuteRollupTable, "bucket_start <= "+store.placeholder(1), bucket); err != nil {
		return fmt.Errorf("prune query log rollups: %w", err)
	}
	if err := store.pruneRollupTiers(ctx, bucket); err != nil {
		return err
	}
	if err := store.pruneClientSightings(ctx, before); err != nil {
		return err
	}
	// The count only sharpens the Logs tab's estimate, so it comes last, where
	// a count that fails can't hold back the rest of retention.
	if !counted {
		return store.queryLogRows.count(ctx, store)
	}
	return nil
}

const (
	// pruneChunkRows is how many rows one prune statement deletes.
	pruneChunkRows = 5_000
	// pruneChunkTimeout bounds one chunk rather than a whole prune, so a
	// backlog of any size finishes as long as each chunk does.
	pruneChunkTimeout = 30 * time.Second
)

// deleteInChunks deletes the rows of table that match condition, at most
// pruneChunkRows at a time, each chunk in its own statement and transaction,
// and says how many it deleted.
// Rows are picked by their physical key: on SQLite the rowid, which is the
// query log's id, and on PostgreSQL the ctid, which the ANY(ARRAY(...)) form
// turns into a direct tuple lookup instead of a scan.
func (store *Store) deleteInChunks(ctx context.Context, table, condition string, arguments ...any) (int64, error) {
	chunk := store.pruneChunk
	if chunk <= 0 {
		chunk = pruneChunkRows
	}
	limit := " WHERE " + condition + " LIMIT " + strconv.Itoa(chunk)
	statement := "DELETE FROM " + table + " WHERE rowid IN (SELECT rowid FROM " + table + limit + ")"
	if store.driver == "postgres" {
		statement = "DELETE FROM " + table + " WHERE ctid = ANY(ARRAY(SELECT ctid FROM " + table + limit + "))"
	}
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		chunkContext, cancel := context.WithTimeout(ctx, pruneChunkTimeout)
		result, err := store.database.ExecContext(chunkContext, statement, arguments...)
		cancel()
		if err != nil {
			return total, err
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return total, err
		}
		total += deleted
		if deleted < int64(chunk) {
			return total, nil
		}
	}
}

func (store *Store) RecentQueryEvents(ctx context.Context, limit int) ([]querylog.Entry, error) {
	if limit <= 0 {
		return []querylog.Entry{}, nil
	}
	limit = min(limit, maximumRecentQueryEvents)
	rows, err := store.database.QueryContext(ctx, `
SELECT id, occurred_at, client_ip, name, record_type, class, response_code, source, protocol, answer, decision, duration_us
FROM sable_query_log
ORDER BY id DESC
LIMIT `+store.placeholder(1), limit)
	if err != nil {
		return nil, fmt.Errorf("read recent query events: %w", err)
	}
	defer rows.Close()
	return scanQueryEvents(rows, limit)
}

func (store *Store) QueryEvents(ctx context.Context, filter querylog.Filter) (querylog.Page, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 {
		filter.PageSize = 50
	}
	filter.PageSize = min(filter.PageSize, 250)

	scope := store.queryEventScope(filter)
	total, estimated, err := store.countQueryEvents(ctx, scope, filter)
	if err != nil {
		return querylog.Page{}, err
	}
	// An estimated total can run high or low, so paging older by cursor
	// reads one row past the page to learn whether an older page exists,
	// rather than trusting the page count.
	lookAhead := estimated && filter.Direction == "older" && filter.Cursor > 0
	totalPages := 0
	if total > 0 {
		totalPages = (total + filter.PageSize - 1) / filter.PageSize
		if !lookAhead {
			filter.Page = min(filter.Page, totalPages)
		}
	}
	read := filter
	if lookAhead {
		read.PageSize++
	}
	entries, err := store.selectQueryEvents(ctx, scope, read, total, estimated)
	if err != nil {
		return querylog.Page{}, err
	}
	if lookAhead {
		switch {
		case len(entries) > filter.PageSize:
			// A low estimate: older rows remain past what the count allows.
			entries = entries[:filter.PageSize]
			totalPages = max(totalPages, filter.Page+1)
		case len(entries) == 0 && filter.Page > 1:
			// A high estimate paged past the oldest row, so the page before
			// was the last; show it again rather than an empty log.
			filter.Page--
			filter.Direction = "oldest"
			if entries, err = store.selectQueryEvents(ctx, scope, filter, total, estimated); err != nil {
				return querylog.Page{}, err
			}
			totalPages = filter.Page
		default:
			totalPages = filter.Page
		}
	}
	return querylog.Page{
		Entries: entries, Page: filter.Page, PageSize: filter.PageSize,
		TotalEntries: total, TotalPages: totalPages, TotalEstimated: estimated,
	}, nil
}

// queryEventScope is the part of a query log query a filter decides: where
// rows come from, the column that orders them, and the conditions on them.
type queryEventScope struct {
	store      *Store
	from       string
	idColumn   string
	conditions []string
	arguments  []any
}

func (scope *queryEventScope) add(column, operator string, value any) {
	scope.arguments = append(scope.arguments, value)
	scope.conditions = append(scope.conditions, column+" "+operator+" "+scope.store.placeholder(len(scope.arguments)))
}

// clone copies the conditions so a count and a page can each add their own.
func (scope queryEventScope) clone() queryEventScope {
	scope.conditions = append([]string(nil), scope.conditions...)
	scope.arguments = append([]any(nil), scope.arguments...)
	return scope
}

func (store *Store) queryEventScope(filter querylog.Filter) queryEventScope {
	scope := queryEventScope{
		store: store, from: " FROM sable_query_log", idColumn: "id",
		conditions: make([]string, 0, 5), arguments: make([]any, 0, 7),
	}
	store.addQueryEventTextSearch(&scope, filter)
	if !filter.Since.IsZero() {
		scope.add("occurred_at", ">=", filter.Since.UTC())
	}
	if !filter.Until.IsZero() {
		scope.add("occurred_at", "<=", filter.Until.UTC())
	}
	if len(filter.RecordTypes) > 0 {
		placeholders := make([]string, 0, len(filter.RecordTypes))
		for _, recordType := range filter.RecordTypes {
			scope.arguments = append(scope.arguments, recordType)
			placeholders = append(placeholders, store.placeholder(len(scope.arguments)))
		}
		scope.conditions = append(scope.conditions, "record_type IN ("+strings.Join(placeholders, ", ")+")")
	}
	if filter.ResponseCode != nil {
		scope.add("response_code", "=", *filter.ResponseCode)
	}
	if filter.Source != "" {
		scope.add("source", "=", filter.Source)
	}
	if filter.Protocol != "" {
		scope.add("protocol", "=", strings.ToUpper(filter.Protocol))
	}
	return scope
}

// addQueryEventTextSearch adds the client, name and free-text parts of a
// filter. Text found anywhere in a column, as opposed to an exact value,
// comes from the search index when it can; see query_log_search.go.
func (store *Store) addQueryEventTextSearch(scope *queryEventScope, filter querylog.Filter) {
	var textSearches [][]textMatch
	if value := strings.TrimSpace(filter.ClientIP); value != "" {
		if filter.Exact || filter.ExactClient {
			scope.add("client_ip_key", "=", queryLogClientKey(value))
		} else {
			textSearches = append(textSearches, []textMatch{{"client_ip_key", queryLogClientKey(value)}})
		}
	}
	if value := strings.TrimSpace(filter.Name); value != "" {
		if filter.Exact {
			scope.add(queryLogDomainExpression, "=", queryLogDomainKey(value))
		} else {
			textSearches = append(textSearches, []textMatch{{queryLogDomainExpression, queryLogDomainKey(value)}})
		}
	}
	if value := strings.ToLower(strings.TrimSpace(filter.Search)); value != "" {
		textSearches = append(textSearches, []textMatch{
			{queryLogDomainExpression, queryLogDomainKey(value)},
			{"client_ip_key", queryLogClientKey(value)},
			{"answer", value},
		})
	}
	if expression, indexed := store.indexedTextSearch(textSearches); indexed {
		// The index leads, so a page stops after its rows and a count reads
		// only the matches. Joining the log leaves out rows pruned since.
		scope.from = " FROM " + queryLogSearchTable + " JOIN sable_query_log ON sable_query_log.id = " + queryLogSearchTable + ".rowid"
		scope.idColumn = queryLogSearchTable + ".rowid"
		scope.add(queryLogSearchTable, "MATCH", expression)
		return
	}
	for _, matches := range textSearches {
		condition, values := store.likeTextSearch(len(scope.arguments)+1, matches)
		scope.conditions = append(scope.conditions, condition)
		scope.arguments = append(scope.arguments, values...)
	}
}

// countQueryEvents returns how many rows the filter matches. A caller that
// already knows the total skips the count, and an incremental refresh counts
// only the rows after the last one it saw. An unfiltered count of a large log
// the caller lets be estimated comes from the ID span; see
// estimateQueryEvents.
func (store *Store) countQueryEvents(ctx context.Context, scope queryEventScope, filter querylog.Filter) (int, bool, error) {
	total := filter.KnownTotal
	if filter.UseKnownTotal && !filter.Incremental {
		return total, filter.KnownTotalEstimated, nil
	}
	if filter.EstimateTotal && !filter.Incremental && len(scope.conditions) == 0 {
		span, err := store.estimateQueryEvents(ctx)
		if err != nil {
			return 0, false, err
		}
		limit := store.exactCountRows
		if limit <= 0 {
			limit = exactCountRowsLimit
		}
		if span > limit {
			return span, true, nil
		}
	}
	count := scope.clone()
	if filter.Incremental {
		count.add(count.idColumn, ">", filter.AfterID)
	}
	var counted int
	if err := store.database.QueryRowContext(ctx, "SELECT COUNT(*)"+count.from+queryLogWhere(count.conditions), count.arguments...).Scan(&counted); err != nil {
		return 0, false, fmt.Errorf("count query events: %w", err)
	}
	if filter.Incremental {
		return total + counted, filter.KnownTotalEstimated, nil
	}
	return counted, false, nil
}

// exactCountRowsLimit is the most rows an unfiltered count reads. Counting
// this many takes about a millisecond warm and tens cold; past it the span of
// IDs stands in, since a month of a busy network's queries takes seconds to
// count from a cold disk.
const exactCountRowsLimit = 50_000

// queryLogSpanQuery reads the query log's lowest and highest IDs. Each end is
// its own subquery: SQLite answers a lone MIN or MAX from the end of the
// primary key, but scans every row when one SELECT asks for both.
const queryLogSpanQuery = "SELECT (SELECT MIN(id) FROM sable_query_log), (SELECT MAX(id) FROM sable_query_log)"

// estimateQueryEvents sizes the whole log from its lowest and highest IDs.
// An exact COUNT(*) reads every row on both SQLite and PostgreSQL, which on a
// month of a busy network's queries is most of the Logs page's time; the ends
// of the primary key are two index seeks. IDs only ever grow, and pruning
// deletes from the old end, so the span is the row count apart from the few
// rows a prune leaves behind out of order and any IDs a PostgreSQL sequence
// skipped: it can run high, never low.
//
// The span also counts every row a prune leaves a hole for, so once the log
// has been counted the estimate is the smaller of the span and that count
// plus the IDs written since; see queryLogCount.
func (store *Store) estimateQueryEvents(ctx context.Context) (int, error) {
	var oldest, newest sql.NullInt64
	if err := store.database.QueryRowContext(ctx, queryLogSpanQuery).Scan(&oldest, &newest); err != nil {
		return 0, fmt.Errorf("estimate query events: %w", err)
	}
	if !oldest.Valid || !newest.Valid {
		return 0, nil
	}
	span := int(newest.Int64 - oldest.Int64 + 1)
	if counted, ok := store.queryLogRows.since(newest.Int64); ok {
		return min(span, counted), nil
	}
	return span, nil
}

// queryLogCount carries an exact count of the query log between prunes, the
// way Pi-hole's FTL keeps its totals in memory rather than counting its
// database. The first prune after start counts the log once, in the
// background where a cold count's seconds cost nobody a page load; each later
// prune subtracts the rows it deleted, and rows written since are the IDs
// past the newest one counted. Writes the count doesn't see, such as another
// node pruning a shared PostgreSQL log, leave it high, as the span is, so the
// estimate takes the smaller of the two. On PostgreSQL it can also run a few
// rows low: a row whose sequence ID was taken before the count but committed
// after it is in neither the count nor the IDs past it. Either way the total
// is shown as an estimate.
type queryLogCount struct {
	mutex    sync.Mutex
	known    bool
	rows     int
	newestID int64
}

// queryLogCountQuery counts the log and reads its newest ID in one statement,
// so both come from the same snapshot.
const queryLogCountQuery = "SELECT COUNT(*), COALESCE(MAX(id), 0) FROM sable_query_log"

// pruned takes a prune's deletions off the count and says whether there was
// one to take them off; if not, the caller counts the log.
func (count *queryLogCount) pruned(deleted int64) bool {
	count.mutex.Lock()
	defer count.mutex.Unlock()
	if count.known {
		count.rows = max(count.rows-int(deleted), 0)
	}
	return count.known
}

// count counts the log and reads its newest ID.
func (count *queryLogCount) count(ctx context.Context, store *Store) error {
	var rows int
	var newestID int64
	if err := store.database.QueryRowContext(ctx, queryLogCountQuery).Scan(&rows, &newestID); err != nil {
		return fmt.Errorf("count query log: %w", err)
	}
	count.mutex.Lock()
	count.known, count.rows, count.newestID = true, rows, newestID
	count.mutex.Unlock()
	return nil
}

// forget drops the count after a prune that may have deleted rows it can't
// say how many of, so the next prune counts again.
func (count *queryLogCount) forget() {
	count.mutex.Lock()
	count.known = false
	count.mutex.Unlock()
}

// since returns the count for a log whose newest ID is newestID. A newest ID
// below the one counted means the log was replaced, so the count no longer
// applies.
func (count *queryLogCount) since(newestID int64) (int, bool) {
	count.mutex.Lock()
	defer count.mutex.Unlock()
	if !count.known || newestID < count.newestID {
		return 0, false
	}
	return count.rows + int(newestID-count.newestID), true
}

// selectQueryEvents reads one page, newest first, either by page number or
// relative to a cursor row.
func (store *Store) selectQueryEvents(ctx context.Context, scope queryEventScope, filter querylog.Filter, total int, estimated bool) ([]querylog.Entry, error) {
	page := scope.clone()
	order := "DESC"
	useOffset := false
	switch filter.Direction {
	case "older":
		if filter.Cursor > 0 {
			page.add(page.idColumn, "<", filter.Cursor)
		}
	case "newer":
		if filter.Cursor > 0 {
			page.add(page.idColumn, ">", filter.Cursor)
			order = "ASC"
		}
	case "oldest":
		order = "ASC"
	default:
		useOffset = filter.Page > 1
	}
	selectWhere := queryLogWhere(page.conditions)
	selectionLimit := filter.PageSize
	// An estimated total can't say how short the last page is, so it shows
	// a full page of the oldest rows.
	if filter.Direction == "oldest" && !estimated && total%filter.PageSize != 0 {
		selectionLimit = total % filter.PageSize
	}
	arguments := append(page.arguments, selectionLimit)
	query := `
	SELECT id, occurred_at, client_ip, name, record_type, class, response_code, source, protocol, answer, decision, duration_us
	` + page.from + selectWhere + `
	ORDER BY ` + page.idColumn + ` ` + order + `
	LIMIT ` + store.placeholder(len(arguments))
	if useOffset {
		arguments = append(arguments, (filter.Page-1)*filter.PageSize)
		query += ` OFFSET ` + store.placeholder(len(arguments))
	}
	rows, err := store.database.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()
	entries, err := scanQueryEvents(rows, selectionLimit)
	if err != nil {
		return nil, err
	}
	if order == "ASC" {
		slices.Reverse(entries)
	}
	return entries, nil
}

// QueryEvent returns the query log row with the given ID, and whether it is
// still in the log.
func (store *Store) QueryEvent(ctx context.Context, id int64) (querylog.Entry, bool, error) {
	rows, err := store.database.QueryContext(ctx, `
	SELECT id, occurred_at, client_ip, name, record_type, class, response_code, source, protocol, answer, decision, duration_us
	FROM sable_query_log WHERE id = `+store.placeholder(1), id)
	if err != nil {
		return querylog.Entry{}, false, fmt.Errorf("query event: %w", err)
	}
	defer rows.Close()
	entries, err := scanQueryEvents(rows, 1)
	if err != nil || len(entries) == 0 {
		return querylog.Entry{}, false, err
	}
	return entries[0], true, nil
}

func queryLogWhere(conditions []string) string {
	if len(conditions) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(conditions, " AND ")
}

func scanQueryEvents(rows *sql.Rows, capacity int) ([]querylog.Entry, error) {
	entries := make([]querylog.Entry, 0, capacity)
	for rows.Next() {
		var entry querylog.Entry
		var source string
		var decision string
		var durationMicroseconds int64
		if err := rows.Scan(
			&entry.ID, &entry.OccurredAt, &entry.ClientIP, &entry.Name,
			&entry.RecordType, &entry.Class, &entry.ResponseCode, &source, &entry.Protocol, &entry.Answer, &decision, &durationMicroseconds,
		); err != nil {
			return nil, fmt.Errorf("scan query event: %w", err)
		}
		entry.Source = querylog.Source(source)
		if err := json.Unmarshal([]byte(decision), &entry.Decision); err != nil {
			return nil, fmt.Errorf("decode query decision: %w", err)
		}
		entry.Duration = time.Duration(durationMicroseconds) * time.Microsecond
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate query events: %w", err)
	}
	return entries, nil
}

func (store *Store) queryLogTable() string {
	primaryKey := "INTEGER PRIMARY KEY AUTOINCREMENT"
	if store.driver == "postgres" {
		primaryKey = "BIGSERIAL PRIMARY KEY"
	}
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS sable_query_log (
    id %s,
	occurred_at TIMESTAMP NOT NULL,
	client_ip TEXT NOT NULL,
	client_ip_key TEXT NOT NULL DEFAULT '',
	name TEXT NOT NULL,
	name_key TEXT NOT NULL DEFAULT '',
    record_type INTEGER NOT NULL,
    class INTEGER NOT NULL,
    response_code INTEGER NOT NULL,
    source TEXT NOT NULL,
	protocol TEXT NOT NULL DEFAULT '',
	answer TEXT NOT NULL DEFAULT '',
	decision TEXT NOT NULL DEFAULT '{}',
    duration_us BIGINT NOT NULL
)`, primaryKey)
}

func (store *Store) queryLogInsert() string {
	if store.driver == "postgres" {
		return `INSERT INTO sable_query_log
(occurred_at, client_ip, client_ip_key, name, name_key, record_type, class, response_code, source, protocol, answer, decision, duration_us)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	}
	return `INSERT INTO sable_query_log
(occurred_at, client_ip, client_ip_key, name, name_key, record_type, class, response_code, source, protocol, answer, decision, duration_us)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
}

// sqliteBusy reports whether err is SQLite's database-locked error, under its
// primary code or any extended one.
func sqliteBusy(err error) bool {
	var sqliteError *sqlite.Error
	return errors.As(err, &sqliteError) && sqliteError.Code()&0xff == sqlite3.SQLITE_BUSY
}

func databaseDriverName(driver string) (string, error) {
	switch driver {
	case "sqlite":
		return "sqlite", nil
	case "postgres":
		return "pgx", nil
	default:
		return "", fmt.Errorf("unsupported database driver %q", driver)
	}
}

func prepareSQLitePath(dsn string) error {
	if dsn == ":memory:" || strings.HasPrefix(dsn, "file:") {
		return nil
	}
	directory := filepath.Dir(dsn)
	if directory == "." {
		return nil
	}
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("create SQLite directory: %w", err)
	}
	return nil
}

func IsBackendChange(activeDriver, activeDSN, candidateDriver, candidateDSN string) error {
	if activeDriver == candidateDriver && activeDSN == candidateDSN {
		return nil
	}
	return errors.New("database driver and DSN changes require a controlled restart")
}
