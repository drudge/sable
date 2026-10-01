package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The query log search index lets a search for text inside a domain, client
// address, or answer use an index instead of reading every row. A month of
// queries on a busy network is millions of rows, and reading all of them took
// seconds, worst for a term that matched nothing. It is a trigram index: it
// matches any run of three or more characters, which is what a substring
// search needs.
//
// On SQLite it is an FTS5 table with the trigram tokenizer that stores no
// copy of the text. Each batch the log writes is indexed in the same
// transaction with one statement; indexing row by row, as triggers would,
// cost several times more because the index reorganizes after every write.
// Pruning leaves the index alone, since deleting from it row by row held the
// log's write lock for seconds. Searches join the index to the log, so an
// entry for a pruned row never shows, and a background pass clears those
// entries in small batches. On PostgreSQL it is pg_trgm GIN indexes on the
// same columns, which the planner uses for the LIKE searches by itself.
const (
	queryLogSearchTable = "sable_query_log_search"
	// queryLogSearchPendingKey holds the range of query log IDs that were
	// written while there was no index, such as the log from before an
	// upgrade, as "after:through". Searches read the whole log until they are
	// indexed.
	queryLogSearchPendingKey = "query_log_search_pending"
	// queryLogSearchClearedKey holds the ID below which the index has no
	// entries for pruned rows left.
	queryLogSearchClearedKey = "query_log_search_cleared_below"
	// queryLogSearchBatch is how many IDs one background transaction covers,
	// so the log's own writes never wait long behind it.
	queryLogSearchBatch = 5_000
	// minimumIndexedSearch is the shortest text a trigram index can find.
	minimumIndexedSearch = 3
)

// queryLogSearchColumns are the index's columns for the log's.
var queryLogSearchColumns = map[string]string{
	queryLogDomainExpression: "domain",
	"client_ip_key":          "client",
	"answer":                 "answers",
}

const queryLogSearchInsert = "INSERT INTO " + queryLogSearchTable + ` (rowid, domain, client, answers)
SELECT id, name_key, client_ip_key, LOWER(answer) FROM sable_query_log WHERE id > ? AND id <= ?`

func (store *Store) migrateQueryLogSearch(ctx context.Context) error {
	if store.driver != "sqlite" {
		// PostgreSQL builds its indexes in the background; see
		// BuildQueryLogSearch.
		return nil
	}
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin query log search index: %w", err)
	}
	defer transaction.Rollback()
	var existing int
	if err := transaction.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", queryLogSearchTable,
	).Scan(&existing); err != nil {
		return fmt.Errorf("inspect query log search index: %w", err)
	}
	var newest sql.NullInt64
	if err := transaction.QueryRowContext(ctx, "SELECT MAX(id) FROM sable_query_log").Scan(&newest); err != nil {
		return fmt.Errorf("find the newest query log row: %w", err)
	}
	// Rows above the newest one indexed were written without the index: the
	// whole log on the upgrade that adds it, or what an older Sable wrote
	// after a downgrade.
	indexedThrough := int64(0)
	if existing == 0 {
		if _, err := transaction.ExecContext(ctx, `
CREATE VIRTUAL TABLE `+queryLogSearchTable+` USING fts5(
    domain, client, answers,
    content='', contentless_delete=1, tokenize='trigram'
)`); err != nil {
			return fmt.Errorf("create query log search index: %w", err)
		}
	} else {
		var highest sql.NullInt64
		if err := transaction.QueryRowContext(ctx,
			"SELECT rowid FROM "+queryLogSearchTable+" ORDER BY rowid DESC LIMIT 1",
		).Scan(&highest); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("find the newest indexed row: %w", err)
		}
		indexedThrough = highest.Int64
	}
	after, through, pending, err := queryLogSearchPendingIn(ctx, transaction)
	if err != nil {
		return err
	}
	if newest.Int64 > indexedThrough {
		// A gap still waiting from an earlier start is widened, not lost.
		if !pending {
			after = indexedThrough
		}
		after, through, pending = min(after, indexedThrough), max(through, newest.Int64), true
		if _, err := transaction.ExecContext(ctx,
			"INSERT INTO sable_metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
			queryLogSearchPendingKey, formatQueryLogSearchRange(after, through),
		); err != nil {
			return fmt.Errorf("record query log rows to index: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit query log search index: %w", err)
	}
	store.searchIndexed.Store(!pending)
	return nil
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, arguments ...any) *sql.Row
}

func queryLogSearchPendingIn(ctx context.Context, database queryRower) (int64, int64, bool, error) {
	var raw string
	err := database.QueryRowContext(ctx, "SELECT value FROM sable_metadata WHERE key = ?", queryLogSearchPendingKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, fmt.Errorf("read %s: %w", queryLogSearchPendingKey, err)
	}
	afterText, throughText, found := strings.Cut(raw, ":")
	after, afterErr := strconv.ParseInt(afterText, 10, 64)
	through, throughErr := strconv.ParseInt(throughText, 10, 64)
	if !found || afterErr != nil || throughErr != nil {
		return 0, 0, false, fmt.Errorf("parse %s %q", queryLogSearchPendingKey, raw)
	}
	return after, through, true, nil
}

func formatQueryLogSearchRange(after, through int64) string {
	return strconv.FormatInt(after, 10) + ":" + strconv.FormatInt(through, 10)
}

// indexQueryLogBatch indexes the rows a write just added, in its transaction.
func (store *Store) indexQueryLogBatch(ctx context.Context, transaction *sql.Tx, first, last int64) error {
	if store.driver != "sqlite" || last < first {
		return nil
	}
	if _, err := transaction.ExecContext(ctx, queryLogSearchInsert, first-1, last); err != nil {
		return fmt.Errorf("index query log batch: %w", err)
	}
	return nil
}

// BuildQueryLogSearch indexes the rows written while there was no index,
// clears the entries of rows pruned since the last pass, and reports whether
// it indexed anything. It runs in the background: on SQLite at start and then
// every so often, on PostgreSQL once per start to build the trigram indexes.
func (store *Store) BuildQueryLogSearch(ctx context.Context) (bool, error) {
	if store.driver == "postgres" {
		return store.buildPostgresQueryLogSearch(ctx)
	}
	built, err := store.indexPendingQueryLog(ctx)
	if err != nil {
		return built, err
	}
	return built, store.clearPrunedQueryLogSearch(ctx)
}

func (store *Store) indexPendingQueryLog(ctx context.Context) (bool, error) {
	after, through, pending, err := queryLogSearchPendingIn(ctx, store.database)
	if err != nil || !pending {
		return false, err
	}
	var oldest sql.NullInt64
	if err := store.database.QueryRowContext(ctx, "SELECT MIN(id) FROM sable_query_log").Scan(&oldest); err != nil {
		return false, fmt.Errorf("find the oldest query log row: %w", err)
	}
	// Newest first: a search that reaches the index soon after an upgrade
	// mostly wants recent rows. Nothing below the oldest row is left to do.
	floor := max(after, oldest.Int64-1)
	for through > floor {
		if err := ctx.Err(); err != nil {
			return true, err
		}
		below := max(through-queryLogSearchBatch, floor)
		if err := store.indexPendingRange(ctx, after, below, through); err != nil {
			return true, err
		}
		through = below
	}
	if _, err := store.database.ExecContext(ctx, "DELETE FROM sable_metadata WHERE key = ?", queryLogSearchPendingKey); err != nil {
		return true, fmt.Errorf("finish query log search index: %w", err)
	}
	store.searchIndexed.Store(true)
	return true, nil
}

// indexPendingRange indexes the rows with IDs above below and up to through,
// and records that the pending range now ends at below. Entries already in
// the range, left by a pass a downgrade interrupted, are replaced.
func (store *Store) indexPendingRange(ctx context.Context, after, below, through int64) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin query log search batch: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, "DELETE FROM "+queryLogSearchTable+" WHERE rowid > ? AND rowid <= ?", below, through); err != nil {
		return fmt.Errorf("replace indexed query log rows: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, queryLogSearchInsert, below, through); err != nil {
		return fmt.Errorf("index query log rows: %w", err)
	}
	if _, err := transaction.ExecContext(ctx,
		"UPDATE sable_metadata SET value = ? WHERE key = ?", formatQueryLogSearchRange(after, below), queryLogSearchPendingKey,
	); err != nil {
		return fmt.Errorf("record query log search progress: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit query log search batch: %w", err)
	}
	return nil
}

// clearPrunedQueryLogSearch deletes the index entries of rows the log no
// longer has, a batch at a time.
func (store *Store) clearPrunedQueryLogSearch(ctx context.Context) error {
	var oldest sql.NullInt64
	if err := store.database.QueryRowContext(ctx, "SELECT MIN(id) FROM sable_query_log").Scan(&oldest); err != nil {
		return fmt.Errorf("find the oldest query log row: %w", err)
	}
	var raw string
	err := store.database.QueryRowContext(ctx, "SELECT value FROM sable_metadata WHERE key = ?", queryLogSearchClearedKey).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read %s: %w", queryLogSearchClearedKey, err)
	}
	cleared, _ := strconv.ParseInt(raw, 10, 64)
	// Nothing lies below the lowest entry, however long the log has been
	// pruned before.
	var lowest, highest sql.NullInt64
	for _, query := range []struct {
		order  string
		target *sql.NullInt64
	}{{"ASC", &lowest}, {"DESC", &highest}} {
		if err := store.database.QueryRowContext(ctx,
			"SELECT rowid FROM "+queryLogSearchTable+" ORDER BY rowid "+query.order+" LIMIT 1",
		).Scan(query.target); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("find the indexed rows: %w", err)
		}
	}
	if !lowest.Valid {
		return nil
	}
	cleared = max(cleared, lowest.Int64)
	// An empty log has nothing left to keep, so everything indexed goes.
	keepFrom := oldest.Int64
	if !oldest.Valid {
		keepFrom = highest.Int64 + 1
	}
	for cleared < keepFrom {
		if err := ctx.Err(); err != nil {
			return err
		}
		next := min(cleared+queryLogSearchBatch, keepFrom)
		transaction, err := store.database.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin clearing pruned query log search entries: %w", err)
		}
		if _, err := transaction.ExecContext(ctx,
			"DELETE FROM "+queryLogSearchTable+" WHERE rowid >= ? AND rowid < ?", cleared, next,
		); err != nil {
			transaction.Rollback()
			return fmt.Errorf("clear pruned query log search entries: %w", err)
		}
		if _, err := transaction.ExecContext(ctx,
			"INSERT INTO sable_metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
			queryLogSearchClearedKey, strconv.FormatInt(next, 10),
		); err != nil {
			transaction.Rollback()
			return fmt.Errorf("record cleared query log search entries: %w", err)
		}
		if err := transaction.Commit(); err != nil {
			return fmt.Errorf("commit clearing pruned query log search entries: %w", err)
		}
		cleared = next
	}
	return nil
}

// postgresQueryLogSearchIndexes are the pg_trgm indexes behind the query log
// search. They cover the same expressions the search compares.
var postgresQueryLogSearchIndexes = [][2]string{
	{"sable_query_log_name_trgm_idx", "name_key gin_trgm_ops"},
	{"sable_query_log_client_trgm_idx", "client_ip_key gin_trgm_ops"},
	{"sable_query_log_answer_trgm_idx", "(LOWER(answer)) gin_trgm_ops"},
}

// buildPostgresQueryLogSearch builds the pg_trgm indexes without locking the
// log against writes. A database where the extension can't be enabled keeps
// reading the whole log, as before.
func (store *Store) buildPostgresQueryLogSearch(ctx context.Context) (bool, error) {
	// Once per start: the indexes keep themselves current, and a database
	// without pg_trgm would say so again at every pass.
	if !store.postgresSearchTried.CompareAndSwap(false, true) {
		return false, nil
	}
	if _, err := store.database.ExecContext(ctx, "CREATE EXTENSION IF NOT EXISTS pg_trgm"); err != nil {
		return false, fmt.Errorf("enable pg_trgm for query log search: %w", err)
	}
	built := false
	for _, index := range postgresQueryLogSearchIndexes {
		// A build that was interrupted leaves an invalid index behind,
		// which IF NOT EXISTS would keep forever.
		var valid bool
		err := store.database.QueryRowContext(ctx, `
SELECT index_state.indisvalid FROM pg_index index_state
JOIN pg_class index_class ON index_class.oid = index_state.indexrelid
WHERE index_class.relname = $1 AND index_class.relnamespace = to_regnamespace(current_schema())`, index[0]).Scan(&valid)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return built, fmt.Errorf("inspect %s: %w", index[0], err)
		case valid:
			continue
		default:
			if _, err := store.database.ExecContext(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+index[0]); err != nil {
				return built, fmt.Errorf("drop unfinished %s: %w", index[0], err)
			}
		}
		if _, err := store.database.ExecContext(ctx,
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS "+index[0]+" ON sable_query_log USING gin ("+index[1]+")",
		); err != nil {
			return built, fmt.Errorf("build %s: %w", index[0], err)
		}
		built = true
	}
	return built, nil
}

// textMatch is text to find anywhere in one query log column, in the form
// that column stores it.
type textMatch struct {
	column string
	text   string
}

// indexedTextSearch is the FTS5 expression that finds rows matching every
// group of text searches, where a group matches when any of its columns
// holds its text. It reports false when the index can't answer: it isn't
// complete yet, or a text is too short for trigrams.
func (store *Store) indexedTextSearch(groups [][]textMatch) (string, bool) {
	if len(groups) == 0 || store.driver != "sqlite" || !store.searchIndexed.Load() {
		return "", false
	}
	clauses := make([]string, 0, len(groups))
	for _, group := range groups {
		phrases := make([]string, 0, len(group))
		for _, match := range group {
			if utf8.RuneCountInString(match.text) < minimumIndexedSearch {
				return "", false
			}
			phrases = append(phrases, "{"+queryLogSearchColumns[match.column]+"}: "+ftsPhrase(match.text))
		}
		// The same text in every column is one phrase over the whole row,
		// which reads each match once instead of once per column.
		if len(group) == len(queryLogSearchColumns) && sameText(group) {
			phrases = []string{ftsPhrase(group[0].text)}
		}
		clauses = append(clauses, "("+strings.Join(phrases, " OR ")+")")
	}
	return strings.Join(clauses, " AND "), true
}

func sameText(group []textMatch) bool {
	for _, match := range group[1:] {
		if match.text != group[0].text {
			return false
		}
	}
	return true
}

// likeTextSearch is the condition that finds a group of text searches by
// reading each row, with its arguments. PostgreSQL's trigram indexes serve
// it there.
func (store *Store) likeTextSearch(firstPlaceholder int, group []textMatch) (string, []any) {
	conditions := make([]string, 0, len(group))
	arguments := make([]any, 0, len(group))
	for index, match := range group {
		column := match.column
		if column == "answer" {
			column = "LOWER(answer)"
		}
		conditions = append(conditions, column+" LIKE "+store.placeholder(firstPlaceholder+index))
		arguments = append(arguments, "%"+match.text+"%")
	}
	if len(conditions) == 1 {
		return conditions[0], arguments
	}
	return "(" + strings.Join(conditions, " OR ") + ")", arguments
}

// ftsPhrase quotes text as one FTS5 phrase, so its punctuation, such as the
// dots and colons in names and addresses, is matched rather than parsed.
func ftsPhrase(text string) string {
	return `"` + strings.ReplaceAll(text, `"`, `""`) + `"`
}
