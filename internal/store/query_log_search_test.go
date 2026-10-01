package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/drudge/sable/internal/querylog"
	"github.com/miekg/dns"
)

func searchTestEvents(now time.Time) []querylog.Event {
	event := func(client, name, answer string) querylog.Event {
		return querylog.Event{OccurredAt: now, ClientIP: client, Name: name, RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceUpstream, Protocol: "UDP", Answer: answer}
	}
	return []querylog.Event{
		event("10.0.7.88", "eu.tectonic.remarkable.com.", "A 35.201.126.131"),
		event("2603:7083:af01:1500:4b53:1028:c3bd:115b", "device.cloud.remarkable.com.", "CNAME device.memfault.com. AAAA 2600:1f18:2f7f:7001::1"),
		event("10.0.7.20", "time.apple.com.", "A 17.253.4.125"),
		event("10.0.7.21", `odd"quote.example.`, "A 192.0.2.1"),
		event("10.0.7.22", "ab.example.", "A 192.0.2.2"),
	}
}

// The index finds exactly what reading every row finds, for searches long
// enough to use it and short ones that can't.
func TestQueryLogSearchIndexFindsWhatTheFullReadFinds(t *testing.T) {
	t.Parallel()
	opened := openQueryLogStore(t, searchTestEvents(time.Now().UTC().Truncate(time.Second)))
	if !opened.searchIndexed.Load() {
		t.Fatal("a new database's search index should be ready at once")
	}
	filters := []querylog.Filter{
		{Search: "remarkable"}, {Search: "REMARKABLE.COM."}, {Search: "2603:7083"}, {Search: "35.201"},
		{Search: "memfault"}, {Search: "nowhere"}, {Search: `"quote`}, {Search: "ab"}, {Search: "."},
		{Name: "apple"}, {ClientIP: "10.0.7.2"}, {Search: "remarkable", ClientIP: "10.0.7.88"},
	}
	for _, filter := range filters {
		indexed, err := opened.QueryEvents(context.Background(), filter)
		if err != nil {
			t.Fatalf("indexed %+v: %v", filter, err)
		}
		opened.searchIndexed.Store(false)
		full, err := opened.QueryEvents(context.Background(), filter)
		opened.searchIndexed.Store(true)
		if err != nil {
			t.Fatalf("full read %+v: %v", filter, err)
		}
		if indexed.TotalEntries != full.TotalEntries || len(indexed.Entries) != len(full.Entries) {
			t.Errorf("%+v: index found %d, full read %d", filter, indexed.TotalEntries, full.TotalEntries)
		}
	}
	if expression, indexed := opened.indexedTextSearch([][]textMatch{{{"name_key", "remarkable"}}}); !indexed || expression != `({domain}: "remarkable")` {
		t.Fatalf("a long enough search = %q, %t; want the index", expression, indexed)
	}
	if _, indexed := opened.indexedTextSearch([][]textMatch{{{"name_key", "ab"}}}); indexed {
		t.Fatal("a two-letter search used the index, which can't find it")
	}
	// The same text in every column reads the index once.
	everywhere := []textMatch{{"name_key", "apple"}, {"client_ip_key", "apple"}, {"answer", "apple"}}
	if expression, _ := opened.indexedTextSearch([][]textMatch{everywhere}); expression != `("apple")` {
		t.Fatalf("a search of every column = %q, want one phrase", expression)
	}
}

// A database from before the index gets it on upgrade. Searches read the
// whole log until the rows already there are indexed in the background, and
// rows written or pruned meanwhile stay right.
func TestQueryLogSearchIndexesAnUpgradedLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sable.db")
	opened, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	// More rows than one indexing batch, so the build takes several.
	old := make([]querylog.Event, 0, 2*queryLogSearchBatch+500)
	for index := range cap(old) {
		old = append(old, querylog.Event{
			OccurredAt: now.Add(-time.Duration(cap(old)-index) * time.Second), ClientIP: fmt.Sprintf("10.0.%d.%d", index/250, index%250),
			Name: fmt.Sprintf("host-%d.example.", index), RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceCache, Protocol: "UDP",
			Answer: "A 192.0.2.1",
		})
	}
	old[0].Name, old[len(old)-1].Name = "first.remarkable.com.", "last.remarkable.com."
	if err := opened.WriteQueryEvents(ctx, old); err != nil {
		t.Fatal(err)
	}
	// Take the log back to before the index existed.
	for _, statement := range []string{"DROP TABLE " + queryLogSearchTable} {
		if _, err := opened.database.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	opened.Close()

	upgraded, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	if upgraded.searchIndexed.Load() {
		t.Fatal("the index was used before the existing log was in it")
	}
	count := func(search string) int {
		t.Helper()
		page, err := upgraded.QueryEvents(ctx, querylog.Filter{Search: search})
		if err != nil {
			t.Fatal(err)
		}
		return page.TotalEntries
	}
	if got := count("remarkable"); got != 2 {
		t.Fatalf("before indexing, search found %d, want both old rows", got)
	}
	// A row written and one pruned while the old log waits to be indexed.
	if err := upgraded.WriteQueryEvents(ctx, []querylog.Event{{
		OccurredAt: now, ClientIP: "10.0.7.88", Name: "new.remarkable.com.", RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceUpstream, Protocol: "UDP",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := upgraded.PruneQueryEvents(ctx, old[1].OccurredAt); err != nil {
		t.Fatal(err)
	}

	built, err := upgraded.BuildQueryLogSearch(ctx)
	if err != nil || !built {
		t.Fatalf("BuildQueryLogSearch() = %t, %v", built, err)
	}
	if !upgraded.searchIndexed.Load() {
		t.Fatal("the finished index isn't used")
	}
	if got := count("remarkable"); got != 2 {
		t.Fatalf("after indexing, search found %d, want the newest old row and the new one, not the pruned one", got)
	}
	if got := count(fmt.Sprintf("host-%d.", queryLogSearchBatch+7)); got != 1 {
		t.Fatalf("a row from a middle batch was found %d times, want once", got)
	}
	if again, err := upgraded.BuildQueryLogSearch(ctx); err != nil || again {
		t.Fatalf("a second build = %t, %v; want nothing left to do", again, err)
	}
	var indexed, logged int
	if err := upgraded.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+queryLogSearchTable+" WHERE "+queryLogSearchTable+" MATCH '\"example\" OR \"remarkable\"'").Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if err := upgraded.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM sable_query_log").Scan(&logged); err != nil {
		t.Fatal(err)
	}
	if indexed != logged {
		t.Fatalf("the index holds %d rows, the log %d", indexed, logged)
	}
}

// Rows an older Sable wrote after a downgrade are indexed on the next upgrade.
func TestQueryLogSearchIndexesRowsWrittenWithoutIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sable.db")
	opened, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := opened.WriteQueryEvents(ctx, searchTestEvents(now)); err != nil {
		t.Fatal(err)
	}
	// An older Sable writes the log without touching the index.
	if _, err := opened.database.ExecContext(ctx, opened.queryLogInsert(),
		now, "10.0.7.99", "10.0.7.99", "older.remarkable.com.", "older.remarkable.com", dns.TypeA, dns.ClassINET, 0, "cache", "UDP", "", "{}", 1000,
	); err != nil {
		t.Fatal(err)
	}
	opened.Close()

	reopened, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.searchIndexed.Load() {
		t.Fatal("the index was used while it missed rows")
	}
	if built, err := reopened.BuildQueryLogSearch(ctx); err != nil || !built {
		t.Fatalf("BuildQueryLogSearch() = %t, %v", built, err)
	}
	page, err := reopened.QueryEvents(ctx, querylog.Filter{Search: "older.remarkable"})
	if err != nil || page.TotalEntries != 1 || !reopened.searchIndexed.Load() {
		t.Fatalf("search found %d rows, %v, indexed %t; want the older Sable's row through the index", page.TotalEntries, err, reopened.searchIndexed.Load())
	}
}

// A pruned row leaves the search at once and the index at the next pass.
func TestQueryLogSearchForgetsPrunedRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	opened := openQueryLogStore(t, []querylog.Event{
		{OccurredAt: now.Add(-48 * time.Hour), ClientIP: "10.0.7.88", Name: "old.remarkable.com.", RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceCache, Protocol: "UDP"},
		{OccurredAt: now, ClientIP: "10.0.7.88", Name: "new.remarkable.com.", RecordType: dns.TypeA, Class: dns.ClassINET, Source: querylog.SourceCache, Protocol: "UDP"},
	})
	if err := opened.PruneQueryEvents(ctx, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	indexed := func() int {
		t.Helper()
		var count int
		if err := opened.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+queryLogSearchTable+" WHERE "+queryLogSearchTable+" MATCH '\"remarkable\"'").Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	page, err := opened.QueryEvents(ctx, querylog.Filter{Search: "remarkable"})
	if err != nil || page.TotalEntries != 1 || len(page.Entries) != 1 || page.Entries[0].Name != "new.remarkable.com." {
		t.Fatalf("search after pruning = %+v, %v; want only the row the log kept", page, err)
	}
	if got := indexed(); got != 2 {
		t.Fatalf("the index holds %d entries before its pass, want the pruned one still there", got)
	}
	if _, err := opened.BuildQueryLogSearch(ctx); err != nil {
		t.Fatal(err)
	}
	if got := indexed(); got != 1 {
		t.Fatalf("the index holds %d entries after its pass, want the one the log kept", got)
	}
}
