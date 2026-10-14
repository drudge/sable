package web

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/serverlog"
)

// countingLogStore counts reads of each log, so a test can tell which tabs
// the Logs page loaded.
type countingLogStore struct {
	testServerLogStore
	queryReads, serverReads atomic.Int32
}

func (store *countingLogStore) QueryEvents(ctx context.Context, filter querylog.Filter) (querylog.Page, error) {
	store.queryReads.Add(1)
	return store.testServerLogStore.QueryEvents(ctx, filter)
}

func (store *countingLogStore) ServerLogEntries(ctx context.Context, query serverlog.Query) (serverlog.Page, error) {
	store.serverReads.Add(1)
	return store.testServerLogStore.ServerLogEntries(ctx, query)
}

func newCountingLogTestServer(t *testing.T, store *countingLogStore) *Server {
	t.Helper()
	configuration := config.Defaults()
	configuration.Cluster.DataDirectory = t.TempDir()
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{},
		testConfiguration{snapshot: config.Snapshot{Config: configuration, Revision: 1}},
		testZones{}, "sqlite", testQueryLog{}, store,
		func(context.Context) error { return nil },
		nil, false, false, false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server
}

// A busy network's query log is millions of rows, and counting them is most
// of the cost of the page, so the Logs page reads only the log its open tab
// shows. The other tab loads, with the same address's filters, when opened.
func TestLogsPageReadsOnlyTheOpenTab(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		target, pending                 string
		wantQueryReads, wantServerReads int32
	}{
		{"/logs", `hx-get="/ui/logs/queries"`, 0, 1},
		{"/logs?tab=server&q=example", `hx-get="/ui/logs/queries?q=example"`, 0, 1},
		{"/logs?tab=queries&q=example", `hx-get="/ui/logs/runtime?q=example"`, 1, 0},
	} {
		store := &countingLogStore{}
		server := newCountingLogTestServer(t, store)
		body := serveRequest(server, "GET", test.target).Body.String()
		if got := store.queryReads.Load(); got != test.wantQueryReads {
			t.Errorf("%s read the query log %d times, want %d", test.target, got, test.wantQueryReads)
		}
		if got := store.serverReads.Load(); got != test.wantServerReads {
			t.Errorf("%s read the server log %d times, want %d", test.target, got, test.wantServerReads)
		}
		if !strings.Contains(body, test.pending) || !strings.Contains(body, `hx-trigger="revealed"`) {
			t.Errorf("%s does not load the hidden tab when it opens; want %s", test.target, test.pending)
		}
		// The query details dialog lives outside both tabs.
		if !strings.Contains(body, `id="query-detail-dialog"`) {
			t.Errorf("%s has no query details dialog", test.target)
		}
	}
}

// The query log loaded on its own, as when its tab opens or it refreshes
// live, keeps the block and allow actions the page offers.
func TestQueryLogPanelKeepsPolicyActions(t *testing.T) {
	t.Parallel()

	server := newCountingLogTestServer(t, &countingLogStore{})
	body := serveRequest(server, "GET", "/ui/logs/queries").Body.String()
	if !strings.Contains(body, "Block example.com") {
		t.Error("query log panel lost the block action")
	}
}
