package web

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/serverlog"
)

// testServerLogStore answers both the query-log surface New requires and the
// server-log history the runtime panel looks for.
type testServerLogStore struct {
	testQueryLog
	entries []serverlog.Entry
}

func (store *testServerLogStore) ServerLogEntries(_ context.Context, query serverlog.Query) (serverlog.Page, error) {
	matched := make([]serverlog.Entry, 0, len(store.entries))
	for _, entry := range store.entries {
		if query.Search != "" && !strings.Contains(strings.ToLower(entry.Message), strings.ToLower(query.Search)) {
			continue
		}
		matched = append(matched, entry)
	}
	if query.Page < 1 {
		query.Page = 1
	}
	if query.PageSize < 1 {
		query.PageSize = 50
	}
	totalPages := 0
	if len(matched) > 0 {
		totalPages = (len(matched) + query.PageSize - 1) / query.PageSize
		query.Page = min(query.Page, totalPages)
	}
	start := min((query.Page-1)*query.PageSize, len(matched))
	return serverlog.Page{
		Entries: matched[start:min(start+query.PageSize, len(matched))],
		Page:    query.Page, PageSize: query.PageSize,
		TotalEntries: len(matched), TotalPages: totalPages,
	}, nil
}

func newRuntimeLogTestServerWithStore(t *testing.T, configuration config.Config, store *testServerLogStore) *Server {
	t.Helper()
	configuration.Cluster.DataDirectory = t.TempDir()
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{},
		testConfiguration{snapshot: config.Snapshot{Config: configuration, Revision: 1}},
		testZones{},
		"sqlite",
		testQueryLog{},
		store,
		func(context.Context) error { return nil },
		nil,
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server
}

func TestRuntimeLogPanelServesPersistedHistoryWithPaging(t *testing.T) {
	t.Parallel()

	store := &testServerLogStore{entries: []serverlog.Entry{
		{ID: 3, OccurredAt: time.Now(), Level: slog.LevelError, Message: "zone transfer failed"},
		{ID: 2, OccurredAt: time.Now().Add(-time.Hour), Level: slog.LevelInfo, Message: "listener started"},
		{ID: 1, OccurredAt: time.Now().Add(-48 * time.Hour), Level: slog.LevelInfo, Message: "from before the restart"},
	}}
	server := newRuntimeLogTestServerWithStore(t, config.Defaults(), store)

	body := serveRequest(server, "GET", "/ui/logs/runtime?page_size=2").Body.String()
	for _, expected := range []string{"zone transfer failed", "listener started", "3 entries", "Server log pages"} {
		if !strings.Contains(body, expected) {
			t.Errorf("runtime panel does not contain %q", expected)
		}
	}
	if strings.Contains(body, "from before the restart") {
		t.Error("runtime panel showed a second-page entry on the first page")
	}

	second := serveRequest(server, "GET", "/ui/logs/runtime?page=2&page_size=2").Body.String()
	if !strings.Contains(second, "from before the restart") {
		t.Error("second page does not contain the oldest entry")
	}
}

// Switching persistence off has to fall back to the live buffer. Serving the
// table anyway would show whatever was captured before it was switched off and
// then simply stop, which reads as a broken log rather than a disabled one.
func TestRuntimeLogPanelFallsBackToBufferWhenPersistenceIsOff(t *testing.T) {
	t.Parallel()

	configuration := config.Defaults()
	configuration.ServerLog.Enabled = false
	store := &testServerLogStore{entries: []serverlog.Entry{
		{ID: 1, OccurredAt: time.Now(), Level: slog.LevelInfo, Message: "stale persisted entry"},
	}}
	server := newRuntimeLogTestServerWithStore(t, configuration, store)

	buffer := serverlog.New(8)
	slog.New(serverlog.NewHandler(slog.NewTextHandler(io.Discard, nil), buffer)).
		Info("live buffer entry", "listener", "127.0.0.1:53")
	server.SetRuntimeLogs(buffer)

	body := serveRequest(server, "GET", "/ui/logs/runtime").Body.String()
	if !strings.Contains(body, "live buffer entry") {
		t.Error("runtime panel does not contain the buffered entry")
	}
	if strings.Contains(body, "stale persisted entry") {
		t.Error("runtime panel served persisted entries while persistence is off")
	}
	if strings.Contains(body, "Server log pages") {
		t.Error("runtime panel offered paging over a buffer that cannot page")
	}
}

func TestRuntimeLogSearchReachesBeyondTheCurrentProcess(t *testing.T) {
	t.Parallel()

	store := &testServerLogStore{entries: []serverlog.Entry{
		{ID: 2, OccurredAt: time.Now(), Level: slog.LevelInfo, Message: "listener started"},
		{ID: 1, OccurredAt: time.Now().Add(-72 * time.Hour), Level: slog.LevelError, Message: "upgrade rollback"},
	}}
	server := newRuntimeLogTestServerWithStore(t, config.Defaults(), store)

	body := serveRequest(server, "GET", "/ui/logs/runtime?search=rollback").Body.String()
	if !strings.Contains(body, "upgrade rollback") {
		t.Error("search did not reach the entry from before this process")
	}
	if strings.Contains(body, "listener started") {
		t.Error("search returned an entry it should have filtered out")
	}
}

// The export is written oldest first while the pages arrive newest first, so
// the file reads in the order a log file is expected to.
func TestRuntimeLogExportWritesHistoryOldestFirst(t *testing.T) {
	t.Parallel()

	store := &testServerLogStore{entries: []serverlog.Entry{
		{ID: 3, OccurredAt: time.Now(), Level: slog.LevelInfo, Message: "newest"},
		{ID: 2, OccurredAt: time.Now().Add(-time.Hour), Level: slog.LevelInfo, Message: "middle"},
		{ID: 1, OccurredAt: time.Now().Add(-2 * time.Hour), Level: slog.LevelInfo, Message: "oldest"},
	}}
	server := newRuntimeLogTestServerWithStore(t, config.Defaults(), store)

	body := serveRequest(server, "GET", "/api/v1/logs/runtime/export").Body.String()
	oldest, middle, newest := strings.Index(body, "oldest"), strings.Index(body, "middle"), strings.Index(body, "newest")
	if oldest < 0 || middle < 0 || newest < 0 {
		t.Fatalf("export is missing entries: %q", body)
	}
	if !(oldest < middle && middle < newest) {
		t.Fatalf("export is not oldest first: %q", body)
	}
}
