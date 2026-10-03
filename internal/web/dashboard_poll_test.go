package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
	zonemodel "github.com/drudge/sable/internal/zone"
)

// countingRecentQueries counts the newest-rows reads the dashboard makes.
type countingRecentQueries struct {
	testQueryLog
	mu     sync.Mutex
	recent int
}

func (queries *countingRecentQueries) RecentQueryEvents(ctx context.Context, limit int) ([]querylog.Entry, error) {
	queries.mu.Lock()
	queries.recent++
	queries.mu.Unlock()
	return queries.testQueryLog.RecentQueryEvents(ctx, limit)
}

func TestDashboardPollsShareStoreReads(t *testing.T) {
	t.Parallel()
	queries := &countingRecentQueries{}
	started := time.Now()
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: started}},
		testConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}},
		testZones{snapshot: zonemodel.Snapshot{}},
		"sqlite",
		testQueryLog{},
		queries,
		func(context.Context) error { return nil },
		nil,
		false,
		false,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	backing := newFakeStatsStore()
	if err := server.history.attach(context.Background(), backing); err != nil {
		t.Fatal(err)
	}

	// Three tabs polling the same chart within one cache window.
	for range 3 {
		if response := serveRequest(server, http.MethodGet, "/ui/stats/chart?range=hour"); response.Code != http.StatusOK {
			t.Fatalf("chart poll status = %d", response.Code)
		}
	}
	if backing.reads != 1 || queries.recent != 1 {
		t.Fatalf("three polls read the statistics %d times and the query log %d times, want once each", backing.reads, queries.recent)
	}

	// A flush moves samples into the store, so the next poll reads it again.
	server.history.record(time.Now(), dnsserver.Stats{StartedAt: started, Queries: 10})
	server.flushStatsHistory()
	if response := serveRequest(server, http.MethodGet, "/ui/stats/chart?range=hour"); response.Code != http.StatusOK {
		t.Fatalf("chart poll status = %d", response.Code)
	}
	if backing.reads != 2 {
		t.Fatalf("poll after a flush read the statistics %d times in all, want 2", backing.reads)
	}
}
