package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/store"
)

type technitiumAuthenticator struct{ testAuthenticator }

func (technitiumAuthenticator) AuthenticateToken(_ context.Context, token string) (auth.Principal, error) {
	principal := auth.Principal{AuthenticatedByToken: true}
	switch token {
	case "metrics":
		principal.Permissions = []string{auth.PermissionMetricsRead}
	case "metrics-and-logs":
		principal.Permissions = []string{auth.PermissionMetricsRead, auth.PermissionLogsRead}
	case "logs":
		principal.Permissions = []string{auth.PermissionLogsRead}
	default:
		return auth.Principal{}, auth.ErrUnauthorized
	}
	return principal, nil
}

type technitiumQueryLog struct {
	testQueryLog
	start, end time.Time
	calls      int
	err        error
}

func (log *technitiumQueryLog) QueryLogInsights(_ context.Context, start, end time.Time) (querylog.Insights, error) {
	log.start, log.end = start, end
	log.calls++
	return querylog.Insights{Blocked: map[string]uint64{
		"ads.example": 3, "tracker.example": 1, "a.example": 1,
		"b.example": 1, "c.example": 1, "d.example": 1,
	}}, log.err
}

func newTechnitiumTestServer(t *testing.T) (*Server, *technitiumQueryLog) {
	t.Helper()
	log := &technitiumQueryLog{}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{},
		testConfiguration{snapshot: config.Snapshot{Config: config.Defaults()}}, testZones{},
		"sqlite", log, log, nil, technitiumAuthenticator{}, true, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	return server, log
}

func TestTechnitiumStatsGlanceResponse(t *testing.T) {
	t.Parallel()
	server, log := newTechnitiumTestServer(t)
	now := time.Now().UTC().Truncate(time.Minute)
	backing := newFakeStatsStore()
	backing.buckets[now.Add(-25*time.Hour).Unix()] = store.QueryStatsDelta{Queries: 500, Blocked: 50}
	backing.buckets[now.Add(-23*time.Hour).Unix()] = store.QueryStatsDelta{Queries: 12, Blocked: 4}
	backing.buckets[now.Add(-2*time.Hour).Unix()] = store.QueryStatsDelta{Queries: 5, Blocked: 1}
	if err := server.SetStatsStore(context.Background(), backing); err != nil {
		t.Fatal(err)
	}
	server.history.record(now.Add(-time.Hour), dnsserver.Stats{Queries: 1000, Blocked: 200})
	server.history.record(now.Add(-10*time.Minute), dnsserver.Stats{Queries: 1006, Blocked: 202})
	server.stats = testStats{snapshot: dnsserver.Stats{Queries: 1008, Blocked: 203, BlockedDomains: 1234}}

	response := serveRequest(server, http.MethodGet, "/api/dashboard/stats/get?token=metrics-and-logs&type=LastDay")
	if response.Code != http.StatusOK {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	// Decode with Glance's field types, including its untagged TopBlockedDomains.
	var decoded struct {
		Status   string `json:"status"`
		Response struct {
			Stats struct {
				TotalQueries   int `json:"totalQueries"`
				BlockedQueries int `json:"totalBlocked"`
				BlockedZones   int `json:"blockedZones"`
				BlockListZones int `json:"blockListZones"`
			} `json:"stats"`
			MainChartData struct {
				Labels   []time.Time `json:"labels"`
				Datasets []struct {
					Label string `json:"label"`
					Data  []int  `json:"data"`
				} `json:"datasets"`
			} `json:"mainChartData"`
			TopBlockedDomains []struct {
				Domain string `json:"name"`
				Count  int    `json:"hits"`
			}
		} `json:"response"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	stats := decoded.Response.Stats
	if decoded.Status != "ok" || stats.TotalQueries != 25 || stats.BlockedQueries != 8 || stats.BlockedZones+stats.BlockListZones != 1234 {
		t.Fatalf("stats = %+v, status = %q", stats, decoded.Status)
	}
	chart := decoded.Response.MainChartData
	if len(chart.Labels) != 24 || len(chart.Datasets) != 2 {
		t.Fatalf("chart = %+v", chart)
	}
	for index, series := range chart.Datasets {
		if series.Label != []string{"Total", "Blocked"}[index] || len(series.Data) != 24 {
			t.Fatalf("series = %+v", series)
		}
		// Glance groups each three hourly values into one of eight graph bars.
		var sum int
		for bar := range 8 {
			for hour := range 3 {
				sum += series.Data[bar*3+hour]
			}
		}
		if sum != []int{25, 8}[index] {
			t.Fatalf("graph sum = %d for %s", sum, series.Label)
		}
	}
	if !chart.Labels[0].Equal(log.start) || !chart.Labels[23].Add(time.Hour).Equal(log.end) {
		t.Fatalf("rankings window %s–%s differs from graph labels %v", log.start, log.end, chart.Labels)
	}
	domains := decoded.Response.TopBlockedDomains
	if len(domains) != 5 || domains[0].Domain != "ads.example" || domains[0].Count != 3 || domains[1].Domain != "a.example" {
		t.Fatalf("top blocked domains = %+v", domains)
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", response.Header())
	}
}

func TestTechnitiumStatsAuthentication(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, path, bearer, cookie string
		status                     int
		wantDomains                bool
	}{
		{name: "missing token", path: technitiumStatsPath + "?type=LastDay", status: http.StatusUnauthorized},
		{name: "empty token", path: technitiumStatsPath + "?type=LastDay&token=", status: http.StatusUnauthorized},
		{name: "invalid token", path: technitiumStatsPath + "?type=LastDay&token=revoked", status: http.StatusUnauthorized},
		{name: "metrics token", path: technitiumStatsPath + "?type=LastDay&token=metrics", status: http.StatusOK},
		{name: "metrics and logs", path: technitiumStatsPath + "?type=LastDay&token=metrics-and-logs", status: http.StatusOK, wantDomains: true},
		{name: "no metrics permission", path: technitiumStatsPath + "?type=LastDay&token=logs", status: http.StatusForbidden},
		{name: "bearer token", path: technitiumStatsPath + "?type=LastDay", bearer: "metrics", status: http.StatusOK},
		{name: "bearer takes precedence", path: technitiumStatsPath + "?type=LastDay&token=metrics", bearer: "invalid", status: http.StatusUnauthorized},
		{name: "session", path: technitiumStatsPath + "?type=LastDay", cookie: "session-token", status: http.StatusOK, wantDomains: true},
		{name: "invalid token does not fall back to session", path: technitiumStatsPath + "?type=LastDay&token=invalid", cookie: "session-token", status: http.StatusUnauthorized},
		{name: "query token cannot read metrics", path: "/metrics?token=metrics", status: http.StatusUnauthorized},
		{name: "query token cannot read other APIs", path: "/api/v1/policy?token=metrics-and-logs", status: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, log := newTechnitiumTestServer(t)
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			if test.bearer != "" {
				request.Header.Set("Authorization", "Bearer "+test.bearer)
			}
			if test.cookie != "" {
				request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: test.cookie})
			}
			response := httptest.NewRecorder()
			server.httpServer.Handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("response = %d %s, want %d", response.Code, response.Body.String(), test.status)
			}
			if test.status == http.StatusOK {
				var data technitiumStatsResponse
				if err := json.Unmarshal(response.Body.Bytes(), &data); err != nil {
					t.Fatal(err)
				}
				if got := len(data.Response.TopBlockedDomains) > 0; got != test.wantDomains || (log.calls > 0) != test.wantDomains {
					t.Fatalf("domains disclosed = %v, log queries = %d, want domains %v", got, log.calls, test.wantDomains)
				}
			}
		})
	}
}

func TestTechnitiumDashboardHourlyBoundaries(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.September, 3, 12, 37, 0, 0, time.UTC)
	buckets := []store.QueryStatsBucket{
		{Start: start.Add(-time.Minute), QueryStatsDelta: store.QueryStatsDelta{Queries: 100}},
		{Start: start, QueryStatsDelta: store.QueryStatsDelta{Queries: 1, Blocked: 1}},
		{Start: start.Add(59 * time.Minute), QueryStatsDelta: store.QueryStatsDelta{Queries: 2}},
		{Start: start.Add(time.Hour), QueryStatsDelta: store.QueryStatsDelta{Queries: 4}},
		{Start: start.Add(24*time.Hour - time.Minute), QueryStatsDelta: store.QueryStatsDelta{Queries: 8, Blocked: 3}},
		{Start: start.Add(24 * time.Hour), QueryStatsDelta: store.QueryStatsDelta{Queries: 100}},
	}
	data := technitiumDashboard(buckets, start, 12)
	want := make([]uint64, 24)
	want[0], want[1], want[23] = 3, 4, 8
	if !reflect.DeepEqual(data.MainChartData.Datasets[0].Data, want) || data.Stats.TotalQueries != 15 || data.Stats.TotalBlocked != 4 {
		t.Fatalf("dashboard = %+v", data)
	}
}

type unavailableTechnitiumStatsStore struct{ *fakeStatsStore }

func (unavailableTechnitiumStatsStore) QueryStats(context.Context, time.Time, time.Time, time.Duration) ([]store.QueryStatsBucket, error) {
	return nil, errors.New("database unavailable")
}

func TestTechnitiumStatsErrors(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, query      string
		statsUnavailable bool
		logsUnavailable  bool
		setupRequired    bool
		status           int
	}{
		{name: "unsupported range", query: "type=LastWeek", status: http.StatusBadRequest},
		{name: "missing range", status: http.StatusBadRequest},
		{name: "stats unavailable", query: "type=LastDay", statsUnavailable: true, status: http.StatusServiceUnavailable},
		{name: "logs unavailable", query: "type=LastDay", logsUnavailable: true, status: http.StatusServiceUnavailable},
		{name: "setup required", query: "type=LastDay", setupRequired: true, status: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, log := newTechnitiumTestServer(t)
			server.setupRequired.Store(test.setupRequired)
			if test.statsUnavailable {
				if err := server.SetStatsStore(context.Background(), unavailableTechnitiumStatsStore{newFakeStatsStore()}); err != nil {
					t.Fatal(err)
				}
			}
			if test.logsUnavailable {
				log.err = errors.New("database unavailable")
			}
			response := serveRequest(server, http.MethodGet, technitiumStatsPath+"?token=metrics-and-logs&"+test.query)
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.status || body["status"] != "error" || body["errorMessage"] == "" || body["response"] != nil {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
}
