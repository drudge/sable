//go:build browser

package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"

	"github.com/a-h/templ"
	webassets "github.com/drudge/sable/internal/web/assets"
	"github.com/drudge/sable/internal/web/pages"
)

// Exercise the shipped scripts against real templ components and HTTP swaps.
// These fixtures never start a resolver or write to an operator's configuration.
func TestBrowserConsoleFixes(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/assets/", webassets.Handler())
	mux.HandleFunc("POST /ui/blocking/lists/add", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("url") == "" || r.Form.Get("format") != "auto" || r.Header.Get("X-CSRF-Token") != "fixture-csrf" {
			http.Error(w, "incorrect add-list request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		view := pages.BlockingPageView{ActiveTab: "lists", Message: "Block list added and compiled"}
		if r.Form.Get("url") == "https://example.test/unavailable.txt" {
			view.Message = ""
			view.Error = "Could not download the block list."
			writeBlockingErrorStatus(w, r, http.StatusUnprocessableEntity)
		}
		_ = pages.BlockingContent(view).Render(r.Context(), w)
	})
	mux.HandleFunc("POST /ui/blocking/lists/update", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSRF-Token") != "fixture-csrf" {
			http.Error(w, "incorrect update-list request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		writeBlockingErrorStatus(w, r, http.StatusUnprocessableEntity)
		_ = pages.BlockingContent(pages.BlockingPageView{
			ActiveTab: "lists", RemoteListCount: 1, Error: "Could not update the block lists.",
		}).Render(r.Context(), w)
	})
	var dashboardRefreshes atomic.Uint64
	chart := pages.QueryChartView{ActiveRange: "hour", RangeLabel: "Last hour", Live: true}
	mux.HandleFunc("GET /ui/stats/chart", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = pages.QueryChart(chart).Render(r.Context(), w)
		_ = pages.Stats(pages.StatsOverviewView{
			Values: pages.StatsView{Queries: 100 + dashboardRefreshes.Add(1)},
			Scope:  r.URL.Query().Get("stats_scope"), RangeName: chart.ActiveRange,
			RangeLabel: chart.RangeLabel, CanLogs: true, OutOfBand: true,
		}).Render(r.Context(), w)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		view := pages.DashboardView{CSRFToken: "fixture-csrf", CanSettings: true, CanWriteSettings: true, CanZones: true, CanLogs: true, CanBlocking: true, CanWriteBlocking: true, BlockingEnabled: true}
		var content templ.Component = pages.BlockingContent(pages.BlockingPageView{ActiveTab: "lists", RemoteListCount: 1})
		if r.URL.Query().Has("about") {
			content = pages.AboutContent(pages.AboutPageView{
				Console: view, Commit: "abcdef0123456789abcdef0123456789abcdef0123",
				BuiltAt: "2026-09-10T02:00:00Z", GoVersion: "go1.27.1",
				Update: pages.UpdateView{Development: true, Supported: true},
			})
		}
		if r.URL.Query().Has("dashboard") {
			view.Chart = chart
			view.Stats = pages.StatsView{Queries: 100}
			content = pages.DashboardHome(view)
		}
		_ = pages.AppDocument(view, "Browser fixtures", "settings", content).Render(r.Context(), w)
	})
	server := httptest.NewServer(secureHeaders(mux, false))
	defer server.Close()
	command := exec.Command("node", "../../scripts/browser/console-fixes.cjs", server.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser console fixes: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
