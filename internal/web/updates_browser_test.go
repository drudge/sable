//go:build browser

package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	webassets "github.com/drudge/sable/internal/web/assets"
	"github.com/drudge/sable/internal/web/pages"
)

func TestBrowserUpdateNotifications(t *testing.T) {
	var checks atomic.Int32
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", webassets.Handler())
	update := pages.UpdateView{Supported: true, Available: true, Checked: true, CanCheck: true, CanApply: true, CheckOnLogin: true,
		CurrentVersion: "1.0.0", LatestVersion: "1.1.0", ReleaseNotes: "### Improvements\n\n- Rolling updates keep other DNS nodes available.\n- Release notes are visible in the console.\n\n<script>window.releaseNotesExecuted = true</script>"}
	mux.HandleFunc("POST /ui/updates/automatic-check", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSRF-Token") != "fixture-csrf" {
			http.Error(w, "missing CSRF", http.StatusForbidden)
			return
		}
		checks.Add(1)
		_ = pages.UpdateNotification(update).Render(r.Context(), w)
	})
	mux.HandleFunc("GET /checks", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, checks.Load()) })
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		view := pages.DashboardView{Version: "1.0.0", CSRFToken: "fixture-csrf", CanCheckUpdates: true, CheckUpdatesOnLogin: !r.URL.Query().Has("disabled")}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/cluster" {
			_ = pages.ClusterPage(pages.ClusterPageView{Console: view, Initialized: true, LocalRole: "Primary", Update: pages.ClusterUpdateView{Supported: true, CanApply: true,
				Rollout: cluster.RolloutStatus{ID: "fixture", Version: "v1.1.0", Phase: "updating", Nodes: []cluster.RolloutNode{{Name: "ns2-queens", Phase: "complete"}, {Name: "ns3-latham", Phase: "install"}, {Name: "ns1-queens", Phase: "queued"}}},
			}}).Render(r.Context(), w)
			return
		}
		_ = pages.AboutPage(pages.AboutPageView{Console: view, Update: update, Commit: "abcdef0", BuiltAt: "2026-09-10T12:00:00Z"}).Render(r.Context(), w)
	})
	server := httptest.NewServer(secureHeaders(mux, false))
	defer server.Close()
	command := exec.Command("node", "../../scripts/browser/updates.cjs", server.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser update notifications: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
