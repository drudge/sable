//go:build browser

package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	webassets "github.com/drudge/sable/internal/web/assets"
	"github.com/drudge/sable/internal/web/pages"
)

func TestBrowserUpdateNotifications(t *testing.T) {
	var checks atomic.Int32
	var installs atomic.Int32
	var polls atomic.Int32
	var restarts atomic.Int32
	var rollouts atomic.Int32
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", webassets.Handler())
	update := pages.UpdateView{Supported: true, Available: true, Checked: true, CanCheck: true, CanApply: true, CheckOnLogin: true,
		CanRestart: true, ServiceManaged: true, CSRFToken: "fixture-csrf",
		CurrentVersion: "1.0.0", LatestVersion: "1.1.0", ReleaseURL: "https://github.com/drudge/sable/releases/tag/v1.1.0", ReleaseNotes: "### Improvements\n\n- Rolling updates keep other DNS nodes available.\n- Release notes are visible in the console.\n\n<script>window.releaseNotesExecuted = true</script>"}
	mux.HandleFunc("POST /ui/updates/automatic-check", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSRF-Token") != "fixture-csrf" {
			http.Error(w, "missing CSRF", http.StatusForbidden)
			return
		}
		checks.Add(1)
		view := update
		view.CanUpdateCluster = strings.Contains(r.Referer(), "?scope")
		_ = pages.UpdateNotification(view).Render(r.Context(), w)
	})
	mux.HandleFunc("GET /checks", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, checks.Load()) })
	mux.HandleFunc("GET /installs", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, installs.Load()) })
	mux.HandleFunc("GET /restarts", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, restarts.Load()) })
	mux.HandleFunc("GET /rollouts", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, rollouts.Load()) })
	mux.HandleFunc("POST /ui/updates/cluster", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSRF-Token") != "fixture-csrf" || r.PostFormValue("notification") != "true" || r.PostFormValue("version") != "1.1.0" {
			http.Error(w, "invalid cluster update", http.StatusBadRequest)
			return
		}
		rollouts.Add(1)
		w.Header().Set("HX-Redirect", "/cluster")
	})
	currentUpdate := func() pages.UpdateView {
		view := update
		if installs.Load() > 0 {
			view.Phase, view.Busy = "installing", true
			view.Progress = "Downloading sable_1.1.0_linux_amd64.tar.gz..."
		}
		if polls.Load() >= 2 {
			view.Phase, view.Busy, view.Installed = "installed", false, true
		}
		return view
	}
	mux.HandleFunc("GET /ui/updates", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("notification") == "true" {
			polls.Add(1)
			_ = pages.UpdateNotification(currentUpdate()).Render(r.Context(), w)
			return
		}
		_ = pages.UpdatePanel(currentUpdate()).Render(r.Context(), w)
	})
	mux.HandleFunc("POST /ui/updates/install", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSRF-Token") != "fixture-csrf" || r.PostFormValue("notification") != "true" {
			http.Error(w, "invalid notification install", http.StatusBadRequest)
			return
		}
		installs.Add(1)
		w.Header().Set("HX-Trigger", "sableUpdateChanged")
		_ = pages.UpdateNotification(currentUpdate()).Render(r.Context(), w)
	})
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		instance := "before-restart"
		if restarts.Load() > 0 {
			instance = "after-restart"
		}
		writeJSON(w, http.StatusOK, map[string]string{"instance_id": instance})
	})
	mux.HandleFunc("POST /ui/updates/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSRF-Token") != "fixture-csrf" {
			http.Error(w, "missing CSRF", http.StatusForbidden)
			return
		}
		restarts.Add(1)
		writeJSON(w, http.StatusAccepted, map[string]string{"instance_id": "before-restart"})
	})
	clusterUpdate := pages.ClusterUpdateView{Supported: true, CanApply: true, Release: update,
		Rollout: cluster.RolloutStatus{ID: "fixture", Version: "v1.1.0", Phase: "updating", Nodes: []cluster.RolloutNode{{Name: "ns2-queens", Phase: "complete"}, {Name: "ns3-latham", Phase: "install"}, {Name: "ns1-queens", Phase: "queued"}}},
	}
	mux.HandleFunc("GET /ui/cluster/status", func(w http.ResponseWriter, r *http.Request) {
		// A restarting replica's first heartbeat renegotiates update support.
		refresh := clusterUpdate
		refresh.Supported = false
		_ = pages.ClusterLiveStatusUpdate(pages.ClusterPageView{Initialized: true, LocalRole: "Primary", Update: refresh}).Render(r.Context(), w)
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		view := pages.DashboardView{Version: "1.0.0", CSRFToken: "fixture-csrf", CanCheckUpdates: true, CheckUpdatesOnLogin: !r.URL.Query().Has("disabled")}
		view.Username = r.URL.Query().Get("user")
		if restarts.Load() > 0 {
			view.Version = "1.1.0"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/cluster" {
			_ = pages.ClusterPage(pages.ClusterPageView{Console: view, Initialized: true, LocalRole: "Primary", Update: clusterUpdate}).Render(r.Context(), w)
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
