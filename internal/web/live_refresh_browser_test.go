//go:build browser

package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/a-h/templ"
	webassets "github.com/drudge/sable/internal/web/assets"
	"github.com/drudge/sable/internal/web/pages"
)

func TestBrowserLiveRefresh(t *testing.T) {
	combine := func(parts ...templ.Component) templ.Component {
		return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			for _, part := range parts {
				if err := part.Render(ctx, w); err != nil {
					return err
				}
			}
			return nil
		})
	}
	afterPanel := templ.ComponentFunc(func(_ context.Context, writer io.Writer) error {
		_, err := io.WriteString(writer, `<button id="after-live-panel" type="button">After panel</button>`)
		return err
	})
	var backupMutex sync.Mutex
	wrapCluster := func(part templ.Component) templ.Component {
		return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			io.WriteString(w, `<div id="cluster-content">`)
			err := part.Render(ctx, w)
			io.WriteString(w, `</div>`)
			return err
		})
	}
	chart := pages.QueryChartView{ActiveRange: "hour", Live: true}
	insights := pages.DashboardInsightsView{PollRange: "hour", TopDomains: []pages.RankedStatView{{Name: "example.test", Value: 10}}, QueryTypes: []pages.DistributionItemView{{Name: "A", Value: 10, Percent: 100}}}
	cluster := pages.ClusterPageView{LocalRole: "Primary", NetworkReady: true, Nodes: []pages.ClusterNodeView{{ID: "replica-1", Name: "Replica", Role: "Replica", AdvertiseURL: "https://example.test", State: "online", SyncState: "current"}}}
	backup := pages.SettingsBackupView{Available: true, LocalAvailable: true, CanCreate: true, ScheduleDirectory: "backups", ScheduleInterval: "1d", ScheduleRetentionCount: 7, ScheduleRunAt: "01:00", Job: &pages.SettingsBackupJobView{Kind: "local", Title: "Running", Step: 1, Total: 2}}
	update := pages.UpdateView{Busy: true, Available: true, LatestVersion: "1.1.0", ReleaseURL: "https://github.com/drudge/sable/releases/tag/v1.1.0", ReleaseNotes: "### Improvements\n\n- More reliable updates."}
	unifi := pages.UniFiAppView{Enabled: true, Mappings: []pages.UniFiMappingView{{Name: "Office", Zone: "office.example.test", Preview: "workstation-with-a-long-name.office.example.test"}}}
	dynamic := pages.DynamicDNSAppView{Enabled: true}
	logs := pages.QueryLogsView{Live: true, PageSize: 25}
	initial := map[string]templ.Component{
		"chart":    combine(pages.Stats(pages.StatsOverviewView{Scope: pages.StatsScopeAll}), pages.QueryChart(chart), pages.DashboardInsights(insights, false)),
		"insights": pages.DashboardInsights(insights, false),
		"loading":  pages.DashboardInsights(pages.DashboardInsightsView{Loading: true, LoadURL: "/ui/stats/insights?range=hour"}, false),
		"cluster":  wrapCluster(pages.ClusterLiveStatus(cluster)),
		"backup":   pages.SettingsBackupPanel(backup),
		"update":   pages.UpdatePanel(update),
		"unifi":    combine(pages.UniFiStatusPanel(unifi), pages.UniFiMappingTable(unifi, false), pages.UniFiCardActions(unifi, false)),
		"dynamic":  combine(pages.DynamicDNSStatusPanel(dynamic), pages.DynamicDNSCardActions(dynamic, false)),
		"logs":     pages.QueryLogsPanel(logs),
	}
	fragments := map[string]templ.Component{
		"/ui/stats/insights":                  pages.DashboardInsights(insights, false),
		"/ui/cluster/status":                  pages.ClusterLiveStatus(cluster),
		"/ui/updates":                         pages.UpdatePanel(update),
		"/ui/integrations/unifi/status":       combine(pages.UniFiStatusPanel(unifi), pages.UniFiMappingTable(unifi, true), pages.UniFiCardActions(unifi, true)),
		"/ui/integrations/dynamic-dns/status": combine(pages.DynamicDNSStatusPanel(dynamic), pages.DynamicDNSCardActions(dynamic, true)),
		"/ui/logs/queries":                    pages.QueryLogsPanel(logs),
	}
	mux := http.NewServeMux()
	mux.Handle("/assets/", webassets.Handler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/ui/backup/progress" || r.URL.Path == "/ui/backup/schedule" {
			backupMutex.Lock()
			defer backupMutex.Unlock()
			if r.URL.Query().Has("complete") {
				backup.Job = nil
			}
			if r.Method == http.MethodPost {
				if err := r.ParseForm(); err != nil {
					t.Error(err)
					http.Error(w, "invalid form", 400)
					return
				}
				backup.ScheduleDirectory = r.Form.Get("directory")
				backup.Message = "Schedule saved"
			}
			_ = pages.SettingsBackupPanel(backup).Render(r.Context(), w)
		} else if r.URL.Path == "/" {
			view := pages.DashboardView{}
			_ = pages.AppDocument(view, "Live refresh fixtures", "settings", combine(initial[r.URL.Query().Get("case")], afterPanel)).Render(r.Context(), w)
		} else if r.URL.Path == "/ui/stats/chart" {
			selectedChart := chart
			selectedChart.ActiveRange = r.URL.Query().Get("range")
			_ = pages.QueryChart(selectedChart).Render(r.Context(), w)
			if r.URL.Query().Get("insights") == "1" {
				_ = pages.DashboardInsights(insights, true).Render(r.Context(), w)
			}
		} else if component := fragments[r.URL.Path]; component != nil {
			_ = component.Render(r.Context(), w)
		} else {
			http.NotFound(w, r)
		}
	})
	server := httptest.NewServer(secureHeaders(mux, false))
	defer server.Close()
	command := exec.Command("node", "../../scripts/browser/live-refresh.cjs", server.URL)
	command.Env = os.Environ()
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
}
