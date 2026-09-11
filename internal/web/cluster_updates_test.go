package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/update"
	"github.com/drudge/sable/internal/web/pages"
)

type testRollingUpdateController struct {
	clusterController
	supported bool
	role      string
	state     cluster.State
	rollout   cluster.RolloutStatus
	startErr  error
	started   []string
}

func (controller *testRollingUpdateController) Snapshot() cluster.State {
	if controller.state.Initialized {
		return controller.state
	}
	return cluster.State{Initialized: true, LocalRole: controller.role}
}
func (controller *testRollingUpdateController) RollingUpdatesSupported() bool {
	return controller.supported
}
func (controller *testRollingUpdateController) RolloutStatus() cluster.RolloutStatus {
	return controller.rollout
}
func (controller *testRollingUpdateController) StopRollout() error { return nil }
func (controller *testRollingUpdateController) StartRollout(_ context.Context, version string) error {
	if controller.startErr != nil {
		return controller.startErr
	}
	controller.started = append(controller.started, version)
	return nil
}

func TestClusterUpdateViewRetainsCurrentRolloutDuringCapabilityNegotiation(t *testing.T) {
	for _, scenario := range []string{"restarting", "complete", "old cluster", "old primary", "replica"} {
		t.Run(scenario, func(t *testing.T) {
			server := updateTestServer(t, &testUpdateController{})
			controller := &testRollingUpdateController{
				state:   cluster.State{Initialized: true, ClusterID: "cluster", PrimaryID: "ns1", LocalRole: cluster.RolePrimary},
				rollout: cluster.RolloutStatus{ID: "rollout", ClusterID: "cluster", PrimaryID: "ns1", Version: "v1.2.0", Phase: "restarting"},
			}
			switch scenario {
			case "complete":
				controller.rollout.Phase = "complete"
			case "old cluster":
				controller.rollout.ClusterID = "previous-cluster"
			case "old primary":
				controller.rollout.PrimaryID = "previous-primary"
			case "replica":
				controller.state.LocalRole = cluster.RoleReplica
			}
			server.SetClusterController(controller)
			view := server.clusterUpdateView(httptest.NewRequest(http.MethodGet, "/cluster", nil))
			wantVisible := scenario == "restarting" || scenario == "complete"
			if view.Visible() != wantVisible || view.Supported {
				t.Fatalf("visible=%t supported=%t, want visible=%t without enabling new rollouts", view.Visible(), view.Supported, wantVisible)
			}
		})
	}
}

func TestClusterUpdateOfferedOnlyWhenANodeNeedsNewerRelease(t *testing.T) {
	for _, test := range []struct {
		name     string
		versions []string
		want     string
	}{
		{"all current", []string{"1.2.0", "v1.2.0", "1.2.0+build"}, ""},
		{"replica behind", []string{"1.2.0", "1.1.0", "1.2.0"}, "1.2.0"},
		{"newer installed", []string{"1.3.0", "1.3.0"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := updateTestServer(t, &testUpdateController{status: update.Status{LatestVersion: "1.2.0", CheckedAt: time.Now()}})
			controller := &testRollingUpdateController{supported: true, state: cluster.State{Initialized: true, LocalRole: cluster.RolePrimary}}
			for _, version := range test.versions {
				controller.state.Nodes = append(controller.state.Nodes, cluster.Node{Version: version})
			}
			server.SetClusterController(controller)
			view := server.clusterUpdateView(httptest.NewRequest(http.MethodGet, "/cluster", nil))
			if view.Version != test.want || view.UpdateAvailable() != (test.want != "") {
				t.Fatalf("version=%q available=%t, want %q", view.Version, view.UpdateAvailable(), test.want)
			}
		})
	}
}

func TestNotificationClusterChoiceRequiresCapabilityAndPermission(t *testing.T) {
	for _, scenario := range []string{"supported", "standalone", "unsupported", "replica", "update permission only", "cluster permission only", "busy", "installed", "unchecked", "rolling"} {
		t.Run(scenario, func(t *testing.T) {
			updater := &testUpdateController{status: update.Status{Available: true, LatestVersion: "1.2.0", CheckedAt: time.Now()}}
			server := updateTestServer(t, updater)
			controller := &testRollingUpdateController{supported: true, role: cluster.RolePrimary}
			server.SetClusterController(controller)
			server.securityEnabled = true
			permissions := []string{auth.PermissionUpdatesApply, auth.PermissionClusterWrite}
			switch scenario {
			case "standalone":
				server.cluster = nil
			case "unsupported":
				controller.supported = false
			case "replica":
				controller.role = cluster.RoleReplica
			case "update permission only":
				permissions = []string{auth.PermissionUpdatesApply}
			case "cluster permission only":
				permissions = []string{auth.PermissionClusterWrite}
			case "busy":
				updater.status.Phase = update.PhaseInstalling
			case "installed":
				updater.status.Installed = true
			case "unchecked":
				updater.status.CheckedAt = time.Time{}
			case "rolling":
				controller.rollout.Phase = "updating"
			}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, auth.Principal{Permissions: permissions}))
			view := server.updateView(request, updater.Status())
			response := httptest.NewRecorder()
			if err := pages.UpdateNotification(view).Render(request.Context(), response); err != nil {
				t.Fatal(err)
			}
			want := scenario == "supported"
			if view.CanUpdateCluster != want || strings.Contains(response.Body.String(), `data-update-scope-trigger`) != want {
				t.Fatalf("cluster choice = %t, want %t: %s", view.CanUpdateCluster, want, response.Body.String())
			}
		})
	}
}

func TestNotificationClusterUpdateStartsReviewedVersionAndOpensProgress(t *testing.T) {
	for _, scenario := range []string{"success", "stale release", "preflight failure"} {
		t.Run(scenario, func(t *testing.T) {
			updater := &testUpdateController{status: update.Status{Available: true, LatestVersion: "1.2.0", CheckedAt: time.Now()}}
			server := updateTestServer(t, updater)
			controller := &testRollingUpdateController{supported: true, role: cluster.RolePrimary}
			server.SetClusterController(controller)
			target := "1.2.0"
			if scenario == "stale release" {
				target = "1.1.0"
			}
			if scenario == "preflight failure" {
				controller.startErr = errors.New("ns2 must be online and fully synchronized")
			}
			response := serveUpdateForm(server, "/ui/updates/cluster", url.Values{"notification": {"true"}, "version": {target}})
			if scenario == "success" {
				if response.Code != http.StatusOK || response.Header().Get("HX-Redirect") != "/cluster" || len(controller.started) != 1 || controller.started[0] != target {
					t.Fatalf("cluster start = %d, redirect %q, started %v", response.Code, response.Header().Get("HX-Redirect"), controller.started)
				}
			} else {
				if response.Code != http.StatusConflict || response.Header().Get("HX-Redirect") != "" || len(controller.started) != 0 || !strings.Contains(response.Body.String(), `id="update-notification"`) {
					t.Fatalf("cluster rejection = %d %s", response.Code, response.Body.String())
				}
				if scenario == "preflight failure" && !strings.Contains(response.Body.String(), controller.startErr.Error()) {
					t.Fatal("notification omitted the reason the rollout could not start")
				}
			}
			if updater.installs != 0 {
				t.Fatal("cluster choice also triggered a separate node installation")
			}
		})
	}
}
