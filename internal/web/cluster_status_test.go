package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/cluster"
)

// Embedding the unused controller methods makes any accidental call to the
// full configuration path fail, including LocalConfiguration's disk reads.
type statusOnlyCluster struct{ clusterController }

func (statusOnlyCluster) Snapshot() cluster.State {
	return cluster.State{Initialized: true, NetworkReady: true, NodeID: "primary", ClusterID: "cluster", ClusterDomain: "example.test", LocalRole: cluster.RolePrimary, PrimaryID: "primary", Generation: 7, ObservedAt: time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC), Nodes: []cluster.Node{{ID: "primary", Name: "Primary DNS", Role: cluster.RolePrimary, CurrentGeneration: 7, AppliedGeneration: 7}}}
}

type statusUpdateCluster struct {
	statusOnlyCluster
	clusterUpdateController
}

func (statusUpdateCluster) RollingUpdatesSupported() bool        { return true }
func (statusUpdateCluster) RolloutStatus() cluster.RolloutStatus { return cluster.RolloutStatus{} }

func TestClusterLiveStatusDoesNotBuildConsoleOrReadLocalConfiguration(t *testing.T) {
	for _, controller := range []clusterController{statusOnlyCluster{}, statusUpdateCluster{}} {

		// Zones, stats, certificates and local cluster configuration are absent.
		// Rolling updates retain their inexpensive configuration preferences.
		server := &Server{cluster: controller, config: testConfiguration{}}
		request := httptest.NewRequest(http.MethodGet, "/ui/cluster/status", nil)
		response := httptest.NewRecorder()
		server.clusterLiveStatus(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status = %d", response.Code)
		}
		for _, want := range []string{`id="cluster-live-status"`, "Primary DNS", "example.test", "Generation", `id="cluster-updates"`} {
			if !strings.Contains(response.Body.String(), want) {
				t.Errorf("missing %q", want)
			}
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Error("missing no-store")
		}
		if response.Header().Get("HX-Retarget") != "" {
			t.Error("initialized status retargeted full page")
		}
	}
}

func BenchmarkClusterLiveStatus(b *testing.B) {
	server := &Server{cluster: statusUpdateCluster{}, config: testConfiguration{}}
	request := httptest.NewRequest(http.MethodGet, "/ui/cluster/status", nil)
	b.ReportAllocs()
	for b.Loop() {
		server.clusterLiveStatus(httptest.NewRecorder(), request)
	}
}
