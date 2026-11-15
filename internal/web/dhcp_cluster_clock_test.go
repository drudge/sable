package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/cluster"
)

// A replica whose heartbeats arrive but fail the clock window is up and
// serving its ranges. The Cluster page says its clock is out of step, offers
// no Take Over, and the console and API refuse one like an online node's,
// since it would never learn it lost the range (F76, D107).
func TestDHCPTakeOverRefusesANodeOutOfStepWithTheClock(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newDHCPClusterConsoleServer(t, "node-a", "")
	state := server.cluster.Snapshot()
	state.Nodes = append([]cluster.Node(nil), state.Nodes...)
	state.Nodes[1].SyncState, state.Nodes[1].ClockOffsetSeconds = cluster.SyncClock, 300
	server.SetClusterController(testDHCPClusterController{state: &state, promoted: &[]string{}})

	page := dhcpConsoleRequest(t, server, http.MethodGet, "/cluster", nil).Body.String()
	expectContains(t, "Cluster page", page, "Clock out of step", "Clock 5m0s ahead; set it by NTP to sync")
	if strings.Contains(dhcpConsoleRequest(t, server, http.MethodGet, "/ui/cluster/node?name=ns2", nil).Body.String(), "Take Over DHCP Ranges") {
		t.Error("a node that is up with its clock out of step offers Take Over")
	}
	response := dhcpConsoleRequest(t, server, http.MethodPost, "/ui/dhcp/takeover", url.Values{"node": {"node-b"}})
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "clock is out of step") {
		t.Fatalf("console take over = %d: %s", response.Code, response.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/dhcp/takeover", strings.NewReader(`{"node":"node-b"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity || !strings.Contains(recorder.Body.String(), "clock is out of step") {
		t.Fatalf("POST /api/v1/dhcp/takeover = %d: %s", recorder.Code, recorder.Body.String())
	}
	if configuration.snapshot.Config.DHCP.Scopes[0].Ranges[1].Node != "node-b" {
		t.Fatal("the range moved")
	}
}
