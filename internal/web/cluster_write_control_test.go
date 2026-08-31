package web

import (
	"net/http"
	"testing"

	"github.com/drudge/sable/internal/cluster"
)

type testReplicaClusterController struct{ clusterController }

func (testReplicaClusterController) Snapshot() cluster.State {
	return cluster.State{Initialized: true, LocalRole: cluster.RoleReplica}
}

func TestReplicaWriteControl(t *testing.T) {
	replica := cluster.State{Initialized: true, LocalRole: cluster.RoleReplica}
	tests := []struct {
		method  string
		path    string
		blocked bool
	}{
		{http.MethodGet, "/zones", false},
		{http.MethodPost, "/ui/zones/records/add", true},
		{http.MethodPost, "/ui/settings", true},
		{http.MethodPost, "/ui/administration/users", true},
		{http.MethodPost, "/login", false},
		{http.MethodPost, "/logout", false},
		// A replica offers the single sign-on button because sessions are
		// node-local. Blocking the click would leave the button present and
		// broken while password sign-in beside it works.
		{http.MethodPost, ssoStartPath, false},
		{http.MethodGet, ssoCallbackPath, false},
		{http.MethodPost, "/ui/administration/sessions/revoke", false},
		{http.MethodPost, "/ui/api-tokens", true},
		{http.MethodPost, "/ui/profile", true},
		{http.MethodPost, "/ui/profile/password", true},
		{http.MethodPost, "/ui/cache/flush", false},
		{http.MethodPost, "/ui/query", false},
		// A release lookup is read-only even though it uses POST to carry the
		// selected release channel.
		{http.MethodPost, "/ui/updates/check", false},
		{http.MethodPost, "/ui/updates/command-check", false},
		{http.MethodPost, "/ui/certificates/renew", false},
		// Integration settings are cluster-scoped and replicate from the
		// primary, so configuring them on a replica would be overwritten on the
		// next heartbeat. The single sign-on callback is the one node-local
		// part, and each node derives that for itself.
		{http.MethodPost, "/ui/integrations/sso/wizard", true},
		{http.MethodPost, "/ui/integrations/unifi/wizard", true},
		{http.MethodPost, "/ui/cluster/settings", false},
		{http.MethodPost, "/ui/cluster/leave", false},
		{http.MethodPost, "/ui/cluster/restart", false},
		{http.MethodDelete, "/api/v1/cluster/membership", false},
		{http.MethodPost, "/api/v1/cluster/sync", false},
		{http.MethodPost, "/ui/cluster/nodes/local/promote", false},
	}
	for _, test := range tests {
		if got := writeRequiresPrimary(replica, test.method, test.path); got != test.blocked {
			t.Errorf("%s %s blocked = %t, want %t", test.method, test.path, got, test.blocked)
		}
	}
	if writeRequiresPrimary(cluster.State{Initialized: true, LocalRole: cluster.RolePrimary}, http.MethodPost, "/ui/settings") {
		t.Fatal("primary write was blocked")
	}
}
