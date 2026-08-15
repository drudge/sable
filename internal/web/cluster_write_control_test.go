package web

import (
	"net/http"
	"testing"

	"github.com/drudge/sable/internal/cluster"
)

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
		{http.MethodPost, "/ui/administration/sessions/revoke", false},
		{http.MethodPost, "/ui/api-tokens", true},
		{http.MethodPost, "/ui/profile", true},
		{http.MethodPost, "/ui/profile/password", true},
		{http.MethodPost, "/ui/cache/flush", false},
		{http.MethodPost, "/ui/query", false},
		{http.MethodPost, "/ui/certificates/renew", false},
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
