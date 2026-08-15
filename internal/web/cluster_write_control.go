package web

import (
	"net/http"
	"strings"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/web/pages"
)

const replicaWriteMessage = "This node is a replica. Make control-plane changes on the cluster primary."

func (server *Server) primaryWriteControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if server.cluster == nil || !writeRequiresPrimary(server.cluster.Snapshot(), request.Method, request.URL.Path) {
			next.ServeHTTP(writer, request)
			return
		}
		server.logger.Warn("rejected control-plane write on replica", "path", request.URL.Path, "client", requestClientIP(request))
		if tokenRequest(request.URL.Path) {
			writeJSON(writer, http.StatusConflict, map[string]string{"error": replicaWriteMessage})
			return
		}
		if request.Header.Get("HX-Request") == "true" {
			writer.WriteHeader(http.StatusConflict)
			if err := pages.Toast(replicaWriteMessage, "error").Render(request.Context(), writer); err != nil {
				server.logger.Error("render replica write rejection", "error", err)
			}
			return
		}
		http.Error(writer, replicaWriteMessage, http.StatusConflict)
	})
}

func writeRequiresPrimary(state cluster.State, method, path string) bool {
	if safeMethod(method) || !state.Initialized || state.LocalRole != cluster.RoleReplica {
		return false
	}
	return !replicaLocalWrite(path)
}

func replicaLocalWrite(path string) bool {
	switch {
	case path == "/login", path == "/logout", path == "/ui/administration/sessions/revoke", path == "/ui/query":
		return true
	case strings.HasPrefix(path, "/ui/cache/"), strings.HasPrefix(path, "/api/v1/cache/"):
		return true
	case strings.HasPrefix(path, "/ui/certificates/"):
		return true
	case path == "/ui/cluster/settings", path == "/ui/cluster/leave", path == "/ui/cluster/restart", path == "/api/v1/cluster/membership", path == "/api/v1/cluster/sync":
		return true
	case strings.HasSuffix(path, "/promote") &&
		(strings.HasPrefix(path, "/ui/cluster/nodes/") || strings.HasPrefix(path, "/api/v1/cluster/nodes/")):
		return true
	default:
		return false
	}
}
