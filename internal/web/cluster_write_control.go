package web

import (
	"net/http"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/web/pages"
)

const replicaWriteMessage = "This node is a replica. Make control-plane changes on the cluster primary."

// refuseReplicaWrite answers a control-plane write that reached a replica,
// reporting true when it did. Such writes belong on the cluster primary.
func (server *Server) refuseReplicaWrite(writer http.ResponseWriter, request *http.Request, current *route) bool {
	if server.cluster == nil || !writeRequiresPrimary(server.cluster.Snapshot(), request.Method, current) {
		return false
	}
	server.logger.Warn("rejected control-plane write on replica", "path", request.URL.Path, "client", requestClientIP(request))
	switch {
	case tokenRequest(request.URL.Path):
		writeJSON(writer, http.StatusConflict, map[string]string{"error": replicaWriteMessage})
	case request.Header.Get("HX-Request") == "true":
		writer.WriteHeader(http.StatusConflict)
		if err := pages.Toast(replicaWriteMessage, "error").Render(request.Context(), writer); err != nil {
			server.logger.Error("render replica write rejection", "error", err)
		}
	default:
		http.Error(writer, replicaWriteMessage, http.StatusConflict)
	}
	return true
}

// writeRequiresPrimary reports whether a write to the route must be made on
// the cluster primary, which it must on a replica unless it is replicaLocal.
func writeRequiresPrimary(state cluster.State, method string, current *route) bool {
	return !safeMethod(method) && controlPlaneReadOnly(state) && !current.replicaLocal
}

func controlPlaneReadOnly(state cluster.State) bool {
	return state.Initialized && state.LocalRole == cluster.RoleReplica
}
