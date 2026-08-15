package web

import "net/http"

// restartServer performs the controlled restart the console offers after a
// cluster change or an installed update.
func (server *Server) restartServer(writer http.ResponseWriter, request *http.Request) {
	if server.restart == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{
			"error": "managed restart is unavailable; restart Sable with its service manager",
		})
		return
	}
	firstRequest := server.restartRequested.CompareAndSwap(false, true)
	if firstRequest {
		server.logger.Warn("controlled restart requested", "client", requestClientIP(request))
		server.recordControlPlaneAudit(request, "server.restart", "requested a controlled Sable restart")
	}
	writeJSON(writer, http.StatusAccepted, map[string]string{
		"status":      "restarting",
		"instance_id": server.instanceID,
	})
	if firstRequest {
		server.restart()
	}
}
