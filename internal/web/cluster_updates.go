package web

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/web/pages"
	"golang.org/x/mod/semver"
)

type clusterUpdateController interface {
	RollingUpdatesSupported() bool
	RolloutStatus() cluster.RolloutStatus
	StartRollout(context.Context, string) error
	StopRollout() error
}

func (server *Server) startClusterUpdate(writer http.ResponseWriter, request *http.Request) {
	controller, ok := server.cluster.(clusterUpdateController)
	if !ok {
		http.Error(writer, "Cluster updates are unavailable", http.StatusNotImplemented)
		return
	}
	if !server.canManageClusterUpdate(request) {
		http.Error(writer, "Cluster and update permissions are required", http.StatusForbidden)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "Invalid update request", http.StatusBadRequest)
		return
	}
	status := server.updateStatus()
	target := request.FormValue("version")
	if target == "" || target != status.LatestVersion || !status.Checked() || status.Busy() || status.Error != "" {
		server.renderClusterUpdateResult(writer, request, http.StatusConflict, "", "Check for updates on About and review the release before starting a rollout.")
		return
	}
	if err := controller.StartRollout(request.Context(), target); err != nil {
		server.renderClusterUpdateResult(writer, request, http.StatusConflict, "", err.Error())
		return
	}
	server.recordControlPlaneAudit(request, "update.cluster.start", "started rolling cluster update to "+target)
	server.renderClusterUpdateResult(writer, request, http.StatusOK, "Rolling update started. Replicas update one at a time; the primary updates last.", "")
}

func (server *Server) renderClusterUpdateResult(writer http.ResponseWriter, request *http.Request, status int, message, errorMessage string) {
	if request.FormValue("notification") != "true" {
		server.renderClusterMutation(writer, request, status, message, errorMessage)
		return
	}
	if errorMessage != "" {
		writeFragmentStatus(writer, status)
		server.renderUpdatePanel(writer, request, server.updateStatus(), errorMessage)
		return
	}
	// The Cluster page already follows every node through installation and
	// restart, including when the notification was opened on another page.
	writer.Header().Set("HX-Redirect", "/cluster")
	writer.WriteHeader(http.StatusOK)
}

func (server *Server) stopClusterUpdate(writer http.ResponseWriter, request *http.Request) {
	controller, ok := server.cluster.(clusterUpdateController)
	if !ok {
		http.Error(writer, "Cluster updates are unavailable", http.StatusNotImplemented)
		return
	}
	if !server.canManageClusterUpdate(request) {
		http.Error(writer, "Cluster and update permissions are required", http.StatusForbidden)
		return
	}
	if err := controller.StopRollout(); err != nil {
		server.renderClusterMutation(writer, request, http.StatusConflict, "", err.Error())
		return
	}
	server.recordControlPlaneAudit(request, "update.cluster.stop", "stopped the rolling cluster update")
	server.renderClusterMutation(writer, request, http.StatusOK, "Rollout stopped. An update already in progress may finish.", "")
}

func (server *Server) canManageClusterUpdate(request *http.Request) bool {
	if !server.securityEnabled {
		return true
	}
	principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal)
	return ok && auth.HasPermission(principal, auth.PermissionUpdatesApply) && auth.HasPermission(principal, auth.PermissionClusterWrite)
}

func (server *Server) clusterUpdateView(request *http.Request) pages.ClusterUpdateView {
	controller, ok := server.cluster.(clusterUpdateController)
	if !ok {
		return pages.ClusterUpdateView{}
	}
	status := server.updateStatus()
	state := server.cluster.Snapshot()
	rollout := controller.RolloutStatus()
	if rollout.ClusterID != state.ClusterID || rollout.PrimaryID != state.PrimaryID || state.LocalRole != cluster.RolePrimary {
		rollout = cluster.RolloutStatus{}
	}
	view := pages.ClusterUpdateView{
		Supported: controller.RollingUpdatesSupported(),
		Rollout:   rollout,
		CanApply:  server.canManageClusterUpdate(request),
		Release:   server.updateView(request, status),
	}
	if state.LocalRole != cluster.RolePrimary {
		view.CanApply = false
	}
	if status.Checked() && !status.Busy() && status.Error == "" && slices.ContainsFunc(state.Nodes, func(node cluster.Node) bool {
		current := "v" + strings.TrimPrefix(node.Version, "v")
		latest := "v" + strings.TrimPrefix(status.LatestVersion, "v")
		return semver.IsValid(current) && semver.Compare(latest, current) > 0
	}) {
		view.Version = status.LatestVersion
	}
	return view
}
