package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/update"
	"github.com/drudge/sable/internal/version"
	"github.com/drudge/sable/internal/web/pages"
)

// updateController resolves and installs published Sable releases.
type updateController interface {
	Status() update.Status
	Check(context.Context, bool) (update.Status, error)
	Install(bool) error
	ServiceManaged() bool
}

func (server *Server) SetUpdateController(controller updateController) {
	server.updates = controller
}

// updatePanel renders the current update state. The panel polls this endpoint
// while a check or an installation is running.
func (server *Server) updatePanel(writer http.ResponseWriter, request *http.Request) {
	server.renderUpdatePanel(writer, request, server.updateStatus(), "")
}

// checkForUpdates resolves the newest published release. It runs inline
// because it is only a pair of GitHub metadata requests.
func (server *Server) checkForUpdates(writer http.ResponseWriter, request *http.Request) {
	if server.updates == nil {
		server.renderUpdatePanel(writer, request, update.Status{}, "")
		return
	}
	includePreRelease := updatePreReleaseRequested(writer, request)
	server.rememberReleaseChannel(request, includePreRelease)
	status, _ := server.resolveUpdateCheck(request, includePreRelease)
	server.renderUpdatePanel(writer, request, status, "")
}

// checkForUpdatesCommand runs the same release lookup as the About page, but
// reports the result as a global toast so a palette action works from any page.
// It uses the configured release channel without changing that preference.
func (server *Server) checkForUpdatesCommand(writer http.ResponseWriter, request *http.Request) {
	if server.updates == nil {
		writeFragmentStatus(writer, http.StatusNotImplemented)
		_ = pages.Toast("Updates are unavailable on this server.", "error").Render(request.Context(), writer)
		return
	}
	includePreRelease := server.config.Current().Config.Updates.PreRelease
	status, err := server.resolveUpdateCheck(request, includePreRelease)
	server.renderUpdateCheckToast(writer, request, status, err)
}

func (server *Server) resolveUpdateCheck(request *http.Request, includePreRelease bool) (update.Status, error) {
	status, err := server.updates.Check(request.Context(), includePreRelease)
	if err != nil && !errors.Is(err, update.ErrUpdateInProgress) {
		server.logger.Warn("check for Sable updates", "error", err)
	}
	server.recordControlPlaneAudit(request, "update.check", "checked for a newer Sable release")
	return status, err
}

func (server *Server) renderUpdateCheckToast(writer http.ResponseWriter, request *http.Request, status update.Status, checkErr error) {
	view := server.updateView(request, status)
	message, variant, responseStatus := "Update check completed.", "success", http.StatusOK
	switch {
	case checkErr != nil && !errors.Is(checkErr, update.ErrUpdateInProgress):
		message, variant, responseStatus = checkErr.Error(), "error", http.StatusBadGateway
	case view.Error != "":
		message, variant, responseStatus = view.Error, "error", http.StatusBadGateway
	case view.Busy || errors.Is(checkErr, update.ErrUpdateInProgress):
		message = "An update check is already in progress."
	case view.Available:
		message = fmt.Sprintf("Sable v%s is available. Open About to review and install it.", view.LatestVersion)
	case view.UpToDate:
		message = "Sable is up to date."
	}
	writeFragmentStatus(writer, responseStatus)
	_ = pages.Toast(message, variant).Render(request.Context(), writer)
}

// installUpdate replaces the installed executable with the newest release.
// Sable keeps serving the running build until it is restarted.
func (server *Server) installUpdate(writer http.ResponseWriter, request *http.Request) {
	if server.updates == nil {
		server.renderUpdatePanel(writer, request, update.Status{}, "Updates are unavailable on this server.")
		return
	}
	includePreRelease := updatePreReleaseRequested(writer, request)
	if err := server.updates.Install(includePreRelease); err != nil {
		server.renderUpdatePanel(writer, request, server.updateStatus(), err.Error())
		return
	}
	server.logger.Warn("Sable update requested from the console", "client", requestClientIP(request))
	server.recordControlPlaneAudit(request, "update.install", "started installing a newer Sable release")
	server.renderUpdatePanel(writer, request, server.updateStatus(), "")
}

// rememberReleaseChannel stores the operator's pre-release choice so that a
// restart does not silently drop a server back to stable-only checks. The
// manager keeps it for the life of the process; only an operator who may
// install a release writes it to the configuration.
func (server *Server) rememberReleaseChannel(request *http.Request, includePreRelease bool) {
	if server.config.Current().Config.Updates.PreRelease == includePreRelease {
		return
	}
	// A replica may use either release channel for its node-local lookup, but
	// the preference is cluster configuration and must be changed on the
	// primary. The selected channel remains in the update manager's status for
	// subsequent checks during this process lifetime.
	if server.cluster != nil && controlPlaneReadOnly(server.cluster.Snapshot()) {
		return
	}
	if principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal); ok &&
		!auth.HasPermission(principal, auth.PermissionUpdatesApply) {
		return
	}
	editor, ok := server.config.(settingsEditor)
	if !ok {
		return
	}
	if err := editor.Update(request.Context(), func(candidate *config.Config) error {
		candidate.Updates.PreRelease = includePreRelease
		return nil
	}); err != nil {
		server.logger.Warn("remember the update release channel", "error", err)
	}
}

func (server *Server) updateStatus() update.Status {
	if server.updates == nil {
		return update.Status{}
	}
	return server.updates.Status()
}

// updatePreReleaseRequested reports whether the operator asked for
// pre-release builds. A malformed form falls back to stable releases.
func updatePreReleaseRequested(writer http.ResponseWriter, request *http.Request) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		return false
	}
	return request.FormValue("pre_release") == "true"
}

func (server *Server) renderUpdatePanel(
	writer http.ResponseWriter,
	request *http.Request,
	status update.Status,
	errorMessage string,
) {
	view := server.updateView(request, status)
	if errorMessage != "" {
		view.Error = errorMessage
	}
	if err := pages.UpdatePanel(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render update panel", "error", err)
	}
}

func (server *Server) updateView(request *http.Request, status update.Status) pages.UpdateView {
	view := pages.UpdateView{
		Available:         status.Available,
		Blocked:           status.Blocked,
		Busy:              status.Busy(),
		Checked:           status.Checked(),
		CurrentVersion:    status.CurrentVersion,
		Error:             status.Error,
		IncludePreRelease: status.IncludePreRelease,
		Installed:         status.Installed,
		LatestVersion:     status.LatestVersion,
		Phase:             string(status.Phase),
		PreRelease:        status.PreRelease,
		Progress:          status.Progress,
		ReleaseURL:        status.ReleaseURL,
		Supported:         server.updates != nil,
		UpToDate:          status.UpToDate(),
	}
	if view.CurrentVersion == "" {
		view.CurrentVersion = version.Current().Release
	}
	if !status.CheckedAt.IsZero() {
		view.CheckedAt = pages.FormatDateTime(status.CheckedAt, requestTimeDisplay(request))
	}
	if server.updates != nil {
		view.ServiceManaged = server.updates.ServiceManaged()
	}
	view.CanCheck, view.CanApply = !server.securityEnabled, !server.securityEnabled
	if principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal); ok {
		view.CanCheck = auth.HasPermission(principal, auth.PermissionUpdatesRead)
		view.CanApply = auth.HasPermission(principal, auth.PermissionUpdatesApply)
		view.CSRFToken = principal.CSRFToken
	}
	view.CanRestart = view.CanApply && server.restart != nil
	return view
}
