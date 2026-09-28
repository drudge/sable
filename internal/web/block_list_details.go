package web

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/web/pages"
)

// blockListPanel fills the details panel for one block list.
func (server *Server) blockListPanel(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	view := server.blockListDrawerView(request, request.URL.Query().Get("name"))
	if err := pages.BlockListDrawer(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render block list panel", "error", err)
	}
}

// blockListDrawerView describes one configured list: what the Blocking page
// shows in its row, plus the update history the row only summarizes.
func (server *Server) blockListDrawerView(request *http.Request, name string) pages.BlockListDrawerView {
	page := server.blockingView(request, "", "", "lists")
	view := pages.BlockListDrawerView{TimeDisplay: page.Console.TimeDisplay, CanRefresh: page.Console.CanWriteBlocking}
	index := slices.IndexFunc(page.Lists, func(list pages.BlockListSourceView) bool { return list.Name == name })
	if index < 0 {
		view.Missing = true
		return view
	}
	view.List = page.Lists[index]
	if view.List.URL == "" {
		view.LastUpdate = server.blockListFileChanged(view.List)
		return view
	}
	status := server.blockLists.Status()
	view.NextUpdate = status.NextUpdate
	for _, source := range status.Sources {
		if source.URL != view.List.URL {
			continue
		}
		view.LastUpdate = source.LastSuccess
		view.ConsecutiveFailures, view.LastError = source.ConsecutiveFailures, source.LastError
		// The schedule keeps whole seconds, so a retry it was set to still
		// counts as the next update.
		if source.InBackoff(time.Now()) && (view.NextUpdate.IsZero() || !source.RetryAfter.Truncate(time.Second).After(view.NextUpdate)) {
			view.NextUpdate, view.Retrying = source.RetryAfter, true
		}
	}
	// Download history starts with the process, so a list that has not
	// updated since then is dated by its cached copy instead.
	if view.LastUpdate.IsZero() {
		view.LastUpdate = server.blockListFileChanged(view.List)
	}
	return view
}

// blockListFileChanged is when a list's file on disk last changed, or zero
// when it cannot be read.
func (server *Server) blockListFileChanged(list pages.BlockListSourceView) time.Time {
	path := list.Path
	if path == "" {
		path = list.ConfiguredPath
	}
	if path == "" {
		return time.Time{}
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(server.baseDirectory, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// refreshBlockList downloads one list now and recompiles, from its panel.
// The panel shows the result, and the Blocking page beneath it updates with
// the same response.
func (server *Server) refreshBlockList(writer http.ResponseWriter, request *http.Request) {
	started := time.Now()
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.logBlockingOperation(request, err, "duration", time.Since(started))
		writeBlockingErrorStatus(writer, request, http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(request.FormValue("name"))
	sources := remoteBlockSources(server.config.Current().Config.Blocking)
	index := slices.IndexFunc(sources, func(source blockcompiler.RemoteSource) bool { return source.Name == name })
	if index < 0 {
		err := errors.New("block list is not configured or has no URL")
		server.logBlockingOperation(request, err, "list", name, "duration", time.Since(started))
		server.renderBlockListRefresh(writer, request, http.StatusNotFound, name, "", "This block list is not configured, or it is a local file with nothing to download.")
		return
	}
	err := server.blockLists.RefreshSource(request.Context(), sources[index], server.reload)
	// A failed download retries on its own backoff, sooner than the next full
	// update when that is a while off.
	if retry := server.blockLists.RetryAt(); !retry.IsZero() {
		if next := server.blockLists.Status().NextUpdate; next.IsZero() || retry.Before(next) {
			server.blockLists.Schedule(retry)
		}
	}
	if err != nil {
		server.logBlockListHealth()
		server.logBlockingOperation(request, err, "list", name, "duration", time.Since(started))
		server.renderBlockListRefresh(writer, request, http.StatusUnprocessableEntity, name, "", err.Error())
		return
	}
	server.logBlockingOperation(request, nil, "list", name, "domains", server.stats.Stats().BlockedDomains, "duration", time.Since(started))
	server.recordControlPlaneAudit(request, blockingMutationAction(request.URL.Path), fmt.Sprintf("refreshed block list %s", name))
	server.renderBlockListRefresh(writer, request, http.StatusOK, name, name+" downloaded and compiled", "")
}

func (server *Server) renderBlockListRefresh(writer http.ResponseWriter, request *http.Request, status int, name, message, errorMessage string) {
	view := server.blockListDrawerView(request, name)
	view.Message, view.Error = message, errorMessage
	page := server.blockingView(request, "", "", "lists")
	page.OutOfBand = true
	writeFragmentStatus(writer, status)
	if err := pages.BlockListDrawer(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render block list panel", "error", err)
		return
	}
	if err := pages.BlockingContent(page).Render(request.Context(), writer); err != nil {
		server.logger.Error("render blocking page", "error", err)
	}
}
