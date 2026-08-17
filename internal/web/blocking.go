package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"net/http"

	"github.com/drudge/sable/internal/auth"
	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/web/pages"
)

const (
	maximumDomainImportBytes = 4 << 20
	maximumImportedDomains   = 100_000
)

type blockingEditor interface {
	UpdateBlocking(context.Context, func(*config.Blocking) error) error
}

type blockingPauser interface {
	PauseBlocking(time.Duration) time.Time
	ResumeBlocking()
	BlockingPausedUntil() time.Time
}

func (server *Server) blockingPage(writer http.ResponseWriter, request *http.Request) {
	view := server.blockingView(request, "", "", request.URL.Query().Get("tab"))
	if err := pages.BlockingPage(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render blocking page", "error", err)
	}
}

func (server *Server) blockingView(request *http.Request, message, errorMessage, activeTab string) pages.BlockingPageView {
	console := server.consoleView(request)
	snapshot := server.config.Current()
	stats := server.stats.Stats()
	if activeTab != "domains" && activeTab != "allowed" {
		activeTab = "lists"
	}
	sourceStats := make(map[string]pages.BlockListSourceView, len(stats.BlockSources))
	for _, source := range stats.BlockSources {
		sourceStats[source.Name] = pages.BlockListSourceView{
			Name: source.Name, Path: source.Path, Lines: source.Lines,
			Accepted: source.Accepted, Invalid: source.Invalid,
		}
	}
	updateStatus := server.blockLists.Status()
	health := make(map[string]blockcompiler.SourceHealth, len(updateStatus.Sources))
	for _, source := range updateStatus.Sources {
		health[source.URL] = source
	}
	lists := make([]pages.BlockListSourceView, 0, len(snapshot.Config.Blocking.Lists))
	for _, list := range snapshot.Config.Blocking.Lists {
		view := sourceStats[list.Name]
		view.Name = list.Name
		view.ConfiguredPath = list.Path
		view.URL = list.URL
		view.Format = list.Format
		view.Healthy = true
		if source, tracked := health[list.URL]; tracked && !source.Healthy() {
			view.Healthy = false
			view.HealthSummary = blockListHealthSummary(source, time.Now())
			view.HealthDetail = blockListHealthDetail(source)
		}
		lists = append(lists, view)
	}
	pausedUntil := time.Time{}
	if pauser, ok := server.stats.(blockingPauser); ok {
		pausedUntil = pauser.BlockingPausedUntil()
		if !time.Now().Before(pausedUntil) {
			pausedUntil = time.Time{}
		}
	}
	return pages.BlockingPageView{
		Console: console, Enabled: snapshot.Config.Blocking.Enabled, PausedUntil: pausedUntil,
		CompiledDomains: stats.BlockedDomains,
		BlockedQueries:  server.history.blockedSince(request.Context(), time.Hour, time.Now(), stats),
		Domains:         append([]string(nil), snapshot.Config.Blocking.Domains...),
		AllowedDomains:  append([]string(nil), snapshot.Config.Blocking.AllowedDomains...), Lists: lists,
		RemoteListCount: len(remoteBlockSources(snapshot.Config.Blocking)),
		UpdateHours:     max(1, int(snapshot.Config.Blocking.UpdateInterval.Duration/time.Hour)),
		LastUpdate:      updateStatus.LastUpdate, NextUpdate: updateStatus.NextUpdate, Updating: updateStatus.Updating,
		DegradedLists: updateStatus.Degraded,
		ActiveTab:     activeTab, Message: message, Error: errorMessage,
	}
}

// blockListHealthSummary is the short badge shown next to a failing list.
func blockListHealthSummary(source blockcompiler.SourceHealth, now time.Time) string {
	attempts := "1 failed update"
	if source.ConsecutiveFailures > 1 {
		attempts = fmt.Sprintf("%d failed updates", source.ConsecutiveFailures)
	}
	if source.RetryAfter.After(now) {
		return fmt.Sprintf("%s · retrying in %s", attempts, formatApproximateDuration(source.RetryAfter.Sub(now)))
	}
	return attempts + " · retrying shortly"
}

// blockListHealthDetail is the tooltip: why it failed and how stale it is.
func blockListHealthDetail(source blockcompiler.SourceHealth) string {
	detail := source.LastError
	if detail == "" {
		detail = "the last update attempt failed"
	}
	if source.LastSuccess.IsZero() {
		return detail + " (this list has never updated successfully)"
	}
	return fmt.Sprintf("%s (last successful update %s)", detail, source.LastSuccess.Format(time.RFC3339))
}

func formatApproximateDuration(remaining time.Duration) string {
	switch {
	case remaining >= time.Hour:
		return fmt.Sprintf("%dh", int(remaining.Round(time.Hour)/time.Hour))
	case remaining >= time.Minute:
		return fmt.Sprintf("%dm", int(remaining.Round(time.Minute)/time.Minute))
	default:
		return "under a minute"
	}
}

func (server *Server) updateBlocking(writer http.ResponseWriter, request *http.Request, activeTab, success string, mutate func(*config.Blocking) error) {
	started := time.Now()
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.logBlockingOperation(request, err, "duration", time.Since(started))
		writeBlockingErrorStatus(writer, request, http.StatusBadRequest)
		_ = pages.BlockingContent(server.blockingView(request, "", "Invalid blocking form.", activeTab)).Render(request.Context(), writer)
		return
	}
	editor, ok := server.config.(blockingEditor)
	if !ok {
		server.logBlockingOperation(request, errors.New("configuration source is read-only"), "duration", time.Since(started))
		writeBlockingErrorStatus(writer, request, http.StatusNotImplemented)
		_ = pages.BlockingContent(server.blockingView(request, "", "This configuration source is read-only.", activeTab)).Render(request.Context(), writer)
		return
	}
	if err := editor.UpdateBlocking(request.Context(), mutate); err != nil {
		server.logBlockingOperation(request, err, "duration", time.Since(started))
		writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
		_ = pages.BlockingContent(server.blockingView(request, "", err.Error(), activeTab)).Render(request.Context(), writer)
		return
	}
	server.logBlockingOperation(request, nil, "duration", time.Since(started))
	server.recordControlPlaneAudit(request, blockingMutationAction(request.URL.Path), success)
	_ = pages.BlockingContent(server.blockingView(request, success, "", activeTab)).Render(request.Context(), writer)
}

func writeBlockingErrorStatus(writer http.ResponseWriter, request *http.Request, status int) {
	if request.Header.Get("HX-Request") == "true" {
		return
	}
	writer.WriteHeader(status)
}

func (server *Server) logBlockingOperation(request *http.Request, operationErr error, attributes ...any) {
	base := []any{
		"operation", blockingMutationAction(request.URL.Path),
		"client", requestClientIP(request),
	}
	if principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal); ok && principal.Username != "" {
		base = append(base, "user", principal.Username)
	}
	if domain := strings.TrimSpace(request.FormValue("domain")); domain != "" {
		base = append(base, "domain", domain)
	}
	if name := strings.TrimSpace(request.FormValue("name")); name != "" {
		base = append(base, "name", name)
	}
	base = append(base, attributes...)
	if operationErr != nil {
		base = append(base, "error", operationErr)
		server.logger.Warn("blocking operation failed", base...)
		return
	}
	server.logger.Info("blocking operation completed", base...)
}

func blockingMutationAction(path string) string {
	actions := map[string]string{
		"/ui/blocking/reload":         "blocking.reload",
		"/ui/blocking/domains/add":    "blocking.blocked_domain.add",
		"/ui/blocking/domains/delete": "blocking.blocked_domain.delete",
		"/ui/blocking/domains/flush":  "blocking.blocked_domain.clear",
		"/ui/blocking/domains/import": "blocking.blocked_domain.import",
		"/ui/blocking/domains/export": "blocking.blocked_domain.export",
		"/ui/blocking/allowed/add":    "blocking.allowed_domain.add",
		"/ui/blocking/allowed/delete": "blocking.allowed_domain.delete",
		"/ui/blocking/allowed/flush":  "blocking.allowed_domain.clear",
		"/ui/blocking/allowed/import": "blocking.allowed_domain.import",
		"/ui/blocking/allowed/export": "blocking.allowed_domain.export",
		"/ui/blocking/lists/add":      "blocking.list.add",
		"/ui/blocking/lists/delete":   "blocking.list.delete",
		"/ui/blocking/lists/update":   "blocking.list.update",
		"/ui/blocking/toggle":         "blocking.toggle",
		"/ui/blocking/pause":          "blocking.pause",
		"/ui/blocking/resume":         "blocking.resume",
		"/ui/blocking/query-domain":   "blocking.query_log_policy",
	}
	if action := actions[path]; action != "" {
		return action
	}
	return "blocking.update"
}

func (server *Server) addBlockedDomain(writer http.ResponseWriter, request *http.Request) {
	server.addPolicyDomain(writer, request, false)
}

func (server *Server) addAllowedDomain(writer http.ResponseWriter, request *http.Request) {
	server.addPolicyDomain(writer, request, true)
}

func (server *Server) addQueryPolicyDomain(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.logBlockingOperation(request, err)
		_ = pages.Toast("Invalid domain action.", "error").Render(request.Context(), writer)
		return
	}
	allowed := request.FormValue("action") == "allow"
	domain, err := normalizePolicyEntry(request.FormValue("domain"))
	if err != nil {
		server.logBlockingOperation(request, err)
		_ = pages.Toast(err.Error(), "error").Render(request.Context(), writer)
		return
	}
	editor, ok := server.config.(blockingEditor)
	if !ok {
		server.logBlockingOperation(request, errors.New("configuration source is read-only"))
		_ = pages.Toast("This configuration source is read-only.", "error").Render(request.Context(), writer)
		return
	}
	err = editor.UpdateBlocking(request.Context(), func(policy *config.Blocking) error {
		target := &policy.Domains
		if allowed {
			target = &policy.AllowedDomains
		}
		if !slices.Contains(*target, domain) {
			*target = append(*target, domain)
			slices.Sort(*target)
		}
		return nil
	})
	if err != nil {
		server.logBlockingOperation(request, err)
		_ = pages.Toast(err.Error(), "error").Render(request.Context(), writer)
		return
	}
	action := "blocked"
	if allowed {
		action = "allowed"
	}
	server.logBlockingOperation(request, nil, "action", action)
	server.recordControlPlaneAudit(request, blockingMutationAction(request.URL.Path), domain+" marked "+action)
	_ = pages.Toast(domain+" is now "+action+".", "success").Render(request.Context(), writer)
}

func (server *Server) addPolicyDomain(writer http.ResponseWriter, request *http.Request, allowed bool) {
	tab, success := "domains", "Blocked domain added"
	if allowed {
		tab, success = "allowed", "Allowed domain added"
	}
	server.updateBlocking(writer, request, tab, success, func(policy *config.Blocking) error {
		domain, err := normalizePolicyEntry(request.FormValue("domain"))
		if err != nil {
			return err
		}
		target := &policy.Domains
		if allowed {
			target = &policy.AllowedDomains
		}
		if slices.Contains(*target, domain) {
			if allowed {
				return errors.New("domain is already allowed")
			}
			return errors.New("domain is already blocked")
		}
		*target = append(*target, domain)
		return nil
	})
}

func (server *Server) deleteBlockedDomain(writer http.ResponseWriter, request *http.Request) {
	server.deletePolicyDomain(writer, request, false)
}

func (server *Server) deleteAllowedDomain(writer http.ResponseWriter, request *http.Request) {
	server.deletePolicyDomain(writer, request, true)
}

func (server *Server) deletePolicyDomain(writer http.ResponseWriter, request *http.Request, allowed bool) {
	tab, success := "domains", "Blocked domain removed"
	if allowed {
		tab, success = "allowed", "Allowed domain removed"
	}
	server.updateBlocking(writer, request, tab, success, func(policy *config.Blocking) error {
		domain, err := normalizePolicyEntry(request.FormValue("domain"))
		if err != nil {
			return err
		}
		target := &policy.Domains
		if allowed {
			target = &policy.AllowedDomains
		}
		index := slices.Index(*target, domain)
		if index < 0 {
			return errors.New("domain was not found")
		}
		*target = slices.Delete(*target, index, index+1)
		return nil
	})
}

func (server *Server) flushBlockedDomains(writer http.ResponseWriter, request *http.Request) {
	server.flushPolicyDomains(writer, request, false)
}

func (server *Server) flushAllowedDomains(writer http.ResponseWriter, request *http.Request) {
	server.flushPolicyDomains(writer, request, true)
}

func (server *Server) flushPolicyDomains(writer http.ResponseWriter, request *http.Request, allowed bool) {
	tab, success := "domains", "Custom blocked domains cleared"
	if allowed {
		tab, success = "allowed", "Allowed domains cleared"
	}
	server.updateBlocking(writer, request, tab, success, func(policy *config.Blocking) error {
		if allowed {
			policy.AllowedDomains = nil
		} else {
			policy.Domains = nil
		}
		return nil
	})
}

func (server *Server) importBlockedDomains(writer http.ResponseWriter, request *http.Request) {
	server.importPolicyDomains(writer, request, false)
}

func (server *Server) importAllowedDomains(writer http.ResponseWriter, request *http.Request) {
	server.importPolicyDomains(writer, request, true)
}

func (server *Server) importPolicyDomains(writer http.ResponseWriter, request *http.Request, allowed bool) {
	tab, kind := "domains", "blocked"
	if allowed {
		tab, kind = "allowed", "allowed"
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumDomainImportBytes)
	if err := request.ParseMultipartForm(maximumDomainImportBytes); err != nil {
		server.logBlockingOperation(request, err, "kind", kind)
		writeBlockingErrorStatus(writer, request, http.StatusBadRequest)
		_ = pages.BlockingContent(server.blockingView(request, "", "Choose a text or hosts file smaller than 4 MiB.", tab)).Render(request.Context(), writer)
		return
	}
	if request.MultipartForm != nil {
		defer request.MultipartForm.RemoveAll()
	}
	file, _, err := request.FormFile("file")
	if err != nil {
		server.logBlockingOperation(request, err, "kind", kind)
		writeBlockingErrorStatus(writer, request, http.StatusBadRequest)
		_ = pages.BlockingContent(server.blockingView(request, "", "Choose a domain file to import.", tab)).Render(request.Context(), writer)
		return
	}
	defer file.Close()
	domains, invalid, err := parseImportedDomains(file)
	if err != nil {
		server.logBlockingOperation(request, err, "kind", kind)
		writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
		_ = pages.BlockingContent(server.blockingView(request, "", err.Error(), tab)).Render(request.Context(), writer)
		return
	}
	if len(domains) == 0 {
		server.logBlockingOperation(request, errors.New("domain file contains no valid domains"), "kind", kind, "invalid", invalid)
		writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
		_ = pages.BlockingContent(server.blockingView(request, "", "The selected file does not contain any valid domains.", tab)).Render(request.Context(), writer)
		return
	}
	editor, ok := server.config.(blockingEditor)
	if !ok {
		server.logBlockingOperation(request, errors.New("configuration source is read-only"), "kind", kind)
		writeBlockingErrorStatus(writer, request, http.StatusNotImplemented)
		_ = pages.BlockingContent(server.blockingView(request, "", "This configuration source is read-only.", tab)).Render(request.Context(), writer)
		return
	}
	added := 0
	err = editor.UpdateBlocking(request.Context(), func(policy *config.Blocking) error {
		target := &policy.Domains
		if allowed {
			target = &policy.AllowedDomains
		}
		existing := make(map[string]struct{}, len(*target)+len(domains))
		for _, domain := range *target {
			existing[domain] = struct{}{}
		}
		for _, domain := range domains {
			if _, duplicate := existing[domain]; duplicate {
				continue
			}
			existing[domain] = struct{}{}
			*target = append(*target, domain)
			added++
		}
		slices.Sort(*target)
		return nil
	})
	if err != nil {
		server.logBlockingOperation(request, err, "kind", kind)
		writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
		_ = pages.BlockingContent(server.blockingView(request, "", err.Error(), tab)).Render(request.Context(), writer)
		return
	}
	message := fmt.Sprintf("Imported %d domains to the %s list", added, kind)
	if invalid > 0 {
		message += fmt.Sprintf(" (%d invalid lines skipped)", invalid)
	}
	server.logBlockingOperation(request, nil, "kind", kind, "added", added, "invalid", invalid)
	server.recordControlPlaneAudit(request, blockingMutationAction(request.URL.Path), message)
	_ = pages.BlockingContent(server.blockingView(request, message, "", tab)).Render(request.Context(), writer)
}

func parseImportedDomains(reader io.Reader) ([]string, int, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, maximumDomainImportBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read domain import: %w", err)
	}
	if len(contents) > maximumDomainImportBytes {
		return nil, 0, errors.New("domain import exceeds the 4 MiB limit")
	}
	unique := make(map[string]struct{})
	invalid := 0
	for _, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		candidates := fields[:1]
		if len(fields) > 1 {
			if net.ParseIP(fields[0]) == nil {
				invalid++
				continue
			}
			candidates = fields[1:]
		}
		for _, candidate := range candidates {
			normalized, normalizeErr := normalizePolicyEntry(candidate)
			if normalizeErr != nil {
				invalid++
				continue
			}
			unique[normalized] = struct{}{}
			if len(unique) > maximumImportedDomains {
				return nil, invalid, fmt.Errorf("domain import contains more than %d unique domains", maximumImportedDomains)
			}
		}
	}
	domains := make([]string, 0, len(unique))
	for domain := range unique {
		domains = append(domains, domain)
	}
	slices.Sort(domains)
	return domains, invalid, nil
}

func (server *Server) exportBlockedDomains(writer http.ResponseWriter, request *http.Request) {
	server.exportPolicyDomains(writer, request, false)
}

func (server *Server) exportAllowedDomains(writer http.ResponseWriter, request *http.Request) {
	server.exportPolicyDomains(writer, request, true)
}

func (server *Server) exportPolicyDomains(writer http.ResponseWriter, request *http.Request, allowed bool) {
	policy := server.config.Current().Config.Blocking
	domains := policy.Domains
	filename := "blocked-domains.txt"
	if allowed {
		domains = policy.AllowedDomains
		filename = "allowed-domains.txt"
	}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	if len(domains) > 0 {
		_, _ = io.WriteString(writer, strings.Join(domains, "\n")+"\n")
	}
	server.logBlockingOperation(request, nil, "count", len(domains))
}

func (server *Server) addBlockList(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.logBlockingOperation(request, err)
		writeBlockingErrorStatus(writer, request, http.StatusBadRequest)
		_ = pages.BlockingContent(server.blockingView(request, "", "Invalid block-list form.", "lists")).Render(request.Context(), writer)
		return
	}
	name := strings.TrimSpace(request.FormValue("name"))
	remoteURL := strings.TrimSpace(request.FormValue("url"))
	format := strings.TrimSpace(request.FormValue("format"))
	if format == "" {
		format = "auto"
	}
	if err := blockcompiler.ValidateURL(remoteURL); err != nil {
		server.logBlockingOperation(request, err, "url", remoteURL)
		writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
		_ = pages.BlockingContent(server.blockingView(request, "", err.Error(), "lists")).Render(request.Context(), writer)
		return
	}
	if name == "" {
		name = blockListDisplayName(remoteURL)
	}
	for _, list := range server.config.Current().Config.Blocking.Lists {
		if strings.EqualFold(list.Name, name) || list.URL == remoteURL {
			server.logBlockingOperation(request, errors.New("block list is already configured"), "name", name, "url", remoteURL)
			writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
			_ = pages.BlockingContent(server.blockingView(request, "", "This block list is already added.", "lists")).Render(request.Context(), writer)
			return
		}
	}
	path := blockcompiler.CachePath(remoteURL)
	if err := server.blockLists.Download(request.Context(), blockcompiler.RemoteSource{Name: name, URL: remoteURL, Path: path}); err != nil {
		server.logBlockingOperation(request, err, "name", name, "url", remoteURL)
		writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
		_ = pages.BlockingContent(server.blockingView(request, "", err.Error(), "lists")).Render(request.Context(), writer)
		return
	}
	server.updateBlocking(writer, request, "lists", "Block list added and compiled", func(policy *config.Blocking) error {
		for _, list := range policy.Lists {
			if strings.EqualFold(list.Name, name) || list.URL == remoteURL {
				return errors.New("this block list is already added")
			}
		}
		policy.Lists = append(policy.Lists, config.BlockList{Name: name, Path: path, URL: remoteURL, Format: format})
		server.blockLists.Schedule(time.Now().Add(policy.UpdateInterval.Duration))
		return nil
	})
}

func (server *Server) deleteBlockList(writer http.ResponseWriter, request *http.Request) {
	server.updateBlocking(writer, request, "lists", "Block list removed", func(policy *config.Blocking) error {
		name := request.FormValue("name")
		index := slices.IndexFunc(policy.Lists, func(list config.BlockList) bool { return list.Name == name })
		if index < 0 {
			return errors.New("block list was not found")
		}
		policy.Lists = slices.Delete(policy.Lists, index, index+1)
		if len(remoteBlockSources(*policy)) == 0 {
			server.blockLists.Schedule(time.Time{})
		}
		return nil
	})
}

func (server *Server) updateBlockLists(writer http.ResponseWriter, request *http.Request) {
	started := time.Now()
	sources := len(remoteBlockSources(server.config.Current().Config.Blocking))
	// An operator asking for an update expects every source to be tried now,
	// not skipped because it is still serving out a retry backoff.
	server.blockLists.ClearBackoff()
	if err := server.refreshRemoteBlockLists(request.Context()); err != nil {
		server.logBlockingOperation(request, err, "sources", sources, "duration", time.Since(started))
		writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
		_ = pages.BlockingContent(server.blockingView(request, "", err.Error(), "lists")).Render(request.Context(), writer)
		return
	}
	server.logBlockingOperation(request, nil, "sources", sources, "domains", server.stats.Stats().BlockedDomains, "duration", time.Since(started))
	server.recordControlPlaneAudit(request, blockingMutationAction(request.URL.Path), fmt.Sprintf("refreshed %d remote block lists", sources))
	_ = pages.BlockingContent(server.blockingView(request, "Block lists downloaded and compiled", "", "lists")).Render(request.Context(), writer)
}

func (server *Server) toggleBlocking(writer http.ResponseWriter, request *http.Request) {
	server.updateBlocking(writer, request, "lists", "Blocking status updated", func(policy *config.Blocking) error {
		policy.Enabled = !policy.Enabled
		return nil
	})
}

func (server *Server) pauseBlocking(writer http.ResponseWriter, request *http.Request) {
	started := time.Now()
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.logBlockingOperation(request, err, "duration", time.Since(started))
		writeBlockingErrorStatus(writer, request, http.StatusBadRequest)
		return
	}
	minutes, err := strconv.Atoi(request.FormValue("minutes"))
	if err != nil || minutes < 1 || minutes > 1440 {
		validationErr := errors.New("pause duration must be between 1 minute and 24 hours")
		server.logBlockingOperation(request, validationErr, "minutes", minutes, "duration", time.Since(started))
		writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
		_ = pages.BlockingContent(server.blockingView(request, "", "Pause duration must be between 1 minute and 24 hours.", "lists")).Render(request.Context(), writer)
		return
	}
	pauser, ok := server.stats.(blockingPauser)
	if !ok {
		server.logBlockingOperation(request, errors.New("blocking pause is unavailable"), "duration", time.Since(started))
		writeBlockingErrorStatus(writer, request, http.StatusNotImplemented)
		return
	}
	pausedUntil := pauser.PauseBlocking(time.Duration(minutes) * time.Minute)
	server.logBlockingOperation(request, nil, "minutes", minutes, "paused_until", pausedUntil, "duration", time.Since(started))
	server.recordControlPlaneAudit(request, blockingMutationAction(request.URL.Path), fmt.Sprintf("blocking paused for %d minutes", minutes))
	_ = pages.BlockingContent(server.blockingView(request, fmt.Sprintf("Blocking paused for %d minutes", minutes), "", "lists")).Render(request.Context(), writer)
}

func (server *Server) resumeBlocking(writer http.ResponseWriter, request *http.Request) {
	pauser, ok := server.stats.(blockingPauser)
	if !ok {
		err := errors.New("blocking pause is unavailable")
		server.logBlockingOperation(request, err)
		writeBlockingErrorStatus(writer, request, http.StatusNotImplemented)
		_ = pages.BlockingContent(server.blockingView(request, "", err.Error(), "lists")).Render(request.Context(), writer)
		return
	}
	pauser.ResumeBlocking()
	server.logBlockingOperation(request, nil)
	server.recordControlPlaneAudit(request, blockingMutationAction(request.URL.Path), "blocking resumed")
	_ = pages.BlockingContent(server.blockingView(request, "Blocking resumed", "", "lists")).Render(request.Context(), writer)
}

// refreshRemoteBlockLists downloads every healthy source and reschedules the
// next run. A source that failed is retried on its own backoff deadline rather
// than waiting for the full update interval, so the refresh error is reported
// to the caller but the schedule is always advanced.
func (server *Server) refreshRemoteBlockLists(ctx context.Context) error {
	snapshot := server.config.Current()
	sources := remoteBlockSources(snapshot.Config.Blocking)
	if len(sources) == 0 {
		return errors.New("no remote block lists are configured")
	}
	refreshErr := server.blockLists.Refresh(ctx, sources, server.reload)
	next := time.Now().Add(snapshot.Config.Blocking.UpdateInterval.Duration)
	if retry := server.blockLists.RetryAt(); !retry.IsZero() && retry.Before(next) {
		next = retry
	}
	server.blockLists.Schedule(next)
	if refreshErr != nil {
		server.logBlockListHealth()
	}
	return refreshErr
}

// logBlockListHealth emits one structured line per unhealthy source so an
// operator can see which list is stale and for how long without opening the
// console.
func (server *Server) logBlockListHealth() {
	for _, source := range server.blockLists.Status().Sources {
		if source.Healthy() {
			continue
		}
		server.logger.Warn(
			"block-list source is failing",
			"list", source.Name,
			"url", source.URL,
			"consecutive_failures", source.ConsecutiveFailures,
			"last_success", source.LastSuccess,
			"retry_after", source.RetryAfter,
			"error", source.LastError,
		)
	}
}

func (server *Server) runBlockListScheduler() {
	for {
		snapshot := server.config.Current()
		sources := remoteBlockSources(snapshot.Config.Blocking)
		if len(sources) == 0 {
			server.blockLists.SetNext(time.Time{})
			select {
			case <-server.historyStop:
				return
			case <-server.blockLists.Wake():
				continue
			}
		}
		next := server.blockLists.Status().NextUpdate
		if next.IsZero() {
			next = time.Now().Add(snapshot.Config.Blocking.UpdateInterval.Duration)
			server.blockLists.SetNext(next)
		}
		timer := time.NewTimer(max(time.Until(next), time.Second))
		select {
		case <-server.historyStop:
			timer.Stop()
			return
		case <-server.blockLists.Wake():
			timer.Stop()
			continue
		case <-timer.C:
			started := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			err := server.refreshRemoteBlockLists(ctx)
			cancel()
			status := server.blockLists.Status()
			if err != nil {
				server.logger.Error(
					"scheduled block-list update failed",
					"sources", len(sources), "degraded", status.Degraded,
					"next_update", status.NextUpdate, "error", err,
				)
			} else {
				server.logger.Info("scheduled block-list update completed", "sources", len(sources), "domains", server.stats.Stats().BlockedDomains, "duration", time.Since(started), "next_update", status.NextUpdate)
			}
		}
	}
}

func remoteBlockSources(policy config.Blocking) []blockcompiler.RemoteSource {
	sources := make([]blockcompiler.RemoteSource, 0, len(policy.Lists))
	for _, list := range policy.Lists {
		if list.URL != "" {
			sources = append(sources, blockcompiler.RemoteSource{Name: list.Name, URL: list.URL, Path: list.Path})
		}
	}
	return sources
}

func blockListDisplayName(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" {
		return "custom"
	}
	name := parsed.Hostname() + strings.TrimSuffix(parsed.EscapedPath(), "/")
	return strings.TrimPrefix(name, "www.")
}

func splitFormLines(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' })
}

func normalizePolicyEntry(value string) (string, error) {
	value = strings.TrimSpace(value)
	wildcard := strings.HasPrefix(value, "*.")
	normalized, err := dnsname.Normalize(strings.TrimPrefix(value, "*."))
	if err != nil {
		return "", err
	}
	if wildcard {
		return "*." + normalized, nil
	}
	return normalized, nil
}
