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
	server.render(writer, request, pages.BlockingPage(view))
}

func (server *Server) blockingView(request *http.Request, message, errorMessage, activeTab string) pages.BlockingPageView {
	console := server.consoleView(request)
	snapshot := server.config.Current()
	stats := server.stats.Stats()
	if activeTab != "domains" && activeTab != "allowed" && activeTab != ruleSetsTab {
		activeTab = "lists"
	}
	sourceStats := make(map[string]pages.BlockListSourceView, len(stats.BlockSources))
	for _, source := range stats.BlockSources {
		sourceStats[source.Name] = pages.BlockListSourceView{
			Name: source.Name, Path: source.Path, Lines: source.Lines,
			Accepted: source.Accepted, Invalid: source.Invalid,
			Exceptions: source.Exceptions, Unsupported: source.Unsupported,
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
		RuleSets:      server.ruleSetViews(request.Context(), snapshot.Config), DefaultLists: slices.Clone(snapshot.Config.Blocking.DefaultLists),
		ActiveTab: activeTab, Message: message, Error: errorMessage,
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
	if err := request.ParseForm(); err != nil {
		server.logBlockingOperation(request, err, "duration", time.Since(started))
		writeBlockingErrorStatus(writer, request, http.StatusBadRequest)
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", "Invalid blocking form.", activeTab)))
		return
	}
	editor, ok := server.config.(blockingEditor)
	if !ok {
		server.logBlockingOperation(request, errors.New("configuration source is read-only"), "duration", time.Since(started))
		writeBlockingErrorStatus(writer, request, http.StatusNotImplemented)
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", "This configuration source is read-only.", activeTab)))
		return
	}
	if err := editor.UpdateBlocking(request.Context(), mutate); err != nil {
		server.logBlockingOperation(request, err, "duration", time.Since(started))
		writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", err.Error(), activeTab)))
		return
	}
	server.logBlockingOperation(request, nil, "duration", time.Since(started))
	server.recordControlPlaneAudit(request, blockingMutationAction(request.URL.Path), success)
	server.render(writer, request, pages.BlockingContent(server.blockingView(request, success, "", activeTab)))
}

func writeBlockingErrorStatus(writer http.ResponseWriter, request *http.Request, status int) {
	writeFragmentStatus(writer, status)
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
		"/ui/blocking/reload":            "blocking.reload",
		"/ui/blocking/domains/add":       "blocking.blocked_domain.add",
		"/ui/blocking/domains/delete":    "blocking.blocked_domain.delete",
		"/ui/blocking/domains/flush":     "blocking.blocked_domain.clear",
		"/ui/blocking/domains/import":    "blocking.blocked_domain.import",
		"/ui/blocking/domains/export":    "blocking.blocked_domain.export",
		"/ui/blocking/allowed/add":       "blocking.allowed_domain.add",
		"/ui/blocking/allowed/delete":    "blocking.allowed_domain.delete",
		"/ui/blocking/allowed/flush":     "blocking.allowed_domain.clear",
		"/ui/blocking/allowed/import":    "blocking.allowed_domain.import",
		"/ui/blocking/allowed/export":    "blocking.allowed_domain.export",
		"/ui/blocking/lists/add":         "blocking.list.add",
		"/ui/blocking/lists/delete":      "blocking.list.delete",
		"/ui/blocking/lists/update":      "blocking.list.update",
		"/ui/blocking/lists/refresh":     "blocking.list.refresh",
		"/ui/blocking/toggle":            "blocking.toggle",
		"/ui/blocking/rule-sets/save":    "blocking.rule_set.save",
		"/ui/blocking/rule-sets/delete":  "blocking.rule_set.delete",
		"/ui/blocking/rule-sets/default": "blocking.default_lists.update",
		"/ui/blocking/pause":             "blocking.pause",
		"/ui/blocking/resume":            "blocking.resume",
		"/ui/blocking/query-domain":      "blocking.query_log_policy",
		"/ui/blocking/check/rule":        "blocking.check_policy",
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
	if err := request.ParseForm(); err != nil {
		server.logBlockingOperation(request, err)
		server.render(writer, request, pages.Toast("Invalid domain action.", "error"))
		return
	}
	allowed := request.FormValue("action") == "allow"
	result, err := server.policyService().Add(request.Context(), requestActor(request, ""), request.FormValue("domain"), allowed)
	if err != nil {
		server.render(writer, request, pages.Toast(err.Error(), "error"))
		return
	}
	server.render(writer, request, pages.Toast(sentence(result.Message)+".", "success"))
}

func (server *Server) addPolicyDomain(writer http.ResponseWriter, request *http.Request, allowed bool) {
	server.changePolicyDomain(writer, request, allowed, server.policyService().Add)
}

func (server *Server) deleteBlockedDomain(writer http.ResponseWriter, request *http.Request) {
	server.deletePolicyDomain(writer, request, false)
}

func (server *Server) deleteAllowedDomain(writer http.ResponseWriter, request *http.Request) {
	server.deletePolicyDomain(writer, request, true)
}

func (server *Server) deletePolicyDomain(writer http.ResponseWriter, request *http.Request, allowed bool) {
	server.changePolicyDomain(writer, request, allowed, server.policyService().Remove)
}

// changePolicyDomain adds a domain to one list or takes it off, and shows the
// list. A change that would do nothing is an error here, because the person
// expected the list to change.
func (server *Server) changePolicyDomain(
	writer http.ResponseWriter,
	request *http.Request,
	allowed bool,
	change func(context.Context, actor, string, bool) (domainRuleChange, error),
) {
	tab := policyTab(allowed)
	if err := request.ParseForm(); err != nil {
		server.renderPolicyChange(writer, request, tab, "", refuse(http.StatusBadRequest, "Invalid blocking form."))
		return
	}
	result, err := change(request.Context(), requestActor(request, ""), request.FormValue("domain"), allowed)
	if err == nil && !result.Changed {
		err = refuse(http.StatusUnprocessableEntity, "%s", sentence(result.Message))
	}
	server.renderPolicyChange(writer, request, tab, sentence(result.Message), err)
}

// renderPolicyChange shows the Blocking page after a list change.
func (server *Server) renderPolicyChange(writer http.ResponseWriter, request *http.Request, tab, message string, err error) {
	if err != nil {
		writeBlockingErrorStatus(writer, request, serviceStatus(err))
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", sentence(err.Error()), tab)))
		return
	}
	server.render(writer, request, pages.BlockingContent(server.blockingView(request, message, "", tab)))
}

func policyTab(allowed bool) string {
	if allowed {
		return "allowed"
	}
	return "domains"
}

// sentence capitalizes a message for the console, where messages start a
// sentence. A message that opens with a domain name keeps its case.
func sentence(message string) string {
	if first, _, _ := strings.Cut(message, " "); first == "" || strings.Contains(first, ".") {
		return message
	}
	return strings.ToUpper(message[:1]) + message[1:]
}

func (server *Server) flushBlockedDomains(writer http.ResponseWriter, request *http.Request) {
	server.flushPolicyDomains(writer, request, false)
}

func (server *Server) flushAllowedDomains(writer http.ResponseWriter, request *http.Request) {
	server.flushPolicyDomains(writer, request, true)
}

func (server *Server) flushPolicyDomains(writer http.ResponseWriter, request *http.Request, allowed bool) {
	message, err := server.policyService().Clear(request.Context(), requestActor(request, ""), allowed)
	server.renderPolicyChange(writer, request, policyTab(allowed), message, err)
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
	if err := request.ParseMultipartForm(maximumDomainImportBytes); err != nil {
		server.logBlockingOperation(request, err, "kind", kind)
		writeBlockingErrorStatus(writer, request, http.StatusBadRequest)
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", "Choose a text or hosts file smaller than 4 MiB.", tab)))
		return
	}
	if request.MultipartForm != nil {
		defer request.MultipartForm.RemoveAll()
	}
	file, _, err := request.FormFile("file")
	if err != nil {
		server.logBlockingOperation(request, err, "kind", kind)
		writeBlockingErrorStatus(writer, request, http.StatusBadRequest)
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", "Choose a domain file to import.", tab)))
		return
	}
	defer file.Close()
	domains, invalid, err := parseImportedDomains(file)
	if err != nil {
		server.logBlockingOperation(request, err, "kind", kind)
		writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", err.Error(), tab)))
		return
	}
	if len(domains) == 0 {
		server.logBlockingOperation(request, errors.New("domain file contains no valid domains"), "kind", kind, "invalid", invalid)
		writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", "The selected file does not contain any valid domains.", tab)))
		return
	}
	message, err := server.policyService().Import(request.Context(), requestActor(request, ""), domains, invalid, allowed)
	server.renderPolicyChange(writer, request, tab, message, err)
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
	if err := request.ParseForm(); err != nil {
		server.logBlockingOperation(request, err)
		writeBlockingErrorStatus(writer, request, http.StatusBadRequest)
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", "Invalid block-list form.", "lists")))
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
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", err.Error(), "lists")))
		return
	}
	if name == "" {
		name = blockListDisplayName(remoteURL)
	}
	for _, list := range server.config.Current().Config.Blocking.Lists {
		if strings.EqualFold(list.Name, name) || list.URL == remoteURL {
			server.logBlockingOperation(request, errors.New("block list is already configured"), "name", name, "url", remoteURL)
			writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
			server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", "This block list is already added.", "lists")))
			return
		}
	}
	path := blockcompiler.CachePath(remoteURL)
	if err := server.blockLists.Download(request.Context(), blockcompiler.RemoteSource{Name: name, URL: remoteURL, Path: path}); err != nil {
		server.logBlockingOperation(request, err, "name", name, "url", remoteURL)
		writeBlockingErrorStatus(writer, request, http.StatusUnprocessableEntity)
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", err.Error(), "lists")))
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
		if err := policy.RemoveList(request.FormValue("name")); err != nil {
			return err
		}
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
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", err.Error(), "lists")))
		return
	}
	server.logBlockingOperation(request, nil, "sources", sources, "domains", server.stats.Stats().BlockedDomains, "duration", time.Since(started))
	server.recordControlPlaneAudit(request, blockingMutationAction(request.URL.Path), fmt.Sprintf("refreshed %d remote block lists", sources))
	server.render(writer, request, pages.BlockingContent(server.blockingView(request, "Block lists downloaded and compiled", "", "lists")))
}

func (server *Server) toggleBlocking(writer http.ResponseWriter, request *http.Request) {
	server.updateBlocking(writer, request, "lists", "Blocking status updated", func(policy *config.Blocking) error {
		policy.Enabled = !policy.Enabled
		return nil
	})
}

func (server *Server) pauseBlocking(writer http.ResponseWriter, request *http.Request) {
	started := time.Now()
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
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", "Pause duration must be between 1 minute and 24 hours.", "lists")))
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
	server.render(writer, request, pages.BlockingContent(server.blockingView(request, fmt.Sprintf("Blocking paused for %d minutes", minutes), "", "lists")))
}

func (server *Server) resumeBlocking(writer http.ResponseWriter, request *http.Request) {
	pauser, ok := server.stats.(blockingPauser)
	if !ok {
		err := errors.New("blocking pause is unavailable")
		server.logBlockingOperation(request, err)
		writeBlockingErrorStatus(writer, request, http.StatusNotImplemented)
		server.render(writer, request, pages.BlockingContent(server.blockingView(request, "", err.Error(), "lists")))
		return
	}
	pauser.ResumeBlocking()
	server.logBlockingOperation(request, nil)
	server.recordControlPlaneAudit(request, blockingMutationAction(request.URL.Path), "blocking resumed")
	server.render(writer, request, pages.BlockingContent(server.blockingView(request, "Blocking resumed", "", "lists")))
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
			case <-server.runtimeContext.Done():
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
		case <-server.runtimeContext.Done():
			timer.Stop()
			return
		case <-server.blockLists.Wake():
			timer.Stop()
			continue
		case <-timer.C:
			started := time.Now()
			ctx, cancel := context.WithTimeout(server.runtimeContext, 10*time.Minute)
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
