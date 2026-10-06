package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/serverlog"
	"github.com/drudge/sable/internal/web/pages"

	"encoding/csv"
	"io"
)

type queryEventPager interface {
	QueryEvents(context.Context, querylog.Filter) (querylog.Page, error)
}

type serverLogPager interface {
	ServerLogEntries(context.Context, serverlog.Query) (serverlog.Page, error)
}

// runtimeLogHistory reports the pager to read runtime logs from, and nothing
// when the history is unavailable. Persistence being switched off matters as
// much as the store not supporting it: the table would still answer, with
// whatever was captured before it was switched off, which reads as a log that
// mysteriously stops rather than one that was turned off.
func (server *Server) runtimeLogHistory() (serverLogPager, bool) {
	if server.config == nil || !server.config.Current().Config.ServerLog.Enabled {
		return nil, false
	}
	pager, ok := server.queries.(serverLogPager)
	return pager, ok
}

func (server *Server) logsPage(writer http.ResponseWriter, request *http.Request) {
	activeTab := request.URL.Query().Get("tab")
	// A query's address opens Query Logs beneath its details panel.
	if request.PathValue("id") != "" {
		activeTab = "queries"
	}
	if activeTab != "queries" {
		activeTab = "server"
	}
	view := pages.LogsPageView{Console: server.consoleView(request), ActiveTab: activeTab}
	view.Runtime = server.runtimeLogsView(request)
	view.Queries = server.queryLogsView(request)
	view.Queries.CanBlocking = view.Console.CanBlocking
	server.render(writer, request, pages.LogsPage(view))
}

func (server *Server) runtimeLogsPanel(writer http.ResponseWriter, request *http.Request) {
	server.render(writer, request, pages.RuntimeLogsPanel(server.runtimeLogsView(request)))
}

func (server *Server) runtimeLogsView(request *http.Request) pages.RuntimeLogsView {
	values := request.URL.Query()
	view := pages.RuntimeLogsView{
		Search: values.Get("search"), Level: values.Get("level"), Live: liveRequested(values, true),
		Page: parseBoundedInt(values.Get("page"), 1, 1, 1_000_000), PageSize: parseBoundedInt(values.Get("page_size"), 100, 1, 250),
	}
	if view.Level == "" {
		view.Level = "all"
	}
	pager, persisted := server.runtimeLogHistory()
	if persisted {
		return server.persistedRuntimeLogsView(request, pager, view)
	}
	if server.runtimeLogs == nil {
		view.Error = "Runtime log capture is unavailable."
		return view
	}
	entries := server.runtimeLogs.Entries(serverlog.Filter{Search: view.Search, Level: view.Level, Limit: 500})
	return finishRuntimeLogsView(request, view, entries)
}

// persistedRuntimeLogsView pages the stored history rather than the live
// buffer. The buffer only reaches back as far as this process, which is the
// whole reason the history exists, so once it is available it answers every
// read: mixing the two would make the first page and the rest disagree about
// what a page contains whenever an entry landed between them.
func (server *Server) persistedRuntimeLogsView(request *http.Request, pager serverLogPager, view pages.RuntimeLogsView) pages.RuntimeLogsView {
	view.Persisted = true
	result, err := pager.ServerLogEntries(request.Context(), serverlog.Query{
		Page: view.Page, PageSize: view.PageSize, Search: view.Search, Level: view.Level,
	})
	if err != nil {
		server.logger.Error("browse server log", "error", err)
		view.Error = "Server log history is temporarily unavailable."
		return view
	}
	view.Page = result.Page
	view.PageSize = result.PageSize
	view.TotalEntries = result.TotalEntries
	view.TotalPages = result.TotalPages
	view = finishRuntimeLogsView(request, view, result.Entries)
	raw := runtimeExportValues(request.URL.Query())
	view.FirstURL = runtimeLogPanelURL(raw, 1)
	view.PreviousURL = runtimeLogPanelURL(raw, max(1, result.Page-1))
	view.NextURL = runtimeLogPanelURL(raw, min(max(1, result.TotalPages), result.Page+1))
	view.LastURL = runtimeLogPanelURL(raw, max(1, result.TotalPages))
	return view
}

func finishRuntimeLogsView(request *http.Request, view pages.RuntimeLogsView, entries []serverlog.Entry) pages.RuntimeLogsView {
	display := requestTimeDisplay(request)
	view.Entries = make([]pages.RuntimeLogEntryView, 0, len(entries))
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		converted := pages.RuntimeLogEntryView{
			OccurredAt: pages.FormatRuntimeLogTime(entry.OccurredAt, display),
			Level:      runtimeLevelName(entry.Level),
			Message:    entry.Message,
			Attributes: serverlog.AttributeText(entry.Attributes),
		}
		view.Entries = append(view.Entries, converted)
		lines = append(lines, strings.TrimSpace(converted.OccurredAt+" "+strings.ToUpper(converted.Level)+" "+converted.Message+" "+converted.Attributes))
	}
	view.Count = len(view.Entries)
	view.CopyText = strings.Join(lines, "\n")
	if !view.Persisted {
		view.TotalEntries = view.Count
	}
	return view
}

func runtimeExportValues(values url.Values) url.Values {
	copied := make(url.Values)
	for _, key := range []string{"search", "level", "page_size"} {
		if value := values.Get(key); value != "" {
			copied.Set(key, value)
		}
	}
	return copied
}

// runtimeLogPanelURL pages the stored history, and paging stops the follow: the
// live refresh always reads the newest page, so a panel left following would
// drag an operator straight back off the page they asked for.
func runtimeLogPanelURL(values url.Values, page int) string {
	copied := make(url.Values, len(values)+2)
	for key, value := range values {
		copied[key] = value
	}
	copied.Set("page", strconv.Itoa(page))
	copied.Set("live", "0")
	return "/ui/logs/runtime?" + copied.Encode()
}

// liveRequested reads the follow flag, which has to tell "off" apart from
// "unsaid": the runtime log follows by default, so only an explicit live=0
// pauses it.
func liveRequested(values url.Values, byDefault bool) bool {
	switch values.Get("live") {
	case "":
		return byDefault
	case "1":
		return true
	default:
		return false
	}
}

func runtimeLevelName(level interface{ String() string }) string {
	name := strings.ToLower(level.String())
	if before, _, found := strings.Cut(name, "+"); found {
		name = before
	}
	return name
}

type queryEventReader interface {
	QueryEvent(context.Context, int64) (querylog.Entry, bool, error)
}

// queryDetailPanel fills the details panel for one query, opened by its
// address. A query no longer in the log gets a stand-in that searches for
// its domain.
func (server *Server) queryDetailPanel(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	view, err := server.queryDetailView(request)
	if err != nil {
		server.logger.Error("read query", "error", err)
		writer.WriteHeader(http.StatusInternalServerError)
	}
	server.render(writer, request, pages.QueryDetail(view))
}

func (server *Server) queryDetailView(request *http.Request) (pages.QueryDetailView, error) {
	console := server.consoleView(request)
	view := pages.QueryDetailView{
		Name:        strings.TrimSuffix(strings.TrimSpace(request.URL.Query().Get("name")), "."),
		CanBlocking: console.CanBlocking,
		CanWatch:    server.alerts != nil && console.CanWriteSettings,
		Missing:     true,
	}
	id := parsePositiveInt64(request.URL.Query().Get("id"))
	reader, ok := server.queries.(queryEventReader)
	if id == 0 || !ok {
		return view, nil
	}
	entry, found, err := reader.QueryEvent(request.Context(), id)
	if err != nil || !found {
		return view, err
	}
	view.Missing, view.Loaded = false, true
	display := requestTimeDisplay(request)
	view.Entry = queryLogEntryViews([]querylog.Entry{entry}, display)[0]
	view.Entry.OccurredAt = pages.FormatShortDateTime(entry.OccurredAt, display, true)
	return view, nil
}

func (server *Server) queryLogsPanel(writer http.ResponseWriter, request *http.Request) {
	view := server.queryLogsView(request)
	if view.Error != "" {
		writer.WriteHeader(http.StatusInternalServerError)
	}
	server.render(writer, request, pages.QueryLogsPanel(view))
}

func (server *Server) queryLogsView(request *http.Request) pages.QueryLogsView {
	filter, raw := queryLogFilter(request)
	display := requestTimeDisplay(request)
	view := pages.QueryLogsView{
		Page: filter.Page, PageSize: filter.PageSize, ClientIP: raw.Get("client_ip"),
		Name: raw.Get("name"), Search: raw.Get("q"), RecordType: strings.ToUpper(raw.Get("record_type")),
		ResponseCode: strings.ToUpper(raw.Get("response_code")), Source: raw.Get("source"), Protocol: strings.ToUpper(raw.Get("protocol")),
		Start: logTimeField(filter.Since, display), End: logTimeField(filter.Until, display),
		Exact: filter.Exact,
		Live:  liveRequested(raw, true), FiltersOpen: raw.Get("filters") == "1",
		// Only operators who can change alert settings can add a watch.
		CanWatch: server.alerts != nil && server.consoleView(request).CanWriteSettings,
	}
	pager, ok := server.queries.(queryEventPager)
	if !ok {
		view.Error = "The configured query log store does not support browsing."
		return view
	}
	result, err := pager.QueryEvents(request.Context(), filter)
	if err != nil {
		server.logger.Error("browse query log", "error", err)
		view.Error = "Query logs are temporarily unavailable."
		return view
	}
	view.Page = result.Page
	view.PageSize = result.PageSize
	view.TotalEntries = result.TotalEntries
	view.TotalPages = result.TotalPages
	view.Entries = queryLogEntryViews(result.Entries, requestTimeDisplay(request))
	for index := range view.Entries {
		view.Entries[index].OccurredAt = pages.FormatShortDateTime(result.Entries[index].OccurredAt, requestTimeDisplay(request), true)
	}
	view.CopyText = queryLogText(result.Entries)
	var firstID, lastID int64
	if len(result.Entries) > 0 {
		firstID = result.Entries[0].ID
		lastID = result.Entries[len(result.Entries)-1].ID
		view.NewestID = firstID
	}
	view.FirstURL = queryLogPanelURL(raw, 1, 0, "", result.TotalEntries)
	view.PreviousURL = queryLogPanelURL(raw, max(1, result.Page-1), firstID, "newer", result.TotalEntries)
	view.NextURL = queryLogPanelURL(raw, min(max(1, result.TotalPages), result.Page+1), lastID, "older", result.TotalEntries)
	view.LastURL = queryLogPanelURL(raw, max(1, result.TotalPages), 0, "oldest", result.TotalEntries)
	view.ExportURL = "/api/v1/logs/queries/export?" + exportQueryValues(raw).Encode()
	return view
}

func queryLogFilter(request *http.Request) (querylog.Filter, url.Values) {
	values := request.URL.Query()
	filter := querylog.Filter{
		Page:     parseBoundedInt(values.Get("page"), 1, 1, 1_000_000),
		PageSize: parseBoundedInt(values.Get("page_size"), 50, 1, 250),
		ClientIP: values.Get("client_ip"), Name: values.Get("name"), Search: values.Get("q"),
		Source: querylog.Source(values.Get("source")), Protocol: values.Get("protocol"),
	}
	filter.Cursor = parsePositiveInt64(values.Get("cursor"))
	switch values.Get("direction") {
	case "older", "newer", "oldest":
		filter.Direction = values.Get("direction")
	}
	filter.KnownTotal = parseBoundedInt(values.Get("known_total"), 0, 0, 1_000_000_000)
	_, filter.UseKnownTotal = values["known_total"]
	filter.AfterID = parsePositiveInt64(values.Get("after_id"))
	filter.Incremental = values.Get("live") == "1" && filter.UseKnownTotal
	if value := strings.ToUpper(strings.TrimSpace(values.Get("record_type"))); value != "" && value != "ALL" {
		for _, item := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
			if number, found := dns.StringToType[item]; found {
				filter.RecordTypes = append(filter.RecordTypes, number)
			}
		}
	}
	filter.Exact = values.Get("match") == "exact"
	display := requestTimeDisplay(request)
	filter.Since = parseLogTime(values.Get("start"), display)
	filter.Until = parseLogTime(values.Get("end"), display)
	if value := strings.ToUpper(strings.TrimSpace(values.Get("response_code"))); value != "" && value != "ALL" {
		for number, name := range dns.RcodeToString {
			if strings.EqualFold(name, value) {
				code := number
				filter.ResponseCode = &code
				break
			}
		}
		if filter.ResponseCode == nil {
			if number, err := strconv.Atoi(value); err == nil {
				filter.ResponseCode = &number
			}
		}
	}
	return filter, values
}

// parseLogTime reads a window bound. A dashboard ranking links with a precise
// instant so the log counts exactly the rows it counted, while the filter form
// posts back what a datetime-local input can hold, which is minutes in the
// operator's own zone.
func parseLogTime(raw string, display pages.TimeDisplay) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if moment, err := time.Parse(time.RFC3339, raw); err == nil {
		return moment
	}
	location := display.Location
	if location == nil {
		location = time.Local
	}
	if moment, err := time.ParseInLocation("2006-01-02T15:04", raw, location); err == nil {
		return moment
	}
	return time.Time{}
}

// logTimeField renders a window bound for the filter form's datetime-local
// input, which only understands local wall-clock minutes.
func logTimeField(moment time.Time, display pages.TimeDisplay) string {
	if moment.IsZero() {
		return ""
	}
	return display.In(moment).Format("2006-01-02T15:04")
}

func parseBoundedInt(raw string, fallback, minimum, maximum int) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

func parsePositiveInt64(raw string) int64 {
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 1 {
		return 0
	}
	return value
}

func queryLogPanelURL(values url.Values, page int, cursor int64, direction string, total int) string {
	copy := exportQueryValues(values)
	copy.Set("page", strconv.Itoa(page))
	copy.Set("live", "0")
	copy.Set("known_total", strconv.Itoa(total))
	if cursor > 0 {
		copy.Set("cursor", strconv.FormatInt(cursor, 10))
	}
	if direction != "" {
		copy.Set("direction", direction)
	}
	return "/ui/logs/queries?" + copy.Encode()
}

func exportQueryValues(values url.Values) url.Values {
	copy := make(url.Values)
	for _, key := range []string{"q", "client_ip", "name", "record_type", "response_code", "source", "protocol", "page_size", "start", "end", "match"} {
		if value := values.Get(key); value != "" {
			copy.Set(key, value)
		}
	}
	return copy
}

func (server *Server) runtimeLogsAPI(writer http.ResponseWriter, request *http.Request) {
	values := request.URL.Query()
	if pager, ok := server.runtimeLogHistory(); ok {
		result, err := pager.ServerLogEntries(request.Context(), serverlog.Query{
			Page:     parseBoundedInt(values.Get("page"), 1, 1, 1_000_000),
			PageSize: parseBoundedInt(values.Get("page_size"), 100, 1, 250),
			Search:   values.Get("search"), Level: values.Get("level"),
		})
		if err != nil {
			server.logger.Error("read server log history", "error", err)
			apiError(writer, http.StatusInternalServerError, "server log history unavailable")
			return
		}
		writeJSON(writer, http.StatusOK, result)
		return
	}
	if server.runtimeLogs == nil {
		apiError(writer, http.StatusServiceUnavailable, "runtime log capture unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, server.runtimeLogs.Entries(serverlog.Filter{
		Search: values.Get("search"), Level: values.Get("level"), Limit: 500,
	}))
}

func (server *Server) exportRuntimeLogs(writer http.ResponseWriter, request *http.Request) {
	values := request.URL.Query()
	pager, persisted := server.runtimeLogHistory()
	if !persisted && server.runtimeLogs == nil {
		http.Error(writer, "runtime log capture unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Content-Disposition", `attachment; filename="sable-runtime.log"`)
	if !persisted {
		writeRuntimeLogLines(writer, server.runtimeLogs.Entries(serverlog.Filter{
			Search: values.Get("search"), Level: values.Get("level"), Limit: serverlog.DefaultCapacity,
		}))
		return
	}
	// Pages are newest first, so the export walks from the last page back to
	// reach the file's oldest-first order without holding the whole history in
	// memory to reverse it.
	query := serverlog.Query{Page: 1, PageSize: 250, Search: values.Get("search"), Level: values.Get("level")}
	result, err := pager.ServerLogEntries(request.Context(), query)
	if err != nil {
		server.logger.Error("export server log", "error", err)
		http.Error(writer, "server log history unavailable", http.StatusInternalServerError)
		return
	}
	for page := result.TotalPages; page >= 1; page-- {
		query.Page = page
		if page != result.Page {
			result, err = pager.ServerLogEntries(request.Context(), query)
			if err != nil {
				server.logger.Error("continue server log export", "error", err, "page", page)
				return
			}
		}
		writeRuntimeLogLines(writer, result.Entries)
	}
}

func writeRuntimeLogLines(writer io.Writer, entries []serverlog.Entry) {
	for index := len(entries) - 1; index >= 0; index-- {
		entry := entries[index]
		_, _ = fmt.Fprintf(writer, "%s level=%s msg=%q %s\n", entry.OccurredAt.Local().Format(time.RFC3339Nano), runtimeLevelName(entry.Level), entry.Message, serverlog.AttributeText(entry.Attributes))
	}
}

func (server *Server) exportQueryLogs(writer http.ResponseWriter, request *http.Request) {
	pager, ok := server.queries.(queryEventPager)
	if !ok {
		http.Error(writer, "query log browsing unavailable", http.StatusServiceUnavailable)
		return
	}
	filter, _ := queryLogFilter(request)
	filter.Page, filter.PageSize = 1, queryLogExportPageSize
	filter.Cursor, filter.Direction, filter.Incremental = 0, "", false
	result, err := pager.QueryEvents(request.Context(), filter)
	if err != nil {
		server.logger.Error("export query log", "error", err)
		http.Error(writer, "query log unavailable", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
	writer.Header().Set("Content-Disposition", `attachment; filename="sable-query-log.csv"`)
	if err := writeQueryLogCSV(request.Context(), writer, pager, filter, result); err != nil {
		server.logger.Error("export query log", "error", err)
		// The status has gone out, so abort the response rather than end it
		// cleanly. The download then fails instead of saving a short file
		// that looks complete.
		panic(http.ErrAbortHandler)
	}
}

const queryLogExportPageSize = 250

// writeQueryLogCSV writes every row that matched when the export began, newest
// first. Each page continues below the last ID written, so rows logged during
// the export neither shift the pages nor appear twice, and no page recounts
// or skips over the rows before it.
func writeQueryLogCSV(ctx context.Context, writer io.Writer, pager queryEventPager, filter querylog.Filter, first querylog.Page) error {
	output := csv.NewWriter(writer)
	if err := output.Write([]string{"timestamp", "client_ip", "domain", "type", "response", "status", "protocol", "answer", "duration"}); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	filter.KnownTotal, filter.UseKnownTotal, filter.Direction = first.TotalEntries, true, "older"
	result := first
	for {
		for _, entry := range result.Entries {
			if err := output.Write(queryLogCSVRow(entry)); err != nil {
				return fmt.Errorf("write row %d: %w", entry.ID, err)
			}
		}
		if len(result.Entries) < filter.PageSize {
			break
		}
		filter.Cursor = result.Entries[len(result.Entries)-1].ID
		next, err := pager.QueryEvents(ctx, filter)
		if err != nil {
			return fmt.Errorf("read rows older than %d: %w", filter.Cursor, err)
		}
		result = next
	}
	output.Flush()
	return output.Error()
}

func queryLogCSVRow(entry querylog.Entry) []string {
	recordType := dns.TypeToString[entry.RecordType]
	status := dns.RcodeToString[entry.ResponseCode]
	return []string{entry.OccurredAt.Format(time.RFC3339Nano), entry.ClientIP, entry.Name, recordType, string(entry.Source), status, entry.Protocol, entry.Answer, entry.Duration.String()}
}

func queryLogText(entries []querylog.Entry) string {
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		lines = append(lines, strings.Join(queryLogCSVRow(entry), "\t"))
	}
	return strings.Join(lines, "\n")
}

func (server *Server) recentQueryLog(writer http.ResponseWriter, request *http.Request) {
	entries, err := server.queries.RecentQueryEvents(request.Context(), defaultRecentQueryLimit)
	if err != nil {
		server.logger.Error("read recent query log", "error", err)
		http.Error(writer, "query log unavailable", http.StatusInternalServerError)
		return
	}
	server.render(writer, request, pages.RecentQueryLog(queryLogEntryViews(entries, requestTimeDisplay(request))))
}

func (server *Server) canReadLogs(request *http.Request) bool {
	principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal)
	if !ok {
		return !server.securityEnabled
	}
	return auth.HasPermission(principal, auth.PermissionLogsRead)
}

func (server *Server) queryLogAPI(writer http.ResponseWriter, request *http.Request) {
	limit := defaultRecentQueryLimit
	if rawLimit := request.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			apiError(writer, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = parsed
	}
	entries, err := server.queries.RecentQueryEvents(request.Context(), limit)
	if err != nil {
		apiError(writer, http.StatusInternalServerError, "query log unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, queryLogAPIEntries(entries))
}

func queryLogStatus(enabled bool, stats querylog.Stats) string {
	if !enabled {
		return "Disabled"
	}
	if stats.Dropped == 0 {
		return fmt.Sprintf("Active · %d persisted", stats.Persisted)
	}
	return fmt.Sprintf("Active · %d dropped", stats.Dropped)
}

func queryLogEntryViews(entries []querylog.Entry, display pages.TimeDisplay) []pages.QueryLogEntryView {
	views := make([]pages.QueryLogEntryView, 0, len(entries))
	for _, entry := range entries {
		recordType := dns.TypeToString[entry.RecordType]
		if recordType == "" {
			recordType = strconv.Itoa(int(entry.RecordType))
		}
		status := dns.RcodeToString[entry.ResponseCode]
		if status == "" {
			status = strconv.Itoa(entry.ResponseCode)
		}
		views = append(views, pages.QueryLogEntryView{
			ID:         entry.ID,
			OccurredAt: pages.FormatClock(entry.OccurredAt, display, true),
			ClientIP:   entry.ClientIP,
			Name:       entry.Name,
			RecordType: recordType,
			Status:     status,
			Source:     string(entry.Source),
			Protocol:   entry.Protocol,
			Answers:    strings.Split(entry.Answer, "\n"),
			Duration:   entry.Duration.Round(time.Microsecond).String(),
			Decision:   queryDecisionView(entry.Decision),
		})
	}
	return views
}

func queryDecisionView(decision querylog.Decision) pages.QueryDecisionView {
	view := pages.QueryDecisionView{
		Available: decision.Policy != "" || decision.Cache != "" || decision.Resolver != "" || decision.DNSSEC != "",
	}
	switch decision.Policy {
	case querylog.PolicyNotEvaluated:
		view.Policy = "Policy not evaluated"
		view.PolicyDetail = "Authoritative and local answers take precedence."
	case querylog.PolicyDisabled:
		view.Policy = "Blocking disabled"
	case querylog.PolicyPaused:
		view.Policy = "Blocking paused"
	case querylog.PolicyClientBypass:
		view.Policy = "Client bypassed blocking"
	case querylog.PolicyAllowed:
		view.Policy = "Allowed by policy"
		view.PolicyDetail = matchedDecisionRule(decision.PolicyRule)
		if sources := joinSourceNames(decision.PolicySources); sources != "" && view.PolicyDetail != "" {
			view.PolicyDetail += ", an exception on " + sources
		}
	case querylog.PolicyBlocked:
		view.Policy = "Blocked by policy"
		view.PolicyDetail = matchedDecisionRule(decision.PolicyRule)
		if sources := joinSourceNames(decision.PolicySources); sources != "" && view.PolicyDetail != "" {
			view.PolicyDetail += " from " + sources
		}
	case querylog.PolicyNoMatch:
		view.Policy = "No blocking rule matched"
	}
	switch decision.Cache {
	case querylog.CacheHit:
		view.Cache = "Cache hit"
	case querylog.CacheMiss:
		view.Cache = "Cache miss"
	case querylog.CacheStale:
		view.Cache = "Served stale cache"
	}
	switch decision.Resolver {
	case querylog.ResolverAuthoritative:
		view.Resolver = "Answered by an authoritative zone"
		view.Summary = "Sable answered from an authoritative zone it serves."
	case querylog.ResolverLocal:
		view.Resolver = "Answered by a local host override"
		view.Summary = "Sable answered from a local host override."
	case querylog.ResolverBlocked:
		view.Resolver = "Synthesized a blocking response"
		view.Summary = "Sable blocked this query before resolution."
	case querylog.ResolverCache:
		view.Resolver = "Returned a cached response"
		view.Summary = "Sable answered this query from its cache."
	case querylog.ResolverForwarded:
		view.Resolver = "Forwarded upstream"
		view.Summary = "Sable forwarded this query to its configured upstream resolvers."
		if decision.Route != "" {
			view.ResolverDetail = "Conditional route: " + decision.Route
			view.Summary = "Sable matched a conditional route and forwarded the query."
		} else {
			view.ResolverDetail = "Default forwarders"
		}
	case querylog.ResolverRecursive:
		view.Resolver = "Resolved recursively"
		view.Summary = "Sable resolved this query recursively."
	case querylog.ResolverError:
		view.Resolver = "Resolution failed"
		view.Summary = "Sable could not complete resolution."
	case querylog.ResolverNotAllowed:
		view.Resolver = "Refused: recursion not allowed"
		view.Summary = "Sable refused this lookup because this address isn't allowed to use recursion. Settings → Recursion sets who is."
		view.PolicyDetail = "Sable refused the lookup before checking blocking."
	case querylog.ResolverLocallyServed:
		view.Resolver = "Answered as a local-only name"
		view.Summary = "This name is reserved for local networks, so Sable said it doesn't exist instead of asking the internet."
	}
	switch decision.DNSSEC {
	case querylog.DNSSECSecure:
		view.DNSSEC = "DNSSEC secure"
	case querylog.DNSSECInsecure:
		view.DNSSEC = "DNSSEC insecure"
	case querylog.DNSSECBogus:
		view.DNSSEC = "DNSSEC bogus"
	case querylog.DNSSECIndeterminate:
		view.DNSSEC = "DNSSEC not validated"
	}
	return view
}

// joinSourceNames lists block sources in a sentence: "A", "A and B", or
// "A, B, and C".
func joinSourceNames(sources []string) string {
	switch len(sources) {
	case 0:
		return ""
	case 1:
		return sources[0]
	case 2:
		return sources[0] + " and " + sources[1]
	default:
		return strings.Join(sources[:len(sources)-1], ", ") + ", and " + sources[len(sources)-1]
	}
}

func matchedDecisionRule(rule string) string {
	if rule == "" {
		return ""
	}
	return "Matched " + rule
}

type queryLogAPIEntry struct {
	ID           int64             `json:"id"`
	OccurredAt   time.Time         `json:"occurred_at"`
	ClientIP     string            `json:"client_ip"`
	Name         string            `json:"name"`
	RecordType   uint16            `json:"record_type"`
	Class        uint16            `json:"class"`
	ResponseCode int               `json:"response_code"`
	Source       querylog.Source   `json:"source"`
	Protocol     string            `json:"protocol"`
	Answer       string            `json:"answer"`
	DurationUS   int64             `json:"duration_us"`
	Decision     querylog.Decision `json:"decision"`
}

func queryLogAPIEntries(entries []querylog.Entry) []queryLogAPIEntry {
	result := make([]queryLogAPIEntry, 0, len(entries))
	for _, entry := range entries {
		result = append(result, queryLogAPIEntry{
			ID:           entry.ID,
			OccurredAt:   entry.OccurredAt,
			ClientIP:     entry.ClientIP,
			Name:         entry.Name,
			RecordType:   entry.RecordType,
			Class:        entry.Class,
			ResponseCode: entry.ResponseCode,
			Source:       entry.Source,
			Protocol:     entry.Protocol,
			Answer:       entry.Answer,
			DurationUS:   entry.Duration.Microseconds(),
			Decision:     entry.Decision,
		})
	}
	return result
}
