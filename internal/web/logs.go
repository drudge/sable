package web

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/serverlog"
	"github.com/drudge/sable/internal/web/pages"
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
	if activeTab != "queries" {
		activeTab = "server"
	}
	view := pages.LogsPageView{Console: server.consoleView(request), ActiveTab: activeTab}
	view.Runtime = server.runtimeLogsView(request)
	view.Queries = server.queryLogsView(request)
	view.Queries.CanBlocking = view.Console.CanBlocking
	if err := pages.LogsPage(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render logs page", "error", err)
	}
}

func (server *Server) runtimeLogsPanel(writer http.ResponseWriter, request *http.Request) {
	if err := pages.RuntimeLogsPanel(server.runtimeLogsView(request)).Render(request.Context(), writer); err != nil {
		server.logger.Error("render runtime logs", "error", err)
	}
}

func (server *Server) runtimeLogsView(request *http.Request) pages.RuntimeLogsView {
	values := request.URL.Query()
	view := pages.RuntimeLogsView{
		Search: values.Get("search"), Level: values.Get("level"), Live: values.Get("live") == "1",
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
	view.FirstURL = runtimeLogPanelURL(raw, 1, view.Live)
	view.PreviousURL = runtimeLogPanelURL(raw, max(1, result.Page-1), view.Live)
	view.NextURL = runtimeLogPanelURL(raw, min(max(1, result.TotalPages), result.Page+1), view.Live)
	view.LastURL = runtimeLogPanelURL(raw, max(1, result.TotalPages), view.Live)
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

func runtimeLogPanelURL(values url.Values, page int, live bool) string {
	copied := make(url.Values, len(values)+2)
	for key, value := range values {
		copied[key] = value
	}
	copied.Set("page", strconv.Itoa(page))
	if live {
		copied.Set("live", "1")
	}
	return "/ui/logs/runtime?" + copied.Encode()
}

func runtimeLevelName(level interface{ String() string }) string {
	name := strings.ToLower(level.String())
	if before, _, found := strings.Cut(name, "+"); found {
		name = before
	}
	return name
}

func (server *Server) queryLogsPanel(writer http.ResponseWriter, request *http.Request) {
	view := server.queryLogsView(request)
	if view.Error != "" {
		writer.WriteHeader(http.StatusInternalServerError)
	}
	if err := pages.QueryLogsPanel(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render query logs", "error", err)
	}
}

func (server *Server) queryLogsView(request *http.Request) pages.QueryLogsView {
	filter, raw := queryLogFilter(request)
	view := pages.QueryLogsView{
		Page: filter.Page, PageSize: filter.PageSize, ClientIP: raw.Get("client_ip"),
		Name: raw.Get("name"), RecordType: strings.ToUpper(raw.Get("record_type")),
		ResponseCode: strings.ToUpper(raw.Get("response_code")), Source: raw.Get("source"), Protocol: strings.ToUpper(raw.Get("protocol")),
		Live: raw.Get("live") == "1", FiltersOpen: raw.Get("filters") == "1",
	}
	view.FiltersOpen = view.FiltersOpen || queryFiltersActiveView(view)
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
	view.FirstURL = queryLogPanelURL(raw, 1)
	view.PreviousURL = queryLogPanelURL(raw, max(1, result.Page-1))
	view.NextURL = queryLogPanelURL(raw, min(max(1, result.TotalPages), result.Page+1))
	view.LastURL = queryLogPanelURL(raw, max(1, result.TotalPages))
	view.ExportURL = "/api/v1/logs/queries/export?" + exportQueryValues(raw).Encode()
	return view
}

func queryFiltersActiveView(view pages.QueryLogsView) bool {
	return view.ClientIP != "" || view.Name != "" || view.RecordType != "" || view.ResponseCode != "" || view.Source != "" || view.Protocol != ""
}

func queryLogFilter(request *http.Request) (querylog.Filter, url.Values) {
	values := request.URL.Query()
	filter := querylog.Filter{
		Page:     parseBoundedInt(values.Get("page"), 1, 1, 1_000_000),
		PageSize: parseBoundedInt(values.Get("page_size"), 50, 1, 250),
		ClientIP: values.Get("client_ip"), Name: values.Get("name"),
		Source: querylog.Source(values.Get("source")), Protocol: values.Get("protocol"),
	}
	if value := strings.ToUpper(strings.TrimSpace(values.Get("record_type"))); value != "" && value != "ALL" {
		for _, item := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
			if number, found := dns.StringToType[item]; found {
				filter.RecordTypes = append(filter.RecordTypes, number)
			}
		}
	}
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

func parseBoundedInt(raw string, fallback, minimum, maximum int) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}

func queryLogPanelURL(values url.Values, page int) string {
	copy := exportQueryValues(values)
	copy.Set("page", strconv.Itoa(page))
	if values.Get("live") == "1" {
		copy.Set("live", "1")
	}
	return "/ui/logs/queries?" + copy.Encode()
}

func exportQueryValues(values url.Values) url.Values {
	copy := make(url.Values)
	for _, key := range []string{"client_ip", "name", "record_type", "response_code", "source", "protocol", "page_size"} {
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
			writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "server log history unavailable"})
			return
		}
		writeJSON(writer, http.StatusOK, result)
		return
	}
	if server.runtimeLogs == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "runtime log capture unavailable"})
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
	filter.Page = 1
	filter.PageSize = 250
	result, err := pager.QueryEvents(request.Context(), filter)
	if err != nil {
		server.logger.Error("export query log", "error", err)
		http.Error(writer, "query log unavailable", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "text/csv; charset=utf-8")
	writer.Header().Set("Content-Disposition", `attachment; filename="sable-query-log.csv"`)
	output := csv.NewWriter(writer)
	_ = output.Write([]string{"timestamp", "client_ip", "domain", "type", "response", "status", "protocol", "answer", "duration"})
	for {
		for _, entry := range result.Entries {
			_ = output.Write(queryLogCSVRow(entry))
		}
		if result.Page >= result.TotalPages {
			break
		}
		filter.Page++
		result, err = pager.QueryEvents(request.Context(), filter)
		if err != nil {
			server.logger.Error("continue query log export", "error", err, "page", filter.Page)
			break
		}
	}
	output.Flush()
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
