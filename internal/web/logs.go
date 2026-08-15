package web

import (
	"context"
	"encoding/csv"
	"fmt"
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
	filter := serverlog.Filter{
		Search: request.URL.Query().Get("search"),
		Level:  request.URL.Query().Get("level"),
		Limit:  500,
	}
	view := pages.RuntimeLogsView{Search: filter.Search, Level: filter.Level, Live: request.URL.Query().Get("live") == "1"}
	if view.Level == "" {
		view.Level = "all"
	}
	if server.runtimeLogs == nil {
		view.Error = "Runtime log capture is unavailable."
		return view
	}
	entries := server.runtimeLogs.Entries(filter)
	view.Entries = make([]pages.RuntimeLogEntryView, 0, len(entries))
	for _, entry := range entries {
		view.Entries = append(view.Entries, pages.RuntimeLogEntryView{
			OccurredAt: pages.FormatRuntimeLogTime(entry.OccurredAt, requestTimeFormat(request)),
			Level:      runtimeLevelName(entry.Level),
			Message:    entry.Message,
			Attributes: serverlog.AttributeText(entry.Attributes),
		})
	}
	view.Count = len(view.Entries)
	lines := make([]string, 0, len(view.Entries))
	for _, entry := range view.Entries {
		lines = append(lines, strings.TrimSpace(entry.OccurredAt+" "+strings.ToUpper(entry.Level)+" "+entry.Message+" "+entry.Attributes))
	}
	view.CopyText = strings.Join(lines, "\n")
	return view
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
	view.Entries = queryLogEntryViews(result.Entries, requestTimeFormat(request))
	for index := range view.Entries {
		view.Entries[index].OccurredAt = pages.FormatShortDateTime(result.Entries[index].OccurredAt, requestTimeFormat(request), true)
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
	if server.runtimeLogs == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"error": "runtime log capture unavailable"})
		return
	}
	writeJSON(writer, http.StatusOK, server.runtimeLogs.Entries(serverlog.Filter{
		Search: request.URL.Query().Get("search"), Level: request.URL.Query().Get("level"), Limit: 500,
	}))
}

func (server *Server) exportRuntimeLogs(writer http.ResponseWriter, request *http.Request) {
	if server.runtimeLogs == nil {
		http.Error(writer, "runtime log capture unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Content-Disposition", `attachment; filename="sable-runtime.log"`)
	entries := server.runtimeLogs.Entries(serverlog.Filter{
		Search: request.URL.Query().Get("search"), Level: request.URL.Query().Get("level"), Limit: serverlog.DefaultCapacity,
	})
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
