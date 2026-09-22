package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights"
	blockinginsights "github.com/drudge/sable/internal/insights/blocking"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/web/pages"
)

// defaultInsightsRange is the window Insights opens on. A month is long enough
// to catch a list that failed quietly or a block somebody corrected weeks ago,
// and it matches the default query log retention.
const defaultInsightsRange = "month"

// insightsRanges are the windows Insights offers. An hour is too short to say
// anything about blocking behavior, so the control starts at a day.
var insightsRanges = map[string]struct{}{"day": {}, "week": {}, "month": {}, "year": {}}

// insightsEvidenceClients is how many clients one finding lists.
const insightsEvidenceClients = 10

// insightsRankLimit is how many entries the Insights ranking dialogs offer.
const insightsRankLimit = 250

// blockingInsightReader is the optional query log capability Insights needs.
// A store without it leaves the query activity sections unavailable rather
// than estimating them from a sample.
type blockingInsightReader interface {
	BlockingActivity(context.Context, time.Time, time.Time) (querylog.BlockingActivity, error)
	BlockedNamesMatching(context.Context, time.Time, time.Time, []string, []string) (map[string]uint64, error)
	BlockedNameEvidence(context.Context, time.Time, time.Time, string, int) (querylog.BlockedNameEvidence, error)
}

// insightsPermissions are the read permissions that open Insights. Either one
// is enough: each section then shows only what the operator may read.
var insightsPermissions = []string{auth.PermissionBlockingRead, auth.PermissionLogsRead}

func insightsRoute(path string) bool {
	return path == "/insights" || strings.HasPrefix(path, "/ui/insights/")
}

func (server *Server) insightsPage(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanBlocking && !console.CanLogs {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	window := insightsWindow(request.URL.Query().Get("range"), time.Now())
	view := pages.InsightsPageView{Console: console, Overview: pages.InsightsOverviewView{
		Range: window.Range, RangeLabel: window.Label, Loading: true,
		LoadURL: "/ui/insights/overview?range=" + url.QueryEscape(window.Range),
		CanLogs: console.CanLogs, CanBlocking: console.CanBlocking,
	}}
	if err := pages.InsightsPage(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render insights page", "error", err)
	}
}

// insightsOverviewPanel renders the analysis for one window. The page loads it
// after the shell so a slow first comparison of large block lists never holds
// up navigation, and the range control swaps it in place.
func (server *Server) insightsOverviewPanel(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanBlocking && !console.CanLogs {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	window := insightsWindow(request.URL.Query().Get("range"), time.Now())
	view := server.insightsOverview(request, console, window)
	if request.Header.Get("HX-Request") == "true" {
		writer.Header().Set("HX-Replace-Url", "/insights?range="+url.QueryEscape(window.Range))
	}
	if err := pages.InsightsContent(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render insights overview", "error", err)
	}
}

func insightsWindow(rangeName string, now time.Time) insightWindow {
	if _, offered := insightsRanges[rangeName]; !offered {
		rangeName = defaultInsightsRange
	}
	window, _ := chartInsightWindow(rangeName, now)
	return window
}

func (server *Server) insightsOverview(request *http.Request, console pages.DashboardView, window insightWindow) pages.InsightsOverviewView {
	snapshot := server.config.Current()
	blocking := snapshot.Config.Blocking
	view := pages.InsightsOverviewView{
		Range: window.Range, RangeLabel: window.Label, LogWindowQuery: window.logWindowQuery(),
		CanLogs: console.CanLogs, CanBlocking: console.CanBlocking,
		TimeDisplay:     console.TimeDisplay,
		BlockingEnabled: blocking.Enabled,
	}
	if console.CanLogs {
		view.QueryLogDisabled = !snapshot.Config.QueryLog.Enabled
		if retention := snapshot.Config.QueryLog.Retention.Duration; retention > 0 && retention < window.End.Sub(window.Start) {
			view.RetentionNote = "Query history is kept for " + insights.FormatDuration(retention) + ", so older activity in this range is no longer available."
		}
	}

	input := blockinginsights.FindingsInput{Now: window.End, UpdateInterval: blocking.UpdateInterval.Duration}
	var reader blockingInsightReader
	var sources *blockinginsights.SourceQueries
	if console.CanLogs {
		reader, _ = server.queries.(blockingInsightReader)
		if reader == nil {
			view.ActivityUnavailable = true
		}
	}

	if reader != nil {
		activity, countedWindow, err := server.blockingActivityCache.load(request.Context(), window, reader.BlockingActivity)
		if err != nil {
			server.logger.Warn("count blocking activity for insights", "error", err)
			view.ActivityUnavailable = true
		} else {
			window = countedWindow
			view.LogWindowQuery = window.logWindowQuery()
			view.Activity = &pages.InsightsActivityView{
				Queries: activity.Queries, Blocked: activity.Blocked,
				BlockedDomains: activity.BlockedDomains, BlockedClients: activity.BlockedClients,
			}
			hosts, zones := snapshot.Config.Resolver.Hosts, server.zones.Current().Zones
			view.TopClients = rankedStats(activity.TopClients, dashboardClientNames(activity.TopClients, hosts, zones), insightsRankLimit)
			view.TopDomains = rankedStats(activity.TopDomains, nil, insightsRankLimit)
			sources = &blockinginsights.SourceQueries{Lists: activity.Sources, Since: activity.SourcesSince}
			server.nameRankedClients(view.TopClients)
		}
	}

	if console.CanBlocking {
		lists := make([]blockinginsights.List, 0, len(blocking.Lists))
		for _, list := range blocking.Lists {
			lists = append(lists, blockinginsights.List{Name: list.Name, Path: list.Path, URL: list.URL, Format: list.Format})
		}
		contribution, err := server.blockListAnalysis.Contribution(request.Context(), server.baseDirectory, lists)
		if err != nil {
			server.logger.Warn("compare block lists for insights", "error", err)
			view.ListsUnavailable = true
		} else {
			input.Contribution = &contribution
			input.Queries = sources
			view.Contribution = insightsContributionView(contribution, blocking, sources)
		}
		status := server.blockLists.Status()
		health := make(map[string]blockinginsights.ListHealth, len(status.Sources))
		for _, source := range status.Sources {
			health[source.URL] = blockinginsights.ListHealth{Health: source}
		}
		for _, list := range blocking.Lists {
			if tracked, found := health[list.URL]; found && list.URL != "" {
				tracked.Name = list.Name
				input.Health = append(input.Health, tracked)
			}
		}
	}

	// A past block needs both halves of the evidence: the allow rule is
	// blocking configuration and the blocked queries are query history.
	if reader != nil && console.CanBlocking && !view.ActivityUnavailable {
		input.PastBlocks = server.pastBlocks(request.Context(), reader, window, blocking)
	}
	findings := blockinginsights.Findings(input)
	view.Findings = server.insightFindingViews(findings, snapshot.Config)
	view.CheckedSummary = insightsCheckedSummary(console, window)
	return view
}

// pastBlocks finds the names an allow rule matches that the query log shows as
// blocked in the window, then reads the evidence for the busiest of them.
func (server *Server) pastBlocks(ctx context.Context, reader blockingInsightReader, window insightWindow, blocking config.Blocking) []blockinginsights.PastBlock {
	rules := blockinginsights.NewAllowRules(blocking.AllowedDomains)
	if rules.Empty() {
		return nil
	}
	matched, err := reader.BlockedNamesMatching(ctx, window.Start, window.End, rules.Exact(), rules.Suffixes())
	if err != nil {
		server.logger.Warn("match allowed domains against blocked history", "error", err)
		return nil
	}
	ranked := rankedStats(matched, nil, 3)
	blocks := make([]blockinginsights.PastBlock, 0, len(ranked))
	for _, candidate := range ranked {
		rule := rules.Match(candidate.Name)
		if rule == "" {
			continue
		}
		evidence, err := reader.BlockedNameEvidence(ctx, window.Start, window.End, candidate.Name, insightsEvidenceClients)
		if err != nil {
			server.logger.Warn("read blocked name evidence", "name", candidate.Name, "error", err)
			continue
		}
		blocks = append(blocks, blockinginsights.PastBlock{Rule: rule, Evidence: evidence})
	}
	return blocks
}

func (server *Server) insightFindingViews(findings []insights.Finding, configuration config.Config) []pages.InsightFindingView {
	views := make([]pages.InsightFindingView, 0, len(findings))
	for index, finding := range findings {
		view := pages.InsightFindingView{
			ID:   "insight-finding-" + strconv.Itoa(index+1),
			Kind: finding.Kind, Tone: string(finding.Tone), Icon: insightFindingIcon(finding.Kind),
			Title: finding.Title, Subject: finding.Subject, SubjectMonospace: finding.SubjectMonospace,
			Summary: finding.Summary, Method: finding.Method,
			Destination: finding.Destination, DestinationLabel: finding.DestinationLabel,
		}
		for _, fact := range finding.Facts {
			view.Facts = append(view.Facts, pages.InsightFactView{Label: fact.Label, Value: fact.Value, Time: fact.Time, Monospace: fact.Monospace})
		}
		if finding.Query != nil {
			view.Query = &pages.InsightQueryView{Name: finding.Query.Name, ClientIP: finding.Query.ClientIP, Blocked: finding.Query.Blocked}
		}
		if len(finding.Clients) > 0 {
			counts := make(map[string]uint64, len(finding.Clients))
			for _, client := range finding.Clients {
				counts[client.Name] = client.Hits
			}
			view.Clients = rankedStats(counts, dashboardClientNames(counts, configuration.Resolver.Hosts, server.zones.Current().Zones), len(counts))
			server.nameRankedClients(view.Clients)
		}
		views = append(views, view)
	}
	return views
}

func insightFindingIcon(kind string) string {
	switch kind {
	case blockinginsights.KindPastBlock:
		return "flag"
	case blockinginsights.KindUpdateFailing:
		return "alert-triangle"
	case blockinginsights.KindListUnreadable:
		return "file-text"
	case blockinginsights.KindLowUnique:
		return "layers"
	case blockinginsights.KindUniqueCoverage:
		return "check-circle"
	default:
		return "info"
	}
}

func insightsContributionView(contribution blockinginsights.Contribution, blocking config.Blocking, queries *blockinginsights.SourceQueries) *pages.InsightsContributionView {
	locations := make(map[string]string, len(blocking.Lists))
	for _, list := range blocking.Lists {
		locations[list.Name] = pages.BlockListLocation(list.URL, list.Path)
	}
	view := &pages.InsightsContributionView{
		Analyzed: contribution.Analyzed, Domains: contribution.Domains, Unique: contribution.Unique,
		AnalyzedAt: contribution.AnalyzedAt, HasQueries: queries != nil,
	}
	if queries != nil {
		view.QueriesSince = queries.Since
	}
	for _, list := range contribution.Lists {
		view.Lists = append(view.Lists, pages.InsightListView{
			Name: list.Name, Location: locations[list.Name], Available: list.Available, Problem: list.Problem,
			Domains: list.Domains, Unique: list.Unique, Covered: list.Covered,
			LargestOverlap: list.LargestOverlap.Name, LargestOverlapDomains: list.LargestOverlap.Domains,
			Queries: sourceActivity(queries, list.Name),
		})
	}
	// Hand-written blocked domains are a source too. They are not a list to
	// compare, but they belong in an answer to what is doing the blocking.
	if len(blocking.Domains) > 0 {
		view.Custom = &pages.InsightCustomSourceView{Domains: len(blocking.Domains), Queries: sourceActivity(queries, blockcompiler.CustomSourceName)}
	}
	return view
}

// insightsCheckedSummary tells an operator with nothing to review what Sable
// actually looked at, so an empty list reads as a result rather than a gap.
func sourceActivity(queries *blockinginsights.SourceQueries, name string) querylog.SourceActivity {
	if queries == nil {
		return querylog.SourceActivity{}
	}
	return queries.Lists[name]
}

func insightsCheckedSummary(console pages.DashboardView, window insightWindow) string {
	period := strings.ToLower(window.Label)
	switch {
	case console.CanLogs && console.CanBlocking:
		return "Sable checked blocked queries, allowed domains, block list updates, and block list overlap for the " + period + "."
	case console.CanLogs:
		return "Sable checked blocked queries for the " + period + "."
	default:
		return "Sable checked block list updates and block list overlap."
	}
}
