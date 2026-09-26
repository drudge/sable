package web

import (
	"context"
	"fmt"
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
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/insights/services"
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

// insightsTabs are the Insights sections in display order.
var insightsTabs = []string{"overview", "devices", "blocking"}

// maximumOverviewFindings keeps the Overview to what is worth reading.
const maximumOverviewFindings = 10

// insightsTab picks the section to show. A range change arrives without its
// own tab parameter, so the tab the operator is on is read from the page URL
// htmx reports.
func insightsTab(request *http.Request, console pages.DashboardView) string {
	tab := request.URL.Query().Get("tab")
	if tab == "" {
		if current, err := url.Parse(request.Header.Get("HX-Current-URL")); err == nil {
			tab = current.Query().Get("tab")
		}
	}
	if tab == "devices" && !console.CanLogs {
		tab = ""
	}
	for _, offered := range insightsTabs {
		if tab == offered {
			return tab
		}
	}
	return "overview"
}

func insightsPageURL(window insightWindow, tab string) string {
	values := url.Values{"range": []string{window.Range}}
	if tab != "overview" {
		values.Set("tab", tab)
	}
	return "/insights?" + values.Encode()
}

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
	tab := insightsTab(request, console)
	// The page loads its analysis next; start the reads behind it now.
	server.warmInsights(console, window)
	view := pages.InsightsPageView{Console: console, Overview: pages.InsightsOverviewView{
		Range: window.Range, RangeLabel: window.Label, Loading: true, ActiveTab: tab,
		LoadURL: "/ui/insights/overview?" + url.Values{"range": []string{window.Range}, "tab": []string{tab}}.Encode(),
		CanLogs: console.CanLogs, CanBlocking: console.CanBlocking,
	}}
	if err := pages.InsightsPage(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render insights page", "error", err)
	}
}

// warmInsights starts every slow read Insights needs for a window at once, so
// a page with nothing cached waits for its slowest read rather than for each
// in turn. The reads land in the caches the page itself reads through, where
// its own requests join them; reads already cached or running are left alone.
// They run in the background for as long as the server does and never hold up
// the page that started them.
func (server *Server) warmInsights(console pages.DashboardView, window insightWindow) {
	warm := server.goBackground
	if console.CanLogs {
		if reader, ok := server.queries.(deviceInsightReader); ok {
			warm(func(ctx context.Context) { server.deviceActivityCache.load(ctx, window, reader.ClientActivity) })
			warm(func(ctx context.Context) { server.deviceSignalCache.load(ctx, window, deviceSignals(reader)) })
			warm(func(ctx context.Context) {
				server.repeatedLookupCache.load(ctx, window, repeatedLookups(reader, window.End.Add(-24*time.Hour)))
			})
		}
		if reader, ok := server.queries.(blockingInsightReader); ok {
			warm(func(ctx context.Context) { server.blockingActivityCache.load(ctx, window, reader.BlockingActivity) })
		}
		if reader, ok := server.queries.(queryInsightReader); ok {
			warm(func(ctx context.Context) { server.appCache.load(ctx, window, reader.QueryLogInsights) })
		}
	}
	if console.CanBlocking {
		lists := server.config.Current().Config.Blocking.Lists
		analyzed := make([]blockinginsights.List, 0, len(lists))
		for _, list := range lists {
			analyzed = append(analyzed, blockinginsights.List{Name: list.Name, Path: list.Path, URL: list.URL, Format: list.Format})
		}
		warm(func(ctx context.Context) { server.blockListAnalysis.Contribution(ctx, server.baseDirectory, analyzed) })
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
	server.warmInsights(console, window)
	view := server.insightsOverview(request, console, window)
	view.ActiveTab = insightsTab(request, console)
	if request.Header.Get("HX-Request") == "true" {
		writer.Header().Set("HX-Replace-Url", insightsPageURL(window, view.ActiveTab))
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
		CanNameDevices:  console.CanWriteSettings,
	}
	if console.CanLogs {
		view.QueryLogDisabled = !snapshot.Config.QueryLog.Enabled
		if retention := snapshot.Config.QueryLog.Retention.Duration; retention > 0 && retention < window.End.Sub(window.Start) {
			view.RetentionNote = "Query history is kept for " + insights.FormatDuration(retention) + ", so older activity in this range is no longer available."
		}
	}

	analyzers, blockingData, deviceData := server.insightAnalyzers(console, window)
	findings := insights.Collect(request.Context(), insights.Window{Start: window.Start, End: window.End}, analyzers,
		func(analyzer insights.Analyzer, err error) {
			server.logger.Warn("analyze insights", "analyzer", fmt.Sprintf("%T", analyzer), "error", err)
		})
	feedbackStore, canRemember := server.queries.(insightFeedbackStore)
	view.CanHideFindings = canRemember && console.CanWriteSettings
	if canRemember {
		feedback, err := feedbackStore.InsightFeedback(request.Context(), time.Now())
		if err != nil {
			server.logger.Warn("read insight feedback", "error", err)
		}
		var hidden []insights.Finding
		findings, hidden = insights.Hide(findings, feedback, time.Now())
		view.HiddenFindings = insightHiddenViews(hidden, feedback, console.TimeDisplay)
	}
	// Client addresses, and so the names of their devices, are shown only to
	// operators who can read the query log.
	var given devices.GivenNames
	if console.CanLogs {
		given = server.givenClientNames(request.Context(), window.Start)
	}
	view.Findings = server.insightFindingViews(findings[:min(len(findings), maximumOverviewFindings)], given, snapshot.Config)
	view.Headline = insightHeadline(findings, view.Findings)
	view.CheckedSummary = insightsCheckedSummary(console, window)

	// The page's own sections show the material the analyzers examined; the
	// sources kept it, so nothing is loaded twice.
	if console.CanLogs {
		activity, err := blockingData.loadActivity(request.Context())
		if err != nil || activity == nil {
			view.ActivityUnavailable = true
		} else {
			view.LogWindowQuery = blockingData.counted.logWindowQuery()
			view.Activity = &pages.InsightsActivityView{
				Queries: activity.Queries, Blocked: activity.Blocked,
				BlockedDomains: activity.BlockedDomains, BlockedClients: activity.BlockedClients,
			}
			hosts, zones := snapshot.Config.Resolver.Hosts, server.zones.Current().Zones
			view.TopClients = rankedStats(activity.TopClients, dashboardClientNames(activity.TopClients, given, hosts, zones), insightsRankLimit)
			view.TopDomains = rankedStats(activity.TopDomains, nil, insightsRankLimit)
			server.nameRankedClients(view.TopClients)
		}
		if deviceData == nil {
			view.DevicesUnavailable = true
		} else if report, err := deviceData.load(request.Context()); err != nil {
			view.DevicesUnavailable = true
		} else {
			view.Devices = insightDeviceViews(report)
			view.DeviceSummary = insightDeviceSummary(view.Devices)
			view.BusiestDevices = busiestDeviceRanking(view.Devices, window.Range)
		}
		view.TopApps = server.topAppRanking(request, window)
	}
	if console.CanBlocking {
		contribution, err := blockingData.Contribution(request.Context())
		if err != nil || contribution == nil {
			view.ListsUnavailable = true
		} else {
			queries, _ := blockingData.SourceQueries(request.Context(), insights.Window{})
			view.Contribution = insightsContributionView(*contribution, blocking, queries)
		}
	}
	return view
}

// insightHeadline says what stands out, one clause per finding with news. A
// clause that starts with its finding's subject is split after it, so the
// page can set the subject apart, and a finding the page shows opens from it.
func insightHeadline(findings []insights.Finding, views []pages.InsightFindingView) *pages.InsightHeadlineView {
	named, more := insights.Headlines(findings)
	headline := &pages.InsightHeadlineView{More: more}
	for _, finding := range named {
		clause := pages.InsightHeadlineClause{Rest: finding.Headline, Tone: string(finding.Tone)}
		if label := finding.Subject.Label; label != "" && strings.HasPrefix(finding.Headline, label) {
			clause.Subject, clause.Rest, clause.Monospace = label, strings.TrimPrefix(finding.Headline, label), finding.Subject.Monospace
		}
		for _, view := range views {
			if view.FindingID == finding.ID {
				clause.Dialog = view.ID
			}
		}
		headline.Clauses = append(headline.Clauses, clause)
	}
	return headline
}

func insightDeviceSummary(views []pages.InsightDeviceView) pages.InsightDeviceSummaryView {
	summary := pages.InsightDeviceSummaryView{Devices: len(views)}
	for _, device := range views {
		summary.Queries += device.Queries
		summary.Blocked += device.Blocked
		if device.New {
			summary.New++
		}
		if device.Named {
			summary.Named++
		}
	}
	return summary
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

func (server *Server) insightFindingViews(findings []insights.Finding, given devices.GivenNames, configuration config.Config) []pages.InsightFindingView {
	views := make([]pages.InsightFindingView, 0, len(findings))
	for index, finding := range findings {
		view := pages.InsightFindingView{
			ID: "insight-finding-" + strconv.Itoa(index+1), FindingID: finding.ID,
			Kind: finding.Kind, Tone: string(finding.Tone), Icon: insightFindingIcon(finding.Kind),
			Title: finding.Title, Subject: finding.Subject.Label, SubjectMonospace: finding.Subject.Monospace,
			SubjectSource: finding.Subject.LabelSource,
			Summary:       finding.Summary, Explanations: finding.Explanations, Method: finding.Method,
			Destination: finding.Destination, DestinationLabel: finding.DestinationLabel,
			Chart: finding.Chart,
		}
		for _, fact := range finding.Facts {
			view.Facts = append(view.Facts, pages.InsightFactView{Label: fact.Label, Value: fact.Value, Time: fact.Time, Monospace: fact.Monospace})
		}
		if finding.Query != nil {
			view.Query = &pages.InsightQueryView{Name: finding.Query.Name, ClientIP: finding.Query.ClientIP, Blocked: finding.Query.Blocked}
		}
		for _, reason := range finding.Reasons {
			view.Reasons = append(view.Reasons, pages.InsightReasonView{Text: reason.Text, Code: reason.Code})
		}
		view.DeviceKey = finding.Subject.Device
		for _, domain := range finding.Domains {
			item := pages.InsightDeviceDomainView{Name: domain.Name, FirstSeen: domain.FirstSeen}
			if domain.Query != nil {
				item.ClientIP = domain.Query.ClientIP
			}
			view.Domains = append(view.Domains, item)
		}
		if len(finding.Clients) > 0 {
			counts := make(map[string]uint64, len(finding.Clients))
			for _, client := range finding.Clients {
				counts[client.Name] = client.Hits
			}
			view.Clients = rankedStats(counts, dashboardClientNames(counts, given, configuration.Resolver.Hosts, server.zones.Current().Zones), len(counts))
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
	case devices.KindNewDevice:
		return "circle-plus"
	case devices.KindNewDestinations:
		return "globe"
	case devices.KindTrafficSpike:
		return "line-chart"
	case devices.KindWentQuiet:
		return "power"
	case devices.KindNewApp:
		return "grid-2x2-plus"
	case devices.KindUnusualHours:
		return "clock-alert"
	case devices.KindCheckIn:
		return "timer"
	case devices.KindApplianceDrift:
		return "globe-lock"
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

func sourceActivity(queries *blockinginsights.SourceQueries, name string) querylog.SourceActivity {
	if queries == nil {
		return querylog.SourceActivity{}
	}
	return queries.Lists[name]
}

// insightsCheckedSummary tells an operator with nothing to review what Sable
// actually looked at, so an empty list reads as a result rather than a gap.
func insightsCheckedSummary(console pages.DashboardView, window insightWindow) string {
	period := strings.ToLower(window.Label)
	switch {
	case console.CanLogs && console.CanBlocking:
		return "Sable checked new and changed devices, blocked queries, allowed domains, block list updates, and block list overlap for the " + period + "."
	case console.CanLogs:
		return "Sable checked new and changed devices and blocked queries for the " + period + "."
	default:
		return "Sable checked block list updates and block list overlap."
	}
}

// topAppRanking groups the window's busiest domains into the apps that own
// them. It reads the same counts as the dashboard's domain ranking, so the two
// never disagree about the traffic behind an app.
func (server *Server) topAppRanking(request *http.Request, window insightWindow) []pages.RankedStatView {
	reader, ok := server.queries.(queryInsightReader)
	if !ok {
		return nil
	}
	counted, _, err := server.appCache.load(request.Context(), window, reader.QueryLogInsights)
	if err != nil {
		server.logger.Warn("rank insights apps", "error", err)
		return nil
	}
	domains := make([]services.Domain, 0, len(counted.Domains))
	for name, hits := range counted.Domains {
		domains = append(domains, services.Domain{Name: name, Queries: hits})
	}
	usages := services.Group(domains)
	ranking := make([]pages.RankedStatView, 0, min(len(usages), insightsRankLimit))
	for _, usage := range usages {
		// Operating system check-ins are not apps anyone chose to use.
		if usage.Service.Category == services.CategoryPlatform {
			continue
		}
		if len(ranking) == insightsRankLimit {
			break
		}
		ranking = append(ranking, pages.RankedStatView{
			Name: usage.Service.Name, Secondary: usage.Service.Category, Value: usage.Queries,
			Drawer: pages.AppDrawerLink(usage.Service.ID, window.Range),
			Icon:   pages.AppIcon(usage.Service.ID, usage.Service.Category),
		})
	}
	return ranking
}

// busiestDeviceRanking ranks devices by their queries. Each opens the
// device's drawer, whose addresses link to exactly the queries each made: a
// device with several has no single query log filter that matches them all.
func busiestDeviceRanking(views []pages.InsightDeviceView, rangeName string) []pages.RankedStatView {
	ranking := make([]pages.RankedStatView, 0, min(len(views), insightsRankLimit))
	for _, device := range views[:min(len(views), insightsRankLimit)] {
		addresses := make([]string, 0, len(device.Addresses))
		for _, address := range device.Addresses {
			addresses = append(addresses, address.Address)
		}
		ranking = append(ranking, pages.RankedStatView{
			Name: device.Label, Secondary: deviceAddressDetail(device.Label, addresses), Value: device.Queries,
			Drawer: pages.DeviceDrawerLink(device.Key, rangeName),
		})
	}
	return ranking
}
