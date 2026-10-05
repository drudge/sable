package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights"
	blockinginsights "github.com/drudge/sable/internal/insights/blocking"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/web/pages"
)

// defaultInsightsRange is the window Insights opens on. A month is long enough
// to catch a list that failed quietly or a block somebody corrected weeks ago,
// and it matches the default query log retention.
const defaultInsightsRange = "month"

// insightsRangeCookie remembers the range last picked in Insights, so the
// sidebar and the command palette open it again, as the dashboard chart does.
const insightsRangeCookie = "sable_insights_range"

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
var insightsTabs = []string{"overview", "devices", "apps", "blocking"}

// maximumOverviewFindings keeps the Overview to what is worth reading.
const maximumOverviewFindings = 10

// insightsTab picks the section to show. A range change arrives without its
// own tab parameter, so the tab the operator is on is read from the page URL
// htmx reports.
func insightsTab(request *http.Request, console pages.DashboardView) string {
	tab := request.URL.Query().Get("tab")
	// A device's own address opens on Devices, behind its drawer.
	if tab == "" && request.PathValue("key") != "" {
		tab = "devices"
	}
	if tab == "" {
		if current, err := url.Parse(request.Header.Get("HX-Current-URL")); err == nil {
			tab = current.Query().Get("tab")
		}
	}
	if (tab == "devices" || tab == "apps") && !console.CanLogs {
		tab = ""
	}
	for _, offered := range insightsTabs {
		if tab == offered {
			return tab
		}
	}
	return "overview"
}

func insightsPageURL(window insightWindow, tab string, filter pages.InsightDeviceFilterView, apps pages.InsightAppFilterView) string {
	values := url.Values{"range": []string{window.Range}}
	if tab != "overview" {
		values.Set("tab", tab)
	}
	for _, parameter := range [][2]string{
		{"search", filter.Search}, {"type", filter.Type}, {"show", filter.Show},
		{"app_search", apps.Search}, {"category", apps.Category}, {"app_show", apps.Show},
	} {
		if parameter[1] != "" {
			values.Set(parameter[0], parameter[1])
		}
	}
	return "/insights?" + values.Encode()
}

// insightsDeviceShows are the Devices tab's choices of which devices to show.
var insightsDeviceShows = map[string]struct{}{"new": {}, "named": {}, "unnamed": {}, devices.NotUsingSableShow: {}}

// maximumDeviceSearch bounds the search the Devices tab renders back.
const maximumDeviceSearch = 100

// insightDeviceFilter reads the Devices tab's search and filters. The page
// keeps them in its URL, so a range change or a refresh, which arrive without
// them, read them from the page URL htmx reports, as they do the tab.
func insightDeviceFilter(request *http.Request) pages.InsightDeviceFilterView {
	values := request.URL.Query()
	if !values.Has("search") && !values.Has("type") && !values.Has("show") {
		if current, err := url.Parse(request.Header.Get("HX-Current-URL")); err == nil {
			values = current.Query()
		}
	}
	filter := pages.InsightDeviceFilterView{Search: strings.TrimSpace(values.Get("search"))}
	if len(filter.Search) > maximumDeviceSearch {
		filter.Search = strings.ToValidUTF8(filter.Search[:maximumDeviceSearch], "")
	}
	if kind := values.Get("type"); kind == pages.UnknownDeviceType || slices.Contains(config.ClientTypes, kind) {
		filter.Type = kind
	}
	if _, offered := insightsDeviceShows[values.Get("show")]; offered {
		filter.Show = values.Get("show")
	}
	return filter
}

// insightsDrawerOpen reports whether the page htmx is working on is the
// address of a drawer, such as a device's, rather than Insights itself.
func insightsDrawerOpen(request *http.Request) bool {
	current, err := url.Parse(request.Header.Get("HX-Current-URL"))
	return err == nil && strings.HasPrefix(current.Path, "/insights/")
}

// linkedFinding is the link ID of the finding whose address the page is at,
// if it is at one.
func linkedFinding(request *http.Request) string {
	current, err := url.Parse(request.Header.Get("HX-Current-URL"))
	if err != nil {
		return ""
	}
	id, found := strings.CutPrefix(current.Path, pages.InsightFindingRoute)
	if !found || strings.Contains(id, "/") {
		return ""
	}
	return id
}

func (server *Server) insightsPage(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanBlocking && !console.CanLogs {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	window := insightsWindow(server.insightsRange(writer, request), time.Now())
	tab := insightsTab(request, console)
	// The page loads its analysis next; start the reads behind it now.
	server.warmInsights(console, window)
	view := pages.InsightsPageView{Console: console, Overview: pages.InsightsOverviewView{
		Range: window.Range, RangeLabel: window.Label, Loading: true, ActiveTab: tab,
		PageURL: insightsPageURL(window, tab, insightDeviceFilter(request), insightAppFilter(request)),
		LoadURL: "/ui/insights/overview?" + url.Values{"range": []string{window.Range}, "tab": []string{tab}}.Encode(),
		CanLogs: console.CanLogs, CanBlocking: console.CanBlocking,
		Settings: server.insightSettingsPageView(console),
	}}
	server.render(writer, request, pages.InsightsPage(view))
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
		if reader, ok := server.queries.(appInsightReader); ok {
			warm(func(ctx context.Context) { server.appActivityCache.load(ctx, window, reader.AppActivity) })
			if recent, valid := chartInsightWindow(appFailingWindow, window.End); valid {
				warm(func(ctx context.Context) { server.appActivityCache.load(ctx, recent, reader.AppActivity) })
			}
			warm(func(ctx context.Context) { server.appSightingCache.load(ctx, window, appSightings(reader)) })
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
	window := insightsWindow(server.insightsRange(writer, request), time.Now())
	server.warmInsights(console, window)
	view := server.insightsOverview(request, console, window)
	view.ActiveTab = insightsTab(request, console)
	// At a drawer's address the page keeps it, so the drawer can open once
	// this arrives.
	if request.Header.Get("HX-Request") == "true" && !insightsDrawerOpen(request) {
		writer.Header().Set("HX-Replace-Url", insightsPageURL(window, view.ActiveTab, view.DeviceFilter, view.AppFilter))
	}
	server.render(writer, request, pages.InsightsContent(view))
}

// insightsRange is the range a request shows: the one it names, which is
// remembered, or else the one last picked. A request with neither gets the
// default.
func (server *Server) insightsRange(writer http.ResponseWriter, request *http.Request) string {
	if rangeName := request.URL.Query().Get("range"); offersInsightsRange(rangeName) {
		http.SetCookie(writer, &http.Cookie{
			Name: insightsRangeCookie, Value: rangeName, Path: "/",
			Expires: time.Now().Add(dashboardChartRangeMaxAge), MaxAge: int(dashboardChartRangeMaxAge / time.Second),
			HttpOnly: true, Secure: server.secureCookies || request.TLS != nil, SameSite: http.SameSiteStrictMode,
		})
		return rangeName
	}
	return rememberedInsightsRange(request)
}

// requestedInsightsRange is the range a request shows without remembering
// it, for the drawers and tabs that open inside the page.
func requestedInsightsRange(request *http.Request) string {
	if rangeName := request.URL.Query().Get("range"); offersInsightsRange(rangeName) {
		return rangeName
	}
	return rememberedInsightsRange(request)
}

func rememberedInsightsRange(request *http.Request) string {
	if cookie, err := request.Cookie(insightsRangeCookie); err == nil && offersInsightsRange(cookie.Value) {
		return cookie.Value
	}
	return defaultInsightsRange
}

func offersInsightsRange(rangeName string) bool {
	_, offered := insightsRanges[rangeName]
	return offered
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
		Settings:        server.insightSettingsPageView(console),
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
	// Kinds an operator turned off never reach the page, whichever analyzer
	// made them.
	findings = insightModesOf(snapshot.Config.Insights.Findings).shown(findings)
	feedbackStore, canRemember := server.queries.(insightFeedbackStore)
	view.CanHideFindings = canRemember && console.CanWriteSettings
	var hidden []insights.Finding
	if canRemember {
		feedback, err := feedbackStore.InsightFeedback(request.Context(), time.Now())
		if err != nil {
			server.logger.Warn("read insight feedback", "error", err)
		}
		findings, hidden = insights.Hide(findings, feedback, time.Now())
		view.HiddenFindings = insightHiddenViews(hidden, feedback, console.TimeDisplay)
		if deviceData != nil && deviceData.coverage != nil {
			view.HiddenFindings = append(view.HiddenFindings, expectedSilentViews(deviceData.coverage.silent(request.Context()))...)
		}
	}
	// Client addresses, and so the names of their devices, are shown only to
	// operators who can read the query log.
	var given devices.GivenNames
	if console.CanLogs {
		given = server.givenClientNames(request.Context(), window.Start)
	}
	view.Findings = server.insightFindingViews(findings[:min(len(findings), maximumOverviewFindings)], given, snapshot.Config, window.Range)
	view.Headline = insightHeadline(findings, view.Findings)
	// A link can open a finding further down than the Overview lists, and
	// one the page cannot show says why.
	if linked := linkedFinding(request); linked != "" {
		index := slices.IndexFunc(findings, func(finding insights.Finding) bool { return insights.LinkID(finding.ID) == linked })
		switch {
		case index >= maximumOverviewFindings:
			extra := server.insightFindingViews(findings[index:index+1], given, snapshot.Config, window.Range)[0]
			extra.ID = "insight-finding-linked"
			view.LinkedFinding = &extra
		case index < 0:
			view.LinkedMissing = insightLinkedMissing(linked, window.Range, view.HiddenFindings, view.CanHideFindings)
		}
	}
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
		var report deviceReport
		if deviceData == nil {
			view.DevicesUnavailable = true
		} else if loaded, err := deviceData.load(request.Context()); err != nil {
			view.DevicesUnavailable = true
		} else {
			report = loaded
			view.Devices = insightDeviceViews(report)
			if deviceData.coverage != nil {
				view.Devices = withSilentDevices(view.Devices, deviceData.coverage.silent(request.Context()), report)
			}
			view.DeviceSummary = insightDeviceSummary(view.Devices)
			view.BusiestDevices = busiestDeviceRanking(view.Devices, window.Range)
		}
		view.DeviceFilter, view.DeviceTypeOptions = insightDeviceFilter(request), devices.TypeLabels()
		var apps querylog.AppActivity
		if view.TopApps, view.Apps, apps, err = server.insightApps(request.Context(), window, report); err != nil {
			server.logger.Warn("count insights apps", "error", err)
			view.AppsUnavailable = true
		}
		view.AppsSince, view.AppsFailedSince = apps.Since, apps.FailedSince
		view.AppFilter = insightAppFilter(request)
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

// insightsLongerRanges is the next longer range to look for a finding in.
var insightsLongerRanges = map[string][2]string{"day": {"week", "Last 7 Days"}, "week": {"month", "Last 30 Days"}, "month": {"year", "Last Year"}}

// insightLinkedMissing explains a finding's link that the page cannot open:
// the operator hid the finding, or the range does not reach it.
func insightLinkedMissing(linked, rangeName string, hidden []pages.InsightHiddenFindingView, canShowAgain bool) *pages.InsightLinkedMissingView {
	for _, finding := range hidden {
		if insights.LinkID(finding.FindingID) == linked {
			return &pages.InsightLinkedMissingView{Hidden: &finding, CanShowAgain: canShowAgain}
		}
	}
	missing := &pages.InsightLinkedMissingView{}
	if longer, found := insightsLongerRanges[rangeName]; found {
		missing.Wider, missing.WiderLabel = longer[0], longer[1]
		missing.WiderLink = pages.InsightFindingRoute + linked + "?" + url.Values{"range": []string{longer[0]}}.Encode()
	}
	return missing
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
				clause.Dialog, clause.Link = view.ID, view.Link
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

func (server *Server) insightFindingViews(findings []insights.Finding, given devices.GivenNames, configuration config.Config, rangeName string) []pages.InsightFindingView {
	views := make([]pages.InsightFindingView, 0, len(findings))
	for index, finding := range findings {
		view := pages.InsightFindingView{
			ID: "insight-finding-" + strconv.Itoa(index+1), FindingID: finding.ID, Link: pages.InsightFindingPath(finding.ID, rangeName),
			Kind: finding.Kind, Tone: string(finding.Tone), Icon: insightFindingIcon(finding.Kind),
			Title: finding.Title, Subject: finding.Subject.Label, SubjectMonospace: finding.Subject.Monospace,
			SubjectSource: finding.Subject.LabelSource,
			Summary:       finding.Summary, Explanations: finding.Explanations, Method: finding.Method,
			Destination: finding.Destination, DestinationLabel: finding.DestinationLabel,
			Chart: finding.Chart,
		}
		for _, member := range finding.Members {
			view.Members = append(view.Members, pages.InsightMemberView{ID: finding.MemberID(member), Label: member.Label})
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
		view.DeviceKey, view.DomainsTitle = finding.Subject.Device, finding.DomainsTitle
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
	case devices.KindRemoteAccess:
		return "globe-lock"
	case devices.KindNewApp:
		return "grid-2x2-plus"
	case devices.KindUnusualHours:
		return "clock-alert"
	case devices.KindCheckIn:
		return "timer"
	case devices.KindApplianceDrift:
		return "globe-lock"
	case devices.KindNotUsingSable:
		return "shield-off"
	case devices.KindNetworkOtherDNS:
		return "router"
	case devices.KindLookupsRefused:
		return "shield-x"
	case devices.KindNetworkViaGateway:
		return "arrow-left-right"
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
