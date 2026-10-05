package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/web/pages"

	"net/netip"

	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/insights/devices"
	zonemodel "github.com/drudge/sable/internal/zone"
)

// dashboardInsightEvents is how far back the client counter on the stat cards
// reads. The rankings below it no longer sample rows at all; they count the
// selected chart range in the database instead.
const dashboardInsightEvents = 1_000

// dashboardRankLimit is how many ranked entries the dashboard dialog offers.
const dashboardRankLimit = 1_000

// insightWindow is the slice of the query log a set of rankings describes. It
// follows the chart's range picker so a panel and the plot above it always
// answer for the same stretch of time, and so a ranking can hand that same
// window to the query log page instead of sending an operator to a total
// gathered over a different period.
type insightWindow struct {
	Range string
	Start time.Time
	End   time.Time
	Label string
}

func (window insightWindow) loadURL() string {
	values := url.Values{"range": []string{window.Range}}
	if window.Range == "custom" {
		values.Set("start", window.Start.UTC().Format(time.RFC3339Nano))
		values.Set("end", window.End.UTC().Format(time.RFC3339Nano))
	}
	return "/ui/stats/insights?" + values.Encode()
}

func loadingDashboardInsights(window insightWindow) pages.DashboardInsightsView {
	return pages.DashboardInsightsView{
		RangeLabel: window.Label, LogWindowQuery: window.logWindowQuery(),
		PollRange: window.pollRange(), LoadURL: window.loadURL(), Loading: true,
	}
}

// insightPollRanges are the chart ranges whose rankings are cheap enough to
// recount on a timer. A week or more of the query log is aggregated only when
// an operator asks for it, which is what the range picker is for.
var insightPollRanges = map[string]struct{}{"hour": {}, "day": {}}

// pollRange reports the range name the panels may refresh themselves on, or an
// empty string when this window is only ever recounted by a click.
func (window insightWindow) pollRange() string {
	if _, pollable := insightPollRanges[window.Range]; pollable {
		return window.Range
	}
	return ""
}

// chartInsightWindow resolves a chart range name into the window it plots.
func chartInsightWindow(rangeName string, now time.Time) (insightWindow, bool) {
	duration, valid := chartDuration(rangeName)
	if !valid {
		return insightWindow{}, false
	}
	return insightWindow{Range: rangeName, Start: now.Add(-duration), End: now, Label: chartRangeLabel(rangeName)}, true
}

func chartRangeLabel(rangeName string) string {
	switch rangeName {
	case "hour":
		return "Last hour"
	case "day":
		return "Last 24 hours"
	case "week":
		return "Last 7 days"
	case "month":
		return "Last 30 days"
	case "year":
		return "Last year"
	case "custom":
		return "Custom range"
	default:
		return "Selected range"
	}
}

// logWindowQuery is the query string that reproduces this window on the query
// log page. Seconds are kept so the page counts precisely the rows the ranking
// counted, and the exact flag stops a client address from also matching every
// longer address that starts with it.
func (window insightWindow) logWindowQuery() string {
	values := url.Values{}
	if !window.Start.IsZero() {
		values.Set("start", window.Start.UTC().Format(time.RFC3339))
	}
	if !window.End.IsZero() {
		values.Set("end", window.End.UTC().Format(time.RFC3339))
	}
	values.Set("match", "exact")
	return values.Encode()
}

func dashboardInsights(
	insights querylog.Insights,
	window insightWindow,
	given devices.GivenNames,
	hosts []config.HostOverride,
	zones []zonemodel.Zone,
) pages.DashboardInsightsView {
	queryTypes := make(map[string]uint64, len(insights.RecordTypes))
	for recordType, count := range insights.RecordTypes {
		label := dns.TypeToString[recordType]
		if label == "" {
			label = "OTHER"
		}
		queryTypes[label] += count
	}
	sources := make(map[string]uint64, len(insights.Sources))
	for source, count := range insights.Sources {
		sources[dashboardSourceLabel(querylog.Source(source))] += count
	}
	responseCodes := make(map[string]uint64, len(insights.ResponseCodes))
	for responseCode, count := range insights.ResponseCodes {
		label := dns.RcodeToString[responseCode]
		if label == "" {
			label = "Other"
		}
		responseCodes[label] += count
	}
	clientNames := dashboardClientNames(insights.Clients, given, hosts, zones)
	return pages.DashboardInsightsView{
		RangeLabel:      window.Label,
		LogWindowQuery:  window.logWindowQuery(),
		PollRange:       window.pollRange(),
		TopClients:      rankedStats(insights.Clients, clientNames, dashboardRankLimit),
		TopDomains:      rankedStats(insights.Domains, nil, dashboardRankLimit),
		TopBlocked:      rankedStats(insights.Blocked, nil, dashboardRankLimit),
		QueryTypes:      distributionItems(queryTypes, 6),
		ResponseSources: distributionItems(sources, 6),
		ResponseCodes:   distributionItems(responseCodes, 6),
	}
}

// dashboardClientSample counts the distinct clients in a sample of the newest
// query log rows. The stat card it feeds sits with lifetime counters rather
// than with the ranged rankings, so it deliberately keeps its own window.
// dashboardClientCount counts the clients among the newest query log rows.
// Each open dashboard asks on every poll, so the count is shared for a few
// seconds.
func (server *Server) dashboardClientCount(ctx context.Context) (int, error) {
	return server.dashboardClients.get(struct{}{}, time.Now(), dashboardReadCacheTTL, func() (int, error) {
		entries, err := server.queries.RecentQueryEvents(ctx, dashboardInsightEvents)
		if err != nil {
			return 0, err
		}
		return dashboardClientSample(entries), nil
	})
}

func dashboardClientSample(entries []querylog.Entry) int {
	clients := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		clients[entry.ClientIP] = struct{}{}
	}
	return len(clients)
}

// dashboardClientNames labels client addresses in the order Insights names
// devices: the name the operator gave the device, then UniFi's, then a
// configured host override, then a PTR record from a zone this server answers
// for. Whatever is still unnamed is left for nameRankedClients to ask the
// resolver about.
func dashboardClientNames(clients map[string]uint64, given devices.GivenNames, hosts []config.HostOverride, zones []zonemodel.Zone) map[string]string {
	names := make(map[string]string, len(clients))
	for _, host := range hosts {
		for _, address := range host.Addresses {
			names[address] = host.Name
		}
	}
	for address := range clients {
		if name := given.Address(address); name != "" {
			names[address] = name
		}
	}
	if len(zones) == 0 {
		return names
	}
	reverse := newReverseZoneIndex(zones)
	for address := range clients {
		if names[address] != "" {
			continue
		}
		if name, found := reverse.lookup(address); found {
			names[address] = name
		}
	}
	return names
}

// reverseZoneIndex answers PTR lookups from the local zone snapshot. Owners are
// indexed per zone the first time that zone is consulted so a dashboard with a
// hundred clients never rescans one large reverse zone a hundred times.
type reverseZoneIndex struct {
	zones  map[string]*zonemodel.Zone
	owners map[string]map[string]string
	now    time.Time
}

func newReverseZoneIndex(zones []zonemodel.Zone) *reverseZoneIndex {
	index := &reverseZoneIndex{
		zones:  make(map[string]*zonemodel.Zone, len(zones)),
		owners: make(map[string]map[string]string),
		now:    time.Now(),
	}
	for position := range zones {
		name := normalizeZoneName(zones[position].Name)
		if name == "" {
			continue
		}
		if _, taken := index.zones[name]; taken {
			continue
		}
		index.zones[name] = &zones[position]
	}
	return index
}

// lookup returns the PTR target for an address. The deepest zone covering the
// reverse name is the authoritative one, so a hit there settles the question
// even when it holds no PTR for this address.
func (index *reverseZoneIndex) lookup(address string) (string, bool) {
	parsed, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return "", false
	}
	reverseName, err := dnsname.ReverseName(parsed.WithZone(""))
	if err != nil {
		return "", false
	}
	for candidate := reverseName; candidate != ""; {
		if _, known := index.zones[candidate]; known {
			target, found := index.ownersOf(candidate)[reverseName]
			return target, found
		}
		_, rest, cut := strings.Cut(candidate, ".")
		if !cut {
			return "", false
		}
		candidate = rest
	}
	return "", false
}

func (index *reverseZoneIndex) ownersOf(zoneName string) map[string]string {
	if owners, built := index.owners[zoneName]; built {
		return owners
	}
	owners := make(map[string]string)
	for _, record := range index.zones[zoneName].Records {
		if !strings.EqualFold(record.Type, "PTR") {
			continue
		}
		if record.Disabled || (!record.ExpiresAt.IsZero() && !record.ExpiresAt.After(index.now)) {
			continue
		}
		target := normalizeZoneName(record.Value)
		if target == "" {
			continue
		}
		owner := reverseRecordOwner(zoneName, record.Name)
		if _, taken := owners[owner]; taken {
			continue
		}
		owners[owner] = target
	}
	index.owners[zoneName] = owners
	return owners
}

// reverseRecordOwner expands a stored owner into the full reverse name. Records
// are usually written relative to their zone, but an imported zone file may
// carry fully qualified owners instead.
func reverseRecordOwner(zoneName, recordName string) string {
	recordName = strings.TrimSpace(recordName)
	if recordName == "" || recordName == "@" {
		return zoneName
	}
	if strings.HasSuffix(recordName, ".") {
		return normalizeZoneName(recordName)
	}
	return normalizeZoneName(recordName) + "." + zoneName
}

func dashboardSourceLabel(source querylog.Source) string {
	switch source {
	case querylog.SourceCache:
		return "Cached"
	case querylog.SourceUpstream:
		return "Upstream"
	case querylog.SourceLocal:
		return "Local"
	case querylog.SourceAuthoritative:
		return "Authoritative"
	case querylog.SourceBlocked:
		return "Blocked"
	case querylog.SourceError:
		return "Error"
	default:
		return "Other"
	}
}

func rankedStats(counts map[string]uint64, secondary map[string]string, limit int) []pages.RankedStatView {
	items := make([]pages.RankedStatView, 0, len(counts))
	for name, value := range counts {
		if name == "" {
			name = "unknown"
		}
		items = append(items, pages.RankedStatView{Name: name, Secondary: secondary[name], Value: value})
	}
	slices.SortFunc(items, func(left, right pages.RankedStatView) int {
		if left.Value != right.Value {
			if left.Value > right.Value {
				return -1
			}
			return 1
		}
		return strings.Compare(left.Name, right.Name)
	})
	return items[:min(len(items), limit)]
}

func distributionItems(counts map[string]uint64, limit int) []pages.DistributionItemView {
	total := uint64(0)
	for _, count := range counts {
		total += count
	}
	ranked := rankedStats(counts, nil, limit)
	items := make([]pages.DistributionItemView, 0, len(ranked))
	offset := 0.0
	for index, item := range ranked {
		percentage := 0.0
		if total != 0 {
			percentage = float64(item.Value) * 100 / float64(total)
		}
		items = append(items, pages.DistributionItemView{
			Name: item.Name, Value: item.Value, Percent: percentage, Offset: -offset, Color: index % 7,
		})
		offset += percentage
	}
	return items
}

func (server *Server) dashboard(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	if err := pages.Dashboard(server.dashboardView(request)).Render(request.Context(), writer); err != nil {
		server.logger.Error("render dashboard", "error", err)
	}
}

func (server *Server) dashboardView(request *http.Request) pages.DashboardView {
	view := server.consoleView(request)
	view.StatsScope = dashboardStatsScope(request)
	now := time.Now()
	selected := dashboardChartRangeFromRequest(request)
	if selected.Name == "custom" {
		view.Chart = server.history.customView(request.Context(), selected.Start, selected.End, server.stats.Stats(), view.TimeDisplay)
	} else {
		view.Chart = server.history.view(request.Context(), selected.Name, now, server.stats.Stats(), view.TimeDisplay)
	}
	if !view.CanLogs {
		return view
	}
	if clients, err := server.dashboardClientCount(request.Context()); err != nil {
		server.logger.Warn("count dashboard clients", "error", err)
	} else {
		view.Stats.Clients = clients
	}
	view.Stats.Dropped = server.queryLog.Stats().Dropped
	// The rankings open on whatever range the chart opens on, so the panels and
	// the plot above them always answer for the same window.
	if selected.Name == "custom" {
		view.Insights = loadingDashboardInsights(insightWindow{
			Range: "custom", Start: selected.Start, End: selected.End, Label: chartRangeLabel("custom"),
		})
	} else if window, valid := chartInsightWindow(view.Chart.ActiveRange, now); valid {
		view.Insights = loadingDashboardInsights(window)
	}
	return view
}

// queryInsightReader is the optional query log capability the rankings need.
// A store that cannot aggregate simply leaves the panels empty rather than
// falling back to a sample whose totals nothing else on the page agrees with.
type queryInsightReader interface {
	QueryLogInsights(context.Context, time.Time, time.Time) (querylog.Insights, error)
}

func (server *Server) dashboardInsightsView(request *http.Request, window insightWindow) pages.DashboardInsightsView {
	reader, ok := server.queries.(queryInsightReader)
	if !ok {
		return pages.DashboardInsightsView{RangeLabel: window.Label, LogWindowQuery: window.logWindowQuery(), PollRange: window.pollRange()}
	}
	insights, countedWindow, err := server.insightCache.load(request.Context(), window, reader.QueryLogInsights)
	if err != nil {
		server.logger.Warn("build dashboard insights", "error", err)
		return pages.DashboardInsightsView{RangeLabel: window.Label, LogWindowQuery: window.logWindowQuery(), PollRange: window.pollRange()}
	}
	view := dashboardInsights(
		insights,
		countedWindow,
		server.givenClientNames(request.Context(), countedWindow.Start),
		server.config.Current().Config.Resolver.Hosts,
		server.zones.Current().Zones,
	)
	// Whatever the given names, host overrides, and local zones could not name
	// is asked of the resolver, which is the only path that sees a reverse
	// zone this server merely forwards.
	server.nameRankedClients(view.TopClients)
	return view
}

func (server *Server) runtimeStats(writer http.ResponseWriter, request *http.Request) {
	view := server.lifetimeStatsView(request)
	now := time.Now()
	chart := server.history.view(request.Context(), "hour", now, server.stats.Stats(), requestTimeDisplay(request))
	scope := dashboardStatsScope(request)
	values := view
	if scope == pages.StatsScopeRange {
		values = chart.Stats
	}
	window, _ := chartInsightWindow(chart.ActiveRange, now)
	overview := pages.StatsOverviewView{
		Values: values, Lifetime: view, Scope: scope,
		RangeName: chart.ActiveRange, RangeLabel: chart.RangeLabel,
		CustomStart: chart.CustomStart, CustomEnd: chart.CustomEnd,
		CanLogs: server.canReadLogs(request), LogWindowQuery: window.logWindowQuery(),
	}
	if err := pages.Stats(overview).Render(request.Context(), writer); err != nil {
		server.logger.Error("render runtime statistics", "error", err)
	}
}

func (server *Server) lifetimeStatsView(request *http.Request) pages.StatsView {
	view := statsView(server.history.totals(time.Now(), server.stats.Stats()))
	// The client and dropped counts come from the query log rather than the
	// resolver counters, so the refreshed cards have to repeat the read the
	// dashboard performs or those two would drop to zero every poll.
	if server.canReadLogs(request) {
		view.Dropped = server.queryLog.Stats().Dropped
		if clients, err := server.dashboardClientCount(request.Context()); err != nil {
			server.logger.Warn("count dashboard clients", "error", err)
		} else {
			view.Clients = clients
		}
	}
	return view
}

func (server *Server) queryStatistics(writer http.ResponseWriter, request *http.Request) {
	server.rememberDashboardStatsScope(writer, request)
	rangeName := request.URL.Query().Get("range")
	display := requestTimeDisplay(request)
	location := display.Location
	if location == nil {
		location = time.Local
	}
	// The rankings are recounted only when a range control asked for the
	// chart, never on the ten-second refresh: aggregating a week of the query
	// log is worth doing on a click and wasteful on a poll.
	withInsights := request.URL.Query().Get("insights") == "1" && server.canReadLogs(request)
	if rangeName == "custom" {
		start, startErr := time.ParseInLocation("2006-01-02T15:04", request.URL.Query().Get("start"), location)
		end, endErr := time.ParseInLocation("2006-01-02T15:04", request.URL.Query().Get("end"), location)
		if startErr != nil || endErr != nil || !start.Before(end) {
			http.Error(writer, "custom range must contain valid start and end times", http.StatusBadRequest)
			return
		}
		server.rememberDashboardChartRange(writer, request, dashboardChartRange{Name: "custom", Start: start, End: end})
		view := server.history.customView(request.Context(), start, end, server.stats.Stats(), display)
		if err := pages.QueryChart(view).Render(request.Context(), writer); err != nil {
			server.logger.Error("render custom query statistics", "error", err)
			return
		}
		window := insightWindow{Range: "custom", Start: start, End: end, Label: chartRangeLabel("custom")}
		server.renderChartStats(writer, request, view, window.logWindowQuery())
		if withInsights {
			server.renderInsights(writer, request, window)
		}
		return
	}
	if _, valid := chartDuration(rangeName); !valid {
		http.Error(writer, "range must be hour, day, week, month, or year", http.StatusBadRequest)
		return
	}
	server.rememberDashboardChartRange(writer, request, dashboardChartRange{Name: rangeName})
	now := time.Now()
	view := server.history.view(request.Context(), rangeName, now, server.stats.Stats(), display)
	if err := pages.QueryChart(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render query statistics", "error", err)
		return
	}
	window, valid := chartInsightWindow(rangeName, now)
	server.renderChartStats(writer, request, view, window.logWindowQuery())
	if valid && withInsights {
		server.renderInsights(writer, request, window)
	}
}

// renderChartStats updates the headline metrics alongside an htmx chart swap.
// The chart remains the regular response target; this sibling is applied out
// of band so every range control changes the whole dashboard consistently.
func (server *Server) renderChartStats(writer http.ResponseWriter, request *http.Request, view pages.QueryChartView, logWindowQuery string) {
	lifetime := server.lifetimeStatsView(request)
	scope := dashboardStatsScope(request)
	values := lifetime
	if scope == pages.StatsScopeRange {
		values = view.Stats
	}
	overview := pages.StatsOverviewView{
		Values: values, Lifetime: lifetime, Scope: scope,
		RangeName: view.ActiveRange, RangeLabel: view.RangeLabel,
		CustomStart: view.CustomStart, CustomEnd: view.CustomEnd,
		CanLogs: server.canReadLogs(request), LogWindowQuery: logWindowQuery,
		OutOfBand: true,
	}
	if err := pages.Stats(overview).Render(request.Context(), writer); err != nil {
		server.logger.Error("render chart statistics overview", "error", err)
	}
}

// dashboardInsightsPanel loads rankings independently from the initial page.
// Short ranges continue polling; wider and custom ranges use the same endpoint
// once after the operator selects them.
func (server *Server) dashboardInsightsPanel(writer http.ResponseWriter, request *http.Request) {
	window, valid := requestedInsightWindow(request)
	if !valid {
		http.Error(writer, "range must be hour, day, week, month, year, or a valid custom window", http.StatusBadRequest)
		return
	}
	if !server.canReadLogs(request) {
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}
	view := server.dashboardInsightsView(request, window)
	if err := pages.DashboardInsights(view, false).Render(request.Context(), writer); err != nil {
		server.logger.Error("render dashboard insights", "error", err)
	}
}

// renderInsights appends the rankings as an out-of-band swap so one range click
// updates the chart and the panels below it together.
func (server *Server) renderInsights(writer http.ResponseWriter, request *http.Request, window insightWindow) {
	insights := loadingDashboardInsights(window)
	if err := pages.DashboardInsights(insights, true).Render(request.Context(), writer); err != nil {
		server.logger.Error("render dashboard insights", "error", err)
	}
}

func requestedInsightWindow(request *http.Request) (insightWindow, bool) {
	rangeName := request.URL.Query().Get("range")
	if rangeName != "custom" {
		return chartInsightWindow(rangeName, time.Now())
	}
	start, startErr := time.Parse(time.RFC3339Nano, request.URL.Query().Get("start"))
	end, endErr := time.Parse(time.RFC3339Nano, request.URL.Query().Get("end"))
	if startErr != nil || endErr != nil || !start.Before(end) {
		return insightWindow{}, false
	}
	return insightWindow{Range: "custom", Start: start, End: end, Label: chartRangeLabel("custom")}, true
}

func statsView(stats dnsserver.Stats) pages.StatsView {
	return pages.StatsView{
		Queries:              stats.Queries,
		NoError:              stats.NoError,
		ServerFailures:       stats.ServerFailures,
		NXDomain:             stats.NXDomain,
		Refused:              stats.Refused,
		Recursive:            stats.CacheHits + stats.CacheMisses,
		Blocked:              stats.Blocked,
		Failures:             stats.Failures,
		UpstreamErrors:       stats.UpstreamErrors,
		CacheHits:            stats.CacheHits,
		CacheMisses:          stats.CacheMisses,
		CacheEntries:         stats.CacheEntries,
		CacheHitRatio:        cacheHitRatio(stats.CacheHits, stats.CacheMisses),
		RoutedQueries:        stats.RoutedQueries,
		LocalAnswers:         stats.LocalAnswers,
		AuthoritativeAnswers: stats.AuthoritativeAnswers,
		DNSSECSecure:         stats.DNSSECSecure,
		DNSSECInsecure:       stats.DNSSECInsecure,
		DNSSECBogus:          stats.DNSSECBogus,
		LocalHosts:           stats.LocalHosts,
		BlockedDomains:       stats.BlockedDomains,
		BlockLists:           stats.BlockLists,
		Uptime:               time.Since(stats.StartedAt).Round(time.Second).String(),
	}
}

func cacheHitRatio(hits, misses uint64) string {
	total := hits + misses
	if total == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", float64(hits)*100/float64(total))
}
