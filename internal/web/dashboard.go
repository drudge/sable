package web

import (
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/web/pages"
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
	Start time.Time
	End   time.Time
	Label string
}

// chartInsightWindow resolves a chart range name into the window it plots.
func chartInsightWindow(rangeName string, now time.Time) (insightWindow, bool) {
	duration, valid := chartDuration(rangeName)
	if !valid {
		return insightWindow{}, false
	}
	return insightWindow{Start: now.Add(-duration), End: now, Label: chartRangeLabel(rangeName)}, true
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
	clientNames := dashboardClientNames(insights.Clients, hosts, zones)
	return pages.DashboardInsightsView{
		RangeLabel:      window.Label,
		LogWindowQuery:  window.logWindowQuery(),
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
func dashboardClientSample(entries []querylog.Entry) int {
	clients := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		clients[entry.ClientIP] = struct{}{}
	}
	return len(clients)
}

// dashboardClientNames labels the client addresses in the query sample. A
// configured host override wins because an operator wrote it by hand; every
// other address falls back to a PTR record from a zone this server answers
// for, which is where the UniFi synchronizer publishes DHCP client names.
func dashboardClientNames(clients map[string]uint64, hosts []config.HostOverride, zones []zonemodel.Zone) map[string]string {
	names := make(map[string]string, len(clients))
	for _, host := range hosts {
		for _, address := range host.Addresses {
			names[address] = host.Name
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
