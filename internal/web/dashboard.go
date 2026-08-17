package web

import (
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/web/pages"
)

// dashboardInsightEvents is how far back the rankings, distributions, and
// client count read. The dashboard and its refreshing stat cards share it so
// both describe the same slice of the query log.
const dashboardInsightEvents = 1_000

func dashboardInsights(entries []querylog.Entry, hosts []config.HostOverride) pages.DashboardInsightsView {
	clientNames := make(map[string]string)
	for _, host := range hosts {
		for _, address := range host.Addresses {
			clientNames[address] = host.Name
		}
	}
	clients := make(map[string]uint64)
	domains := make(map[string]uint64)
	blocked := make(map[string]uint64)
	queryTypes := make(map[string]uint64)
	sources := make(map[string]uint64)
	responseCodes := make(map[string]uint64)
	for _, entry := range entries {
		clients[entry.ClientIP]++
		name := strings.TrimSuffix(strings.ToLower(entry.Name), ".")
		domains[name]++
		if entry.Source == querylog.SourceBlocked {
			blocked[name]++
		}
		recordType := dns.TypeToString[entry.RecordType]
		if recordType == "" {
			recordType = "OTHER"
		}
		queryTypes[recordType]++
		sources[dashboardSourceLabel(entry.Source)]++
		responseCode := dns.RcodeToString[entry.ResponseCode]
		if responseCode == "" {
			responseCode = "Other"
		}
		responseCodes[responseCode]++
	}
	return pages.DashboardInsightsView{
		Clients:         len(clients),
		TopClients:      rankedStats(clients, clientNames, 1_000),
		TopDomains:      rankedStats(domains, nil, 1_000),
		TopBlocked:      rankedStats(blocked, nil, 1_000),
		QueryTypes:      distributionItems(queryTypes, 6),
		ResponseSources: distributionItems(sources, 6),
		ResponseCodes:   distributionItems(responseCodes, 6),
	}
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
