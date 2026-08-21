package web

import (
	"net/netip"
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

// dashboardInsightEvents is how far back the rankings, distributions, and
// client count read. The dashboard and its refreshing stat cards share it so
// both describe the same slice of the query log.
const dashboardInsightEvents = 1_000

func dashboardInsights(entries []querylog.Entry, hosts []config.HostOverride, zones []zonemodel.Zone) pages.DashboardInsightsView {
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
	clientNames := dashboardClientNames(clients, hosts, zones)
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
