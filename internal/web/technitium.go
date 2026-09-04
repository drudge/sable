package web

import (
	"net/http"
	"time"

	"github.com/drudge/sable/internal/store"
)

const (
	technitiumStatsPath      = "/api/dashboard/stats/get"
	technitiumStatsHours     = 24
	technitiumTopDomainLimit = 5
)

// This is the subset of Technitium's dashboard response consumed by Glance's
// dns-stats widget: https://github.com/glanceapp/glance/blob/main/internal/glance/widget-dns-stats.go.
type technitiumStatsResponse struct {
	Status   string                  `json:"status"`
	Response technitiumDashboardData `json:"response"`
}

type technitiumDashboardData struct {
	Stats struct {
		TotalQueries   uint64 `json:"totalQueries"`
		TotalBlocked   uint64 `json:"totalBlocked"`
		BlockedZones   int    `json:"blockedZones"`
		BlockListZones int    `json:"blockListZones"`
	} `json:"stats"`
	MainChartData struct {
		Labels   []string           `json:"labels"`
		Datasets []technitiumSeries `json:"datasets"`
	} `json:"mainChartData"`
	TopBlockedDomains []technitiumDomain `json:"topBlockedDomains"`
}

type technitiumSeries struct {
	Label string   `json:"label"`
	Data  []uint64 `json:"data"`
}

type technitiumDomain struct {
	Name string `json:"name"`
	Hits uint64 `json:"hits"`
}

func (server *Server) technitiumStats(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if rangeType := request.URL.Query().Get("type"); rangeType != "LastDay" {
		writeTechnitiumError(writer, http.StatusBadRequest, "only type=LastDay is supported")
		return
	}
	now := time.Now()
	stats := server.stats.Stats()
	server.history.record(now, stats)
	// Counters are stored by minute. Include the current minute and keep the
	// rankings and all 24 hourly slots on that same window.
	end := now.UTC().Truncate(statsBucketInterval).Add(statsBucketInterval)
	start := end.Add(-technitiumStatsHours * time.Hour)
	buckets, err := server.history.readBuckets(request.Context(), start, end, statsBucketInterval)
	if err != nil {
		server.logger.Warn("read Technitium dashboard statistics", "error", err)
		writeTechnitiumError(writer, http.StatusServiceUnavailable, "statistics are unavailable")
		return
	}
	data := technitiumDashboard(buckets, start, stats.BlockedDomains)
	if reader, ok := server.queries.(queryInsightReader); ok && server.canReadLogs(request) {
		window := insightWindow{Range: "custom", Start: start, End: end}
		insights, _, err := server.insightCache.load(request.Context(), window, reader.QueryLogInsights)
		if err != nil {
			server.logger.Warn("read Technitium blocked domains", "error", err)
			writeTechnitiumError(writer, http.StatusServiceUnavailable, "blocked domain statistics are unavailable")
			return
		}
		for _, domain := range rankedStats(insights.Blocked, nil, technitiumTopDomainLimit) {
			data.TopBlockedDomains = append(data.TopBlockedDomains, technitiumDomain{Name: domain.Name, Hits: domain.Value})
		}
	}
	writeJSON(writer, http.StatusOK, technitiumStatsResponse{Status: "ok", Response: data})
}

func technitiumDashboard(buckets []store.QueryStatsBucket, start time.Time, blockedDomains int) technitiumDashboardData {
	var data technitiumDashboardData
	// Sable's compiled domain count already deduplicates manual and list entries;
	// Glance adds these two fields, so report the combined count only once.
	data.Stats.BlockListZones = blockedDomains
	data.TopBlockedDomains = []technitiumDomain{}
	data.MainChartData.Labels = make([]string, technitiumStatsHours)
	total := technitiumSeries{Label: "Total", Data: make([]uint64, technitiumStatsHours)}
	blocked := technitiumSeries{Label: "Blocked", Data: make([]uint64, technitiumStatsHours)}
	for hour := range technitiumStatsHours {
		data.MainChartData.Labels[hour] = start.Add(time.Duration(hour) * time.Hour).Format(time.RFC3339)
	}
	for _, bucket := range buckets {
		elapsed := bucket.Start.Sub(start)
		if elapsed < 0 || elapsed >= technitiumStatsHours*time.Hour {
			continue
		}
		hour := int(elapsed / time.Hour)
		total.Data[hour] += bucket.Queries
		blocked.Data[hour] += bucket.Blocked
		data.Stats.TotalQueries += bucket.Queries
		data.Stats.TotalBlocked += bucket.Blocked
	}
	data.MainChartData.Datasets = []technitiumSeries{total, blocked}
	return data
}

func writeTechnitiumError(writer http.ResponseWriter, status int, message string) {
	result := "error"
	if status == http.StatusUnauthorized {
		result = "invalid-token"
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, status, map[string]string{"status": result, "errorMessage": message})
}
