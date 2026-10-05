package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/web/pages"
)

func (server *Server) cachePage(writer http.ResponseWriter, request *http.Request) {
	view := server.consoleView(request)
	server.render(writer, request, pages.CachePage(server.cacheView(request.Context(), view, "")))
}

func (server *Server) cacheStatus(writer http.ResponseWriter, request *http.Request) {
	view := server.consoleView(request)
	server.render(writer, request, pages.CacheContent(server.cacheView(request.Context(), view, "")))
}

func (server *Server) flushCache(writer http.ResponseWriter, request *http.Request) {
	removed := server.stats.PurgeCache()
	view := server.consoleView(request)
	message := fmt.Sprintf("Cleared %d cached DNS records", removed)
	server.render(writer, request, pages.CacheContent(server.cacheView(request.Context(), view, message)))
}

func (server *Server) cacheView(ctx context.Context, console pages.DashboardView, message string) pages.CachePageView {
	stats := server.stats.Stats()
	domains := cachedDomainViews(server.stats.CachedResponses())
	return pages.CachePageView{
		Console:      console,
		Entries:      stats.CacheEntries,
		HitsLastHour: server.history.cacheHitsSince(ctx, time.Hour, time.Now(), stats),
		Domains:      domains,
		Message:      message,
	}
}

func cachedDomainViews(responses []dnsserver.CachedResponse) []pages.CacheDomainView {
	domains := make([]pages.CacheDomainView, 0, len(responses))
	for _, response := range responses {
		name := strings.TrimSuffix(response.Name, ".")
		if len(domains) == 0 || domains[len(domains)-1].Name != name {
			domains = append(domains, pages.CacheDomainView{Name: name})
		}
		domain := &domains[len(domains)-1]
		domain.Responses++
		domain.Records += len(response.Records)
		item := pages.CacheResponseView{
			RecordType: response.RecordType, RemainingTTL: response.RemainingTTL,
			Records: make([]pages.CacheRecordView, 0, len(response.Records)),
		}
		for _, record := range response.Records {
			item.Records = append(item.Records, pages.CacheRecordView{
				Section: record.Section, Value: record.Value, TTL: record.TTL,
			})
		}
		domain.Items = append(domain.Items, item)
		if domain.MinimumTTL == 0 || response.RemainingTTL < domain.MinimumTTL {
			domain.MinimumTTL = response.RemainingTTL
		}
	}
	return domains
}

func (server *Server) purgeCache(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, struct {
		Removed int `json:"removed"`
	}{Removed: server.stats.PurgeCache()})
}

func (server *Server) purgeCacheUI(writer http.ResponseWriter, request *http.Request) {
	removed := server.stats.PurgeCache()
	server.render(writer, request, pages.ActionResult(fmt.Sprintf("Purged %d cache entries", removed), false))
}
