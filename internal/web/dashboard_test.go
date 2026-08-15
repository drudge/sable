package web

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/querylog"
)

func TestDashboardInsightsRanksPersistedQuerySample(t *testing.T) {
	t.Parallel()

	entries := []querylog.Entry{
		{Event: querylog.Event{ClientIP: "192.0.2.10", Name: "api.example.", RecordType: dns.TypeA, ResponseCode: dns.RcodeSuccess, Source: querylog.SourceCache}},
		{Event: querylog.Event{ClientIP: "192.0.2.10", Name: "api.example.", RecordType: dns.TypeAAAA, ResponseCode: dns.RcodeSuccess, Source: querylog.SourceUpstream}},
		{Event: querylog.Event{ClientIP: "192.0.2.20", Name: "ads.example.", RecordType: dns.TypeA, ResponseCode: dns.RcodeNameError, Source: querylog.SourceBlocked}},
	}
	view := dashboardInsights(entries, []config.HostOverride{{
		Name: "laptop.home.arpa", Addresses: []string{"192.0.2.10"}, TTL: 60,
	}})
	if view.Clients != 2 || len(view.TopClients) != 2 {
		t.Fatalf("client insights = %+v", view)
	}
	if view.TopClients[0].Name != "192.0.2.10" || view.TopClients[0].Secondary != "laptop.home.arpa" || view.TopClients[0].Value != 2 {
		t.Fatalf("top client = %+v", view.TopClients[0])
	}
	if view.TopDomains[0].Name != "api.example" || view.TopDomains[0].Value != 2 {
		t.Fatalf("top domain = %+v", view.TopDomains[0])
	}
	if len(view.TopBlocked) != 1 || view.TopBlocked[0].Name != "ads.example" {
		t.Fatalf("top blocked domains = %+v", view.TopBlocked)
	}
	if len(view.QueryTypes) != 2 || len(view.ResponseSources) != 3 || len(view.ResponseCodes) != 2 {
		t.Fatalf("distributions = query %+v source %+v code %+v", view.QueryTypes, view.ResponseSources, view.ResponseCodes)
	}
}
