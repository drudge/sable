package web

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/querylog"
	zonemodel "github.com/drudge/sable/internal/zone"
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
	}}, nil)
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

func TestDashboardInsightsNamesClientsFromReverseZones(t *testing.T) {
	t.Parallel()

	entries := []querylog.Entry{
		{Event: querylog.Event{ClientIP: "10.0.7.207", Name: "api.example.", RecordType: dns.TypeA, ResponseCode: dns.RcodeSuccess}},
		{Event: querylog.Event{ClientIP: "10.0.7.207", Name: "api.example.", RecordType: dns.TypeA, ResponseCode: dns.RcodeSuccess}},
		{Event: querylog.Event{ClientIP: "10.0.7.42", Name: "api.example.", RecordType: dns.TypeA, ResponseCode: dns.RcodeSuccess}},
		{Event: querylog.Event{ClientIP: "10.0.7.9", Name: "api.example.", RecordType: dns.TypeA, ResponseCode: dns.RcodeSuccess}},
		{Event: querylog.Event{ClientIP: "10.0.9.1", Name: "api.example.", RecordType: dns.TypeA, ResponseCode: dns.RcodeSuccess}},
	}
	zones := []zonemodel.Zone{{
		Name: "7.0.10.in-addr.arpa",
		Records: []zonemodel.Record{
			{Name: "207", Type: "PTR", Value: "roku.default.clients.example.net.", TTL: 300},
			{Name: "42.7.0.10.in-addr.arpa.", Type: "PTR", Value: "xbox.default.clients.example.net.", TTL: 300},
			{Name: "9", Type: "PTR", Value: "retired.default.clients.example.net.", TTL: 300, Disabled: true},
		},
	}}
	view := dashboardInsights(entries, []config.HostOverride{{
		Name: "gateway.example.net", Addresses: []string{"10.0.9.1"}, TTL: 60,
	}}, zones)

	names := make(map[string]string, len(view.TopClients))
	for _, client := range view.TopClients {
		names[client.Name] = client.Secondary
	}
	expected := map[string]string{
		"10.0.7.207": "roku.default.clients.example.net",
		"10.0.7.42":  "xbox.default.clients.example.net",
		"10.0.7.9":   "",
		"10.0.9.1":   "gateway.example.net",
	}
	for address, hostname := range expected {
		if names[address] != hostname {
			t.Fatalf("hostname for %s = %q, want %q", address, names[address], hostname)
		}
	}
}
