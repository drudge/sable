package web

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/querylog"
	zonemodel "github.com/drudge/sable/internal/zone"
)

func TestDashboardInsightCacheSharesConcurrentExactRange(t *testing.T) {
	t.Parallel()
	var cache dashboardInsightCache
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	loader := func(context.Context, time.Time, time.Time) (querylog.Insights, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return querylog.Insights{Clients: map[string]uint64{"192.0.2.1": 7}}, nil
	}
	window := insightWindow{Range: "hour", Start: time.Now().Add(-time.Hour), End: time.Now(), Label: "Last hour"}
	const readers = 12
	var group sync.WaitGroup
	group.Add(readers)
	for range readers {
		go func() {
			defer group.Done()
			insights, counted, err := cache.load(context.Background(), window, loader)
			if err != nil {
				t.Errorf("load() error = %v", err)
				return
			}
			if insights.Clients["192.0.2.1"] != 7 || counted != window {
				t.Errorf("load() = %+v, %+v", insights, counted)
			}
		}()
	}
	<-entered
	close(release)
	group.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("aggregation calls = %d, want 1", got)
	}
}

func TestDashboardInsightCacheKeepsTheWindowThatWasCounted(t *testing.T) {
	t.Parallel()
	var cache dashboardInsightCache
	var calls atomic.Int32
	loader := func(context.Context, time.Time, time.Time) (querylog.Insights, error) {
		calls.Add(1)
		return querylog.Insights{}, nil
	}
	first := insightWindow{Range: "day", Start: time.Now().Add(-24 * time.Hour), End: time.Now(), Label: "Last 24 hours"}
	if _, counted, err := cache.load(context.Background(), first, loader); err != nil || counted != first {
		t.Fatalf("first load = %+v, %v", counted, err)
	}
	second := insightWindow{Range: "day", Start: first.Start.Add(time.Second), End: first.End.Add(time.Second), Label: first.Label}
	if _, counted, err := cache.load(context.Background(), second, loader); err != nil || counted != first {
		t.Fatalf("cached load = %+v, %v; want first window %+v", counted, err, first)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("aggregation calls = %d, want 1", got)
	}
}

func TestDashboardInsightCacheSerializesDifferentRanges(t *testing.T) {
	t.Parallel()
	var cache dashboardInsightCache
	var active atomic.Int32
	var maximum atomic.Int32
	loader := func(context.Context, time.Time, time.Time) (querylog.Insights, error) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		active.Add(-1)
		return querylog.Insights{}, nil
	}
	windows := []insightWindow{
		{Range: "hour", Start: time.Now().Add(-time.Hour), End: time.Now()},
		{Range: "day", Start: time.Now().Add(-24 * time.Hour), End: time.Now()},
	}
	var group sync.WaitGroup
	for _, window := range windows {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, _, err := cache.load(context.Background(), window, loader); err != nil {
				t.Errorf("load() error = %v", err)
			}
		}()
	}
	group.Wait()
	if got := maximum.Load(); got != 1 {
		t.Fatalf("concurrent aggregations = %d, want 1", got)
	}
}

// insightsFrom aggregates entries the way the store's GROUP BY does, so these
// tests can keep describing the query log as rows.
func insightsFrom(entries []querylog.Entry) querylog.Insights {
	insights := querylog.Insights{
		Clients:       map[string]uint64{},
		Domains:       map[string]uint64{},
		Blocked:       map[string]uint64{},
		RecordTypes:   map[uint16]uint64{},
		Sources:       map[string]uint64{},
		ResponseCodes: map[int]uint64{},
	}
	for _, entry := range entries {
		name := strings.TrimSuffix(strings.ToLower(entry.Name), ".")
		insights.Clients[entry.ClientIP]++
		insights.Domains[name]++
		if entry.Source == querylog.SourceBlocked {
			insights.Blocked[name]++
		}
		insights.RecordTypes[entry.RecordType]++
		insights.Sources[string(entry.Source)]++
		insights.ResponseCodes[entry.ResponseCode]++
	}
	return insights
}

func TestDashboardInsightsRanksPersistedQuerySample(t *testing.T) {
	t.Parallel()

	entries := []querylog.Entry{
		{Event: querylog.Event{ClientIP: "192.0.2.10", Name: "api.example.", RecordType: dns.TypeA, ResponseCode: dns.RcodeSuccess, Source: querylog.SourceCache}},
		{Event: querylog.Event{ClientIP: "192.0.2.10", Name: "api.example.", RecordType: dns.TypeAAAA, ResponseCode: dns.RcodeSuccess, Source: querylog.SourceUpstream}},
		{Event: querylog.Event{ClientIP: "192.0.2.20", Name: "ads.example.", RecordType: dns.TypeA, ResponseCode: dns.RcodeNameError, Source: querylog.SourceBlocked}},
	}
	window := insightWindow{Label: "Last hour"}
	view := dashboardInsights(insightsFrom(entries), window, []config.HostOverride{{
		Name: "laptop.home.arpa", Addresses: []string{"192.0.2.10"}, TTL: 60,
	}}, nil)
	if dashboardClientSample(entries) != 2 || len(view.TopClients) != 2 {
		t.Fatalf("client insights = %+v", view)
	}
	if view.RangeLabel != "Last hour" {
		t.Fatalf("range label = %q", view.RangeLabel)
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
	view := dashboardInsights(insightsFrom(entries), insightWindow{}, []config.HostOverride{{
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
