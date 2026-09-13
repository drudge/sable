package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/web/pages"
)

type catalogImportStats struct {
	conversionTestStats
	members     []dnsserver.ZoneRecord
	signed      bool
	transferred []dnsserver.ZoneRecord
}

func (s *catalogImportStats) FetchZone(_ context.Context, name, kind string, _ []string, _, _ string) ([]dnsserver.ZoneRecord, error) {
	s.calls++
	if kind == "catalog" {
		return s.members, nil
	}
	if name == "bad.test" {
		return nil, errors.New("transfer refused")
	}
	if s.transferred != nil {
		return s.transferred, nil
	}
	records := []dnsserver.ZoneRecord{
		{Name: "@", Type: "SOA", TTL: 300, Value: "ns." + name + ". hostmaster." + name + ". 1 60 10 600 300"},
		{Name: "@", Type: "NS", TTL: 300, Value: "ns." + name + "."},
	}
	if s.signed {
		records = append(records, dnsserver.ZoneRecord{Name: "@", Type: "NSEC", TTL: 300, Value: "next." + name + ". A NS SOA"})
	}
	return records, nil
}
func catalogImportFixture(t *testing.T) (*Server, *editableTestConfiguration, *catalogImportStats) {
	server, configuration := newConversionServer(t, &conversionTestStats{})
	stats := &catalogImportStats{members: []dnsserver.ZoneRecord{
		{Name: "version", Type: "TXT", TTL: 300, Value: `"2"`},
		{Name: "a.zones", Type: "PTR", TTL: 300, Value: "good.test."},
		{Name: "b.zones", Type: "PTR", TTL: 300, Value: "bad.test."},
	}}
	server.stats = stats
	return server, configuration, stats
}
func catalogImportForm() url.Values {
	return url.Values{"catalog": {"catalog.test"}, "primary_servers": {"192.0.2.53:53"}, "primary_protocol": {"tcp"}}
}
func prepareImport(server *Server, form url.Values) (pages.CatalogImportView, error) {
	request := httptest.NewRequest("POST", "/ui/zones/import-catalog", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = request.ParseForm()
	view := pages.CatalogImportView{Catalog: form.Get("catalog"), Source: form.Get("primary_servers"), Protocol: form.Get("primary_protocol")}
	err := server.prepareCatalogImport(request, &view)
	return view, err
}
func TestCatalogImportDiscoveryAndPartialStaging(t *testing.T) {
	server, configuration, stats := catalogImportFixture(t)
	form := catalogImportForm()
	review, err := prepareImport(server, form)
	if err != nil || len(review.Members) != 2 || len(configuration.zoneSnapshot.Zones) != 1 || stats.calls != 1 {
		t.Fatalf("discovery: %+v %v", review, err)
	}
	form.Set("step", "stage")
	form.Set("confirmation", review.Confirmation)
	form["member"] = []string{"bad.test", "good.test"}
	result, err := prepareImport(server, form)
	if err != nil || len(result.Results) != 2 || result.Results[0].Success || !result.Results[1].Success {
		t.Fatalf("results: %+v %v", result, err)
	}
	current := findZone(configuration.zoneSnapshot.Zones, "good.test")
	if current == nil || current.Type != "secondary" || current.CatalogZone != "" || current.CatalogMemberID != "" || len(current.Records) != 2 {
		t.Fatalf("not independent: %+v", current)
	}
	repeated, err := prepareImport(server, form)
	if err != nil || repeated.Results[1].Success || len(configuration.zoneSnapshot.Zones) != 2 {
		t.Fatalf("repeated import: %+v %v", repeated, err)
	}
}
func TestCatalogImportRejectsUnreviewedSelections(t *testing.T) {
	for _, mode := range []string{"stale", "nonmember", "empty", "source changed"} {
		t.Run(mode, func(t *testing.T) {
			server, configuration, _ := catalogImportFixture(t)
			form := catalogImportForm()
			review, err := prepareImport(server, form)
			if err != nil {
				t.Fatal(err)
			}
			form.Set("step", "stage")
			form.Set("confirmation", review.Confirmation)
			form.Set("member", "good.test")
			switch mode {
			case "stale":
				form.Set("confirmation", "old")
			case "nonmember":
				form.Set("member", "other.test")
			case "empty":
				form.Del("member")
			case "source changed":
				form.Set("primary_servers", "192.0.2.54:53")
			}
			if _, err := prepareImport(server, form); err == nil || len(configuration.zoneSnapshot.Zones) != 1 {
				t.Fatal("invalid selection mutated zones")
			}
		})
	}
}
func TestCatalogImportRequiresCreatePermission(t *testing.T) {
	server, _, stats := catalogImportFixture(t)
	server.securityEnabled = true
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		response := httptest.NewRecorder()
		server.importCatalog(response, httptest.NewRequest(method, "/zones/import-catalog", nil))
		if response.Code != http.StatusForbidden || stats.calls != 0 {
			t.Fatal("unauthorized discovery permitted")
		}
	}
}

func TestCatalogImportAuditAndReplicaProtection(t *testing.T) {
	server, configuration, stats := catalogImportFixture(t)
	audit := &conversionAuditLog{}
	server.queries = audit
	form := catalogImportForm()
	review, err := prepareImport(server, form)
	if err != nil {
		t.Fatal(err)
	}
	form.Set("step", "stage")
	form.Set("confirmation", review.Confirmation)
	form["member"] = []string{"good.test", "bad.test"}
	server.cluster = testReplicaClusterController{}
	request := httptest.NewRequest("POST", "/ui/zones/import-catalog", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || stats.calls != 1 || len(configuration.zoneSnapshot.Zones) != 1 {
		t.Fatal("replica allowed catalog import")
	}
	server.cluster = nil
	if _, err := prepareImport(server, form); err != nil {
		t.Fatal(err)
	}
	if len(audit.events) != 1 || audit.events[0].Action != "zone.catalog_import" || audit.events[0].Details != "zone=good.test" {
		t.Fatalf("audit: %+v", audit.events)
	}
}
func TestCatalogImportRejectsMalformedCatalog(t *testing.T) {
	server, configuration, stats := catalogImportFixture(t)
	stats.members[0].Value = `"3"`
	if _, err := prepareImport(server, catalogImportForm()); err == nil || len(configuration.zoneSnapshot.Zones) != 1 {
		t.Fatal("unsupported catalog accepted")
	}
}

func TestCatalogImportWizardNavigation(t *testing.T) {
	server, _, stats := catalogImportFixture(t)
	submit := func(method string, form url.Values) string {
		t.Helper()
		request := httptest.NewRequest(method, "/ui/zones/import-catalog", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()
		server.importCatalog(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status: %d", response.Code)
		}
		return response.Body.String()
	}
	initial := submit(http.MethodGet, nil)
	if !strings.Contains(initial, `id="zones-content"`) || !strings.Contains(initial, `data-dialog-auto-open="true"`) || !strings.Contains(initial, "Step 1 of 3") || strings.Contains(initial, "<!doctype") {
		t.Fatal("wizard must open within Zones")
	}
	form := catalogImportForm()
	review := submit(http.MethodPost, form)
	if !strings.Contains(review, "Step 2 of 3") || !strings.Contains(review, `name="primary_servers" value="192.0.2.53:53"`) {
		t.Fatal("discovery did not advance with connection settings")
	}
	form.Set("step", "connect")
	back := submit(http.MethodPost, form)
	if !strings.Contains(back, "Step 1 of 3") || !strings.Contains(back, `value="catalog.test"`) || stats.calls != 1 {
		t.Fatal("Back must retain settings without a transfer")
	}
}

func TestCatalogPrimaryImport(t *testing.T) {
	for _, scenario := range []string{"success", "missing freeze", "signed", "invalid type"} {
		t.Run(scenario, func(t *testing.T) {
			server, configuration, stats := catalogImportFixture(t)
			form := catalogImportForm()
			review, err := prepareImport(server, form)
			if err != nil {
				t.Fatal(err)
			}
			form.Set("step", "stage")
			form.Set("confirmation", review.Confirmation)
			form.Set("import_type", "primary")
			form.Set("freeze_confirmed", "true")
			form["member"] = []string{"bad.test", "good.test"}
			switch scenario {
			case "missing freeze":
				form.Del("freeze_confirmed")
			case "signed":
				stats.signed = true
			case "invalid type":
				form.Set("import_type", "forwarder")
			}
			result, err := prepareImport(server, form)
			current := findZone(configuration.zoneSnapshot.Zones, "good.test")
			switch scenario {
			case "success":
				if err != nil || current == nil || current.Type != "primary" || len(current.PrimaryServers) != 0 || current.PrimaryProtocol != "" || current.CatalogZone != "" || current.ZoneTransfer != "deny" || conversionSerial(*current) <= 1 {
					t.Fatalf("Primary import: %+v %v", current, err)
				}
				if result.Results[0].Success || !result.Results[1].Success || !strings.Contains(result.Results[1].Message, "independent Primary") {
					t.Fatalf("mixed batch: %+v", result.Results)
				}
			case "signed":
				if err != nil || current != nil || len(result.Results) != 2 || result.Results[1].Success || !strings.Contains(result.Results[1].Message, "DNSSEC") {
					t.Fatalf("signed import: %+v %v", result, err)
				}
			default:
				if err == nil || current != nil || stats.calls != 2 {
					t.Fatal("invalid import must be rejected before member transfers")
				}
			}
			if findZone(configuration.zoneSnapshot.Zones, "bad.test") != nil {
				t.Fatal("failed transfer persisted a zone")
			}
		})
	}
}

func TestCatalogSignedSecondaryImportStillAllowed(t *testing.T) {
	server, configuration, stats := catalogImportFixture(t)
	stats.signed = true
	form := catalogImportForm()
	review, err := prepareImport(server, form)
	if err != nil {
		t.Fatal(err)
	}
	form.Set("step", "stage")
	form.Set("confirmation", review.Confirmation)
	form.Set("member", "good.test")
	result, err := prepareImport(server, form)
	current := findZone(configuration.zoneSnapshot.Zones, "good.test")
	if err != nil || current == nil || current.Type != "secondary" || !result.Results[0].Success || !strings.Contains(result.Results[0].Message, "Conversion blocked") {
		t.Fatalf("signed Secondary: %+v %v", result, err)
	}
}

func TestCatalogForwarderImport(t *testing.T) {
	for _, mode := range []string{"primary", "secondary"} {
		for _, scenario := range []string{"native", "technitium", "this-server", "invalid", "mixed validation", "unknown"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				server, configuration, stats := catalogImportFixture(t)
				stats.transferred = []dnsserver.ZoneRecord{
					{Name: "@", Type: "SOA", TTL: 300, Value: "ns.good.test. hostmaster.good.test. 1 60 10 600 300"},
					{Name: "@", Type: "FWD", TTL: 600, Value: "udp 10 192.0.2.53:53"},
				}
				switch scenario {
				case "technitium", "mixed validation":
					// UDP, length-prefixed 192.0.2.53, validation disabled, no proxy, priority 10.
					stats.transferred[1].Type = "TYPE65281"
					stats.transferred[1].Value = `\# 15 000a3139322e302e322e353300000a`
					if scenario == "mixed validation" {
						stats.transferred = append(stats.transferred, dnsserver.ZoneRecord{Name: "@", Type: "TYPE65281", TTL: 600, Value: `\# 15 000a3139322e302e322e353301000a`})
					}
				case "this-server":
					stats.transferred[1].Type = "TYPE65281"
					stats.transferred[1].Value = `\# 16 000b746869732d736572766572010000`
				case "invalid":
					stats.transferred[1].Value = "https 10 https://dns.example/dns-query"
				case "unknown":
					stats.transferred[1].Type = "TYPE65282"
				}
				form := catalogImportForm()
				review, err := prepareImport(server, form)
				if err != nil {
					t.Fatal(err)
				}
				form.Set("step", "stage")
				form.Set("confirmation", review.Confirmation)
				form.Set("member", "good.test")
				form.Set("import_type", mode)
				form.Set("freeze_confirmed", "true")
				result, err := prepareImport(server, form)
				if err != nil {
					t.Fatal(err)
				}
				current := findZone(configuration.zoneSnapshot.Zones, "good.test")
				if scenario == "invalid" || scenario == "mixed validation" || scenario == "unknown" {
					if current != nil || result.Results[0].Success {
						t.Fatalf("invalid forwarder persisted: %+v", result)
					}
					return
				}
				if current == nil || current.Type != "forwarder" || len(current.PrimaryServers) != 0 || current.PrimaryProtocol != "" || current.TSIGKey != "" || current.CatalogZone != "" {
					t.Fatalf("not an independent forwarder: %+v", current)
				}
				wantForwarder := "udp 10 192.0.2.53:53"
				if scenario == "this-server" {
					wantForwarder = "udp 0 this-server"
				}
				if len(current.Records) != 2 || current.Records[1].Value != wantForwarder || current.Records[1].TTL != 600 || current.DNSSECValidationDisabled != (scenario == "technitium") {
					t.Fatalf("routing settings changed: %+v", current)
				}
				if !result.Results[0].Success || result.Results[0].Warning || !strings.Contains(result.Results[0].Message, "independent Forwarder") {
					t.Fatalf("incorrect result: %+v", result)
				}
			})
		}
	}
}
