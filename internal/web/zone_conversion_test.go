package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	zonemodel "github.com/drudge/sable/internal/zone"
)

type conversionTestStats struct {
	testStats
	records []dnsserver.ZoneRecord
	err     error
	calls   int
}

func (stats *conversionTestStats) FetchZone(context.Context, string, string, []string, string, string) ([]dnsserver.ZoneRecord, error) {
	stats.calls++
	return stats.records, stats.err
}
func (stats *conversionTestStats) RefreshZone(context.Context, string, string, []string, string, string, []dnsserver.ZoneRecord) ([]dnsserver.ZoneRecord, bool, error) {
	panic("conversion must fetch a complete final snapshot")
}

func conversionTestZone() zonemodel.Zone {
	return zonemodel.Zone{ID: "preserved-id", Name: "secondary.test", Type: "secondary", Revision: 7, DefaultTTL: 300,
		PrimaryServers: []string{"192.0.2.53:53"}, PrimaryProtocol: "tcp", ZoneTransfer: "deny",
		Records: []zonemodel.Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns.secondary.test. hostmaster.secondary.test. 7 60 10 600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns.secondary.test."},
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.1", Comments: "keep metadata"},
		},
	}
}

func newConversionServer(t *testing.T, stats *conversionTestStats) (*Server, *editableTestConfiguration) {
	t.Helper()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}, zoneSnapshot: zonemodel.Snapshot{Zones: []zonemodel.Zone{conversionTestZone()}}}
	server, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), stats, configuration, configuration.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil }, nil, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return server, configuration
}
func conversionForm(current zonemodel.Zone) url.Values {
	return url.Values{"zone": {current.Name}, "confirmation": {zonemodel.ConversionFingerprint(current)}, "freeze_confirmed": {"true"}, "final_sync": {"false"}}
}
func conversionRequest(server *Server, form url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/zones/convert-primary", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

func TestPrimaryConversionAPIReviewAndCommit(t *testing.T) {
	stats := &conversionTestStats{}
	server, configuration := newConversionServer(t, stats)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/zones/convert-primary?zone=secondary.test", nil))
	var review struct {
		Confirmation string
		Serial       uint32
		RecordCount  int `json:"record_count"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &review); err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 || review.Serial != 7 || review.RecordCount != 3 {
		t.Fatalf("review = %d %s", response.Code, response.Body.String())
	}
	form := conversionForm(configuration.zoneSnapshot.Zones[0])
	form.Set("confirmation", review.Confirmation)
	response = conversionRequest(server, form)
	current := configuration.zoneSnapshot.Zones[0]
	if response.Code != 200 || current.Type != "primary" || current.ID != "preserved-id" || len(current.Records) != 3 || stats.calls != 0 {
		t.Fatalf("conversion = %d %s %+v", response.Code, response.Body.String(), current)
	}
	if current.Records[2].Comments != "keep metadata" || current.DynamicUpdates || current.ZoneTransfer != "deny" {
		t.Fatal("metadata or policy changed")
	}
	if response := conversionRequest(server, form); response.Code == 200 {
		t.Fatal("repeated conversion succeeded")
	}
}

func TestPrimaryConversionRejectsStaleAndUnsupportedConfirmations(t *testing.T) {
	for _, change := range []string{"records", "identity", "source", "revision", "signed", "catalog", "freeze", "choice"} {
		t.Run(change, func(t *testing.T) {
			stats := &conversionTestStats{}
			server, configuration := newConversionServer(t, stats)
			form := conversionForm(configuration.zoneSnapshot.Zones[0])
			form.Set("final_sync", "true")
			current := &configuration.zoneSnapshot.Zones[0]
			switch change {
			case "records":
				current.Records[2].Value = "192.0.2.99"
			case "identity":
				current.ID = "replacement"
			case "source":
				current.PrimaryServers = []string{"192.0.2.54:53"}
			case "revision":
				current.Revision++
			case "signed":
				current.Records = append(current.Records, zonemodel.Record{Type: "RRSIG"})
			case "catalog":
				current.CatalogZone = "catalog.test"
			case "freeze":
				form.Del("freeze_confirmed")
			case "choice":
				form.Del("final_sync")
			}
			before := zonemodel.Clone(configuration.zoneSnapshot.Zones)
			response := conversionRequest(server, form)
			if response.Code != 422 || stats.calls != 0 || !reflect.DeepEqual(before, configuration.zoneSnapshot.Zones) {
				t.Fatalf("rejected conversion = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestPrimaryConversionFinalSynchronization(t *testing.T) {
	for _, result := range []string{"success", "failure", "signed", "invalid", "older"} {
		t.Run(result, func(t *testing.T) {
			stats := &conversionTestStats{}
			for _, record := range conversionTestZone().Records {
				stats.records = append(stats.records, dnsserver.ZoneRecord{Name: record.Name, Type: record.Type, Value: record.Value, TTL: record.TTL})
			}
			stats.records[0].Value = "ns.secondary.test. hostmaster.secondary.test. 8 60 10 600 300"
			switch result {
			case "failure":
				stats.err = errors.New("source unreachable")
			case "signed":
				stats.records = append(stats.records, dnsserver.ZoneRecord{Type: "RRSIG"})
			case "invalid":
				stats.records = nil
			case "older":
				stats.records[0].Value = "ns.secondary.test. hostmaster.secondary.test. 6 60 10 600 300"
			}
			server, configuration := newConversionServer(t, stats)
			before := zonemodel.Clone(configuration.zoneSnapshot.Zones)
			form := conversionForm(before[0])
			form.Set("final_sync", "true")
			response := conversionRequest(server, form)
			if stats.calls != 1 {
				t.Fatal("final synchronization not attempted")
			}
			if result == "success" {
				current := configuration.zoneSnapshot.Zones[0]
				if response.Code != 200 || current.Type != "primary" || int32(conversionSerial(current)-8) <= 0 || current.Records[2].Comments != "keep metadata" {
					t.Fatalf("final sync = %d %s", response.Code, response.Body.String())
				}
			} else if response.Code != 422 || !reflect.DeepEqual(before, configuration.zoneSnapshot.Zones) {
				t.Fatalf("failure altered zone: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestPrimaryConversionRequiresPrimaryAndZonePermissions(t *testing.T) {
	for _, path := range []string{"/api/v1/zones/convert-primary", "/ui/zones/convert-primary"} {
		if !writeRequiresPrimary(cluster.State{Initialized: true, LocalRole: cluster.RoleReplica}, http.MethodPost, path) {
			t.Fatal("replica permits conversion")
		}
	}
	server, configuration := newConversionServer(t, &conversionTestStats{testStats: testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}}})
	server.securityEnabled = true
	request := httptest.NewRequest(http.MethodPost, "/ui/zones/convert-primary", strings.NewReader(conversionForm(configuration.zoneSnapshot.Zones[0]).Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, auth.Principal{}))
	response := httptest.NewRecorder()
	server.convertZoneToPrimary(response, request)
	if response.Code != http.StatusForbidden || configuration.zoneSnapshot.Zones[0].Type != "secondary" {
		t.Fatal("unauthorized conversion succeeded")
	}
}

func TestPrimaryConversionScopedPermissions(t *testing.T) {
	for _, test := range []struct {
		name        string
		permissions []string
		sync        bool
		allowed     bool
	}{
		{"settings only", []string{auth.PermissionZonesSettings}, false, false},
		{"records only", []string{auth.PermissionZonesRecords}, false, false},
		{"both", []string{auth.PermissionZonesSettings, auth.PermissionZonesRecords}, false, true},
		{"sync requires transfer", []string{auth.PermissionZonesSettings, auth.PermissionZonesRecords}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			stats := &conversionTestStats{}
			server, configuration := newConversionServer(t, stats)
			server.securityEnabled = true
			principal := auth.Principal{Surface: auth.SurfaceWeb}
			for _, permission := range test.permissions {
				principal.Grants = append(principal.Grants, auth.Grant{Permission: permission, Surface: auth.SurfaceWeb, ResourceType: auth.ResourceZone, ResourceID: "preserved-id"})
			}
			form := conversionForm(configuration.zoneSnapshot.Zones[0])
			if test.sync {
				form.Set("final_sync", "true")
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/zones/convert-primary", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal))
			response := httptest.NewRecorder()
			server.convertZoneToPrimary(response, request)
			if (configuration.zoneSnapshot.Zones[0].Type == "primary") != test.allowed || stats.calls != 0 {
				t.Fatalf("permission check = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

type conversionAuditLog struct {
	testQueryLog
	events []auth.AuditEvent
}

func (log *conversionAuditLog) RecordAuditEvent(_ context.Context, event auth.AuditEvent) error {
	log.events = append(log.events, event)
	return nil
}

func TestPrimaryConversionAuditsOnlySuccessfulCommitAndBlocksReplica(t *testing.T) {
	server, configuration := newConversionServer(t, &conversionTestStats{})
	audit := &conversionAuditLog{}
	server.queries = audit
	form := conversionForm(configuration.zoneSnapshot.Zones[0])
	server.cluster = testReplicaClusterController{}
	if response := conversionRequest(server, form); response.Code != http.StatusConflict {
		t.Fatalf("replica status = %d", response.Code)
	}
	if len(audit.events) != 0 || configuration.zoneSnapshot.Zones[0].Type != "secondary" {
		t.Fatal("replica changed zone")
	}
	server.cluster = nil
	if response := conversionRequest(server, form); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	conversionRequest(server, form)
	if len(audit.events) != 1 || audit.events[0].Action != "zone.convert_primary" || audit.events[0].Details != "zone=secondary.test" {
		t.Fatalf("audit = %+v", audit.events)
	}
}
