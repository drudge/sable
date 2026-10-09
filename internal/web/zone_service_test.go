package web

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	zonemodel "github.com/drudge/sable/internal/zone"
)

var serviceAdmin = actor{principal: auth.Principal{UserID: 1, Username: "admin", Permissions: []string{auth.PermissionAll}}, via: "test"}

func serviceZone(t *testing.T, configuration *editableTestConfiguration, name string) zonemodel.Zone {
	t.Helper()
	zone := findZone(configuration.zoneSnapshot.Zones, name)
	if zone == nil {
		t.Fatalf("zone %s is missing", name)
	}
	return *zone
}

func TestZoneServiceMatchesRecordsByFQDN(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, name := range []string{"www", "WWW", "www.example.test", "www.example.test.", "WWW.Example.Test."} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server, configuration := newMCPTestServer(t)
			service := server.zoneService()
			// TTL is not part of a record's identity.
			change, err := service.DeleteRecord(ctx, serviceAdmin, "Example.Test.", recordKey{Name: name, Type: "a", Value: " 192.0.2.10 "})
			if err != nil || !change.Changed || len(change.Removed) != 1 {
				t.Fatalf("DeleteRecord(%q) = %+v, %v", name, change, err)
			}
			if records := mcpZoneRecords(configuration, "example.test", "www", "A"); len(records) != 0 {
				t.Fatalf("records after delete = %+v", records)
			}
		})
	}
}

func TestZoneServiceStoresOwnersInLowercase(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	service := server.zoneService()
	if _, err := service.AddRecord(context.Background(), serviceAdmin, "example.test", recordInput{Name: "API.Example.Test.", Type: "A", Value: "192.0.2.20"}); err != nil {
		t.Fatal(err)
	}
	if records := mcpZoneRecords(configuration, "example.test", "api", "A"); len(records) != 1 || records[0].TTL != 300 {
		t.Fatalf("api records = %+v", records)
	}
	// Adding the same record again, spelled differently, changes nothing.
	change, err := service.AddRecord(context.Background(), serviceAdmin, "example.test", recordInput{Name: "api", Type: "A", Value: "192.0.2.20", TTL: 60})
	if err != nil || change.Changed {
		t.Fatalf("repeated add = %+v, %v", change, err)
	}
}

func TestZoneServiceTTLChoosesBetweenDuplicates(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	zone := &configuration.zoneSnapshot.Zones[0]
	zone.Records = append(zone.Records, zonemodel.Record{Name: "www", Type: "A", Value: "192.0.2.10", TTL: 60})
	service := server.zoneService()
	if _, err := service.DeleteRecord(context.Background(), serviceAdmin, "example.test", recordKey{Name: "www", Type: "A", Value: "192.0.2.10"}); err == nil ||
		!strings.Contains(err.Error(), "more than one") {
		t.Fatalf("delete without TTL = %v", err)
	}
	if _, err := service.DeleteRecord(context.Background(), serviceAdmin, "example.test", recordKey{Name: "www", Type: "A", Value: "192.0.2.10", TTL: 60}); err != nil {
		t.Fatal(err)
	}
	if records := mcpZoneRecords(configuration, "example.test", "www", "A"); len(records) != 1 || records[0].TTL != 300 {
		t.Fatalf("records after delete = %+v", records)
	}
}

func TestZoneServiceKeepsGlueAndExpiry(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	service := server.zoneService()
	ctx := context.Background()
	glue := "192.0.2.53, 2001:db8::53"
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if _, err := service.AddRecord(ctx, serviceAdmin, "example.test", recordInput{
		Name: "lab", Type: "NS", Value: "nslab", ExpiresAt: expires, Glue: &glue,
	}); err != nil {
		t.Fatal(err)
	}
	ns := mcpZoneRecords(configuration, "example.test", "lab", "NS")
	if len(ns) != 1 || ns[0].Value != "nslab.example.test." || !ns[0].ExpiresAt.Equal(expires) {
		t.Fatalf("NS records = %+v", ns)
	}
	if a, aaaa := mcpZoneRecords(configuration, "example.test", "nslab", "A"), mcpZoneRecords(configuration, "example.test", "nslab", "AAAA"); len(a) != 1 || len(aaaa) != 1 {
		t.Fatalf("glue = %+v %+v", a, aaaa)
	}

	// Moving the name server moves its glue.
	value, newGlue := "nslab2", "192.0.2.54"
	if _, err := service.UpdateRecord(ctx, serviceAdmin, "example.test", recordUpdate{
		Key: recordKey{Name: "lab", Type: "NS", Value: "nslab.example.test."}, Value: &value, Glue: &newGlue,
	}); err != nil {
		t.Fatal(err)
	}
	if old := mcpZoneRecords(configuration, "example.test", "nslab", "A"); len(old) != 0 {
		t.Fatalf("old glue kept: %+v", old)
	}
	if moved := mcpZoneRecords(configuration, "example.test", "nslab2", "A"); len(moved) != 1 || moved[0].Value != "192.0.2.54" {
		t.Fatalf("new glue = %+v", moved)
	}
	if ns := mcpZoneRecords(configuration, "example.test", "lab", "NS"); len(ns) != 1 || !ns[0].ExpiresAt.Equal(expires) {
		t.Fatalf("an edit that leaves the expiry alone dropped it: %+v", ns)
	}
}

func TestZoneServiceRefusesRecordsItDoesNotOwn(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	zone := &configuration.zoneSnapshot.Zones[0]
	zone.Records = append(zone.Records,
		zonemodel.Record{Name: "printer", Type: "A", Value: "192.0.2.40", TTL: 300, Source: "unifi"},
		zonemodel.Record{Name: "@", Type: "DNSKEY", Value: "257 3 13 AQAB", TTL: 300, Comments: "sable:dnssec"},
	)
	service := server.zoneService()
	ctx := context.Background()
	for _, key := range []recordKey{
		{Name: "printer", Type: "A", Value: "192.0.2.40"},
		{Name: "@", Type: "DNSKEY", Value: "257 3 13 AQAB"},
	} {
		if _, err := service.DeleteRecord(ctx, serviceAdmin, "example.test", key); err == nil {
			t.Errorf("delete %s %s succeeded", key.Name, key.Type)
		}
		enabled := false
		if _, err := service.UpdateRecord(ctx, serviceAdmin, "example.test", recordUpdate{Key: key, Enabled: &enabled}); err == nil {
			t.Errorf("update %s %s succeeded", key.Name, key.Type)
		}
	}
	if _, err := service.DeleteRecord(ctx, serviceAdmin, "example.test", recordKey{Name: "@", Type: "SOA", Value: "anything"}); err == nil ||
		!strings.Contains(err.Error(), "SOA") {
		t.Fatalf("SOA delete = %v", err)
	}
	if _, err := service.AddRecord(ctx, serviceAdmin, "secondary.test", recordInput{Name: "x", Type: "A", Value: "192.0.2.1"}); err == nil ||
		!strings.Contains(err.Error(), "read-only") {
		t.Fatalf("secondary add = %v", err)
	}
}

func TestZoneServiceSerial(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	service := server.zoneService()
	ctx := context.Background()
	serial := func() uint32 { return zoneRecordSOASerial(apexSOA(serviceZone(t, configuration, "example.test"))) }
	start := serial()

	ttl := uint32(300)
	if change, err := service.UpdateRecord(ctx, serviceAdmin, "example.test", recordUpdate{Key: recordKey{Name: "www", Type: "A", Value: "192.0.2.10"}, TTL: &ttl}); err != nil || change.Changed || serial() != start {
		t.Fatalf("a no-op update changed the serial: %+v %v %d", change, err, serial())
	}
	value := "192.0.2.11"
	if change, err := service.UpdateRecord(ctx, serviceAdmin, "example.test", recordUpdate{Key: recordKey{Name: "www", Type: "A", Value: "192.0.2.10"}, Value: &value}); err != nil || !change.Changed || serial() <= start || change.Serial != serial() {
		t.Fatalf("update = %+v %v, serial %d -> %d", change, err, start, serial())
	}
	// An edit to the SOA keeps the serial the operator wrote.
	soa := "ns1.example.test. hostmaster.example.test. 2030010101 7200 600 1209600 300"
	if _, err := service.UpdateRecord(ctx, serviceAdmin, "example.test", recordUpdate{Key: recordKey{Name: "@", Type: "SOA", Value: apexSOA(serviceZone(t, configuration, "example.test"))}, Value: &soa}); err != nil {
		t.Fatal(err)
	}
	if serial() != 2030010101 {
		t.Fatalf("SOA serial = %d, want the edited one", serial())
	}
}

func TestZoneServiceAuthorization(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)
	service := server.zoneService()
	ctx := context.Background()
	reader := actor{principal: auth.Principal{UserID: 2, Surface: auth.SurfaceAPI, Grants: []auth.Grant{mcpZoneGrant(auth.PermissionZonesRead, "zone-example")}}}
	input := recordInput{Name: "x", Type: "A", Value: "192.0.2.1"}

	_, err := service.AddRecord(ctx, reader, "example.test", input)
	if serviceStatus(err) != http.StatusForbidden || !strings.Contains(err.Error(), auth.PermissionZonesRecords) {
		t.Fatalf("reader add = %d %v", serviceStatus(err), err)
	}
	// A zone the actor cannot read answers like a missing one.
	_, hidden := service.AddRecord(ctx, reader, "other.test", input)
	_, missing := service.AddRecord(ctx, serviceAdmin, "missing.test", input)
	if serviceStatus(hidden) != http.StatusNotFound || serviceStatus(missing) != http.StatusNotFound ||
		strings.Replace(hidden.Error(), "other.test", "missing.test", 1) != missing.Error() {
		t.Fatalf("hidden = %v, missing = %v", hidden, missing)
	}
	if _, err := service.CreateZone(ctx, reader, zoneCreate{Name: "new.test"}); serviceStatus(err) != http.StatusForbidden {
		t.Fatalf("reader create = %v", err)
	}
	if _, err := service.DeleteZone(ctx, reader, "example.test"); serviceStatus(err) != http.StatusForbidden {
		t.Fatalf("reader delete = %v", err)
	}

	server.SetClusterController(testReplicaClusterController{})
	if _, err := service.AddRecord(ctx, serviceAdmin, "example.test", input); err == nil || err.Error() != replicaWriteMessage {
		t.Fatalf("replica add = %v", err)
	}
	if _, err := service.CreateZone(ctx, serviceAdmin, zoneCreate{Name: "new.test"}); err == nil || err.Error() != replicaWriteMessage {
		t.Fatalf("replica create = %v", err)
	}
}

func TestZoneServiceCreateZoneDefaults(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)
	service := server.zoneService()
	ctx := context.Background()
	created, err := service.CreateZone(ctx, serviceAdmin, zoneCreate{Name: "New.Test."})
	if err != nil {
		t.Fatal(err)
	}
	if created.Name != "new.test" || created.Type != "primary" || created.DefaultTTL != defaultZoneTTL {
		t.Fatalf("created = %+v", created)
	}
	soa, ns := apexSOA(created), ""
	for _, record := range created.Records {
		if record.Type == "NS" {
			ns = record.Value
		}
	}
	if !strings.HasPrefix(soa, "ns1.new.test. hostmaster.new.test. ") || ns != "ns1.new.test." {
		t.Fatalf("SOA = %q, NS = %q", soa, ns)
	}
	if _, err := service.CreateZone(ctx, serviceAdmin, zoneCreate{Name: "new.test"}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second create = %v", err)
	}
	if _, err := service.DeleteZone(ctx, serviceAdmin, "new.test"); err != nil {
		t.Fatal(err)
	}
}

func TestZoneServiceAuditsOnceThroughOneHelper(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)
	queries := server.queries.(*mcpTestQueries)
	service := server.zoneService()
	ctx := context.Background()
	input := recordInput{Name: "audit", Type: "TXT", Value: "hello"}
	for range 2 {
		if _, err := service.AddRecord(ctx, serviceAdmin, "example.test", input); err != nil {
			t.Fatal(err)
		}
	}
	events := queries.auditEvents()
	if len(events) != 1 || events[0].Action != "zone.record.create" || events[0].Details != "zone=example.test via=test" ||
		events[0].UserID == nil || *events[0].UserID != 1 {
		t.Fatalf("audit events = %+v", events)
	}
}

func TestPolicyServiceListsAreExclusive(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	service := server.policyService()
	ctx := context.Background()
	lists := func() (blocked, allowed []string) {
		policy := configuration.snapshot.Config.Blocking
		return policy.Domains, policy.AllowedDomains
	}

	if change, err := service.Allow(ctx, serviceAdmin, "", "Shop.Example."); err != nil || !change.Changed || change.Domain != "shop.example" {
		t.Fatalf("allow = %+v %v", change, err)
	}
	revision := configuration.snapshot.Revision
	if change, err := service.Allow(ctx, serviceAdmin, "", "shop.example"); err != nil || change.Changed || configuration.snapshot.Revision != revision {
		t.Fatalf("repeated allow = %+v %v", change, err)
	}
	if change, err := service.Block(ctx, serviceAdmin, "", "shop.example"); err != nil || !change.Changed || !strings.Contains(change.Message, "allow list") {
		t.Fatalf("block = %+v %v", change, err)
	}
	if blocked, allowed := lists(); !slices.Contains(blocked, "shop.example") || slices.Contains(allowed, "shop.example") {
		t.Fatalf("after block: blocked=%v allowed=%v", blocked, allowed)
	}
	if _, err := service.Allow(ctx, serviceAdmin, "", "shop.example"); err != nil {
		t.Fatal(err)
	}
	if blocked, allowed := lists(); slices.Contains(blocked, "shop.example") || !slices.Contains(allowed, "shop.example") {
		t.Fatalf("after allow: blocked=%v allowed=%v", blocked, allowed)
	}

	message, err := service.Import(ctx, serviceAdmin, "", []string{"shop.example", "ads.example"}, 2, false)
	if err != nil || message != "Imported 2 domains to the blocked list and took 1 off the allow list (2 invalid lines skipped)" {
		t.Fatalf("import = %q %v", message, err)
	}
	if blocked, allowed := lists(); !slices.Equal(blocked, []string{"ads.example", "shop.example"}) || len(allowed) != 0 {
		t.Fatalf("after import: blocked=%v allowed=%v", blocked, allowed)
	}

	if change, err := service.Remove(ctx, serviceAdmin, "", "ads.example", true); err != nil || change.Changed {
		t.Fatalf("remove from the wrong list = %+v %v", change, err)
	}
	if change, err := service.RemoveRule(ctx, serviceAdmin, "", "ads.example"); err != nil || !change.Changed {
		t.Fatalf("remove rule = %+v %v", change, err)
	}
	if _, err := service.Clear(ctx, serviceAdmin, "", false); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := lists(); len(blocked) != 0 {
		t.Fatalf("after clear: blocked=%v", blocked)
	}
}

func TestPolicyServiceRefusals(t *testing.T) {
	t.Parallel()
	server, _ := newMCPTestServer(t)
	service := server.policyService()
	ctx := context.Background()
	reader := actor{principal: auth.Principal{UserID: 2, Permissions: []string{auth.PermissionBlockingRead}}}
	if _, err := service.Block(ctx, reader, "", "x.example"); serviceStatus(err) != http.StatusForbidden || !strings.Contains(err.Error(), auth.PermissionBlockingWrite) {
		t.Fatalf("reader block = %v", err)
	}
	if _, err := service.Block(ctx, serviceAdmin, "", "not a domain"); err == nil || !strings.Contains(err.Error(), "domain is invalid") {
		t.Fatalf("invalid block = %v", err)
	}
	server.SetClusterController(testReplicaClusterController{})
	var refusal *serviceError
	if _, err := service.Allow(ctx, serviceAdmin, "", "x.example"); !errors.As(err, &refusal) || err.Error() != replicaWriteMessage {
		t.Fatalf("replica allow = %v", err)
	}
}
