package app

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/dnsserver"
	zonemodel "github.com/drudge/sable/internal/zone"
)

func TestDynamicUpdatePrerequisites(t *testing.T) {
	t.Parallel()
	zone := dynamicUpdateTestZone()
	records, err := activeZoneRRs(zone, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		make func(*dns.Msg)
		want int
	}{
		{"name used", func(message *dns.Msg) { message.NameUsed([]dns.RR{mustRR(t, "www.example.test. 0 IN A 192.0.2.10")}) }, dns.RcodeSuccess},
		{"name not used", func(message *dns.Msg) {
			message.NameNotUsed([]dns.RR{mustRR(t, "new.example.test. 0 IN A 192.0.2.10")})
		}, dns.RcodeSuccess},
		{"name unexpectedly used", func(message *dns.Msg) {
			message.NameNotUsed([]dns.RR{mustRR(t, "www.example.test. 0 IN A 192.0.2.10")})
		}, dns.RcodeYXDomain},
		{"rrset used", func(message *dns.Msg) { message.RRsetUsed([]dns.RR{mustRR(t, "www.example.test. 0 IN A 192.0.2.10")}) }, dns.RcodeSuccess},
		{"rrset missing", func(message *dns.Msg) {
			message.RRsetUsed([]dns.RR{mustRR(t, "www.example.test. 0 IN AAAA 2001:db8::1")})
		}, dns.RcodeNXRrset},
		{"rrset not used", func(message *dns.Msg) {
			message.RRsetNotUsed([]dns.RR{mustRR(t, "www.example.test. 0 IN AAAA 2001:db8::1")})
		}, dns.RcodeSuccess},
		{"exact rrset", func(message *dns.Msg) { message.Used([]dns.RR{mustRR(t, "www.example.test. 0 IN A 192.0.2.10")}) }, dns.RcodeSuccess},
		{"exact rrset differs", func(message *dns.Msg) { message.Used([]dns.RR{mustRR(t, "www.example.test. 0 IN A 192.0.2.11")}) }, dns.RcodeNXRrset},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := new(dns.Msg)
			message.SetUpdate("example.test.")
			test.make(message)
			if got := evaluateUpdatePrerequisites(zone.Name, records, message.Answer); got != test.want {
				t.Fatalf("evaluateUpdatePrerequisites() = %s, want %s", dns.RcodeToString[got], dns.RcodeToString[test.want])
			}
		})
	}
}

func TestApplyDynamicZoneUpdateMutatesOnceAndProtectsAuthority(t *testing.T) {
	t.Parallel()
	zone := dynamicUpdateTestZone()
	message := new(dns.Msg)
	message.SetUpdate("example.test.")
	message.Insert([]dns.RR{
		mustRR(t, "api.example.test. 60 IN A 192.0.2.20"),
		mustRR(t, "api.example.test. 60 IN TXT \"managed\""),
	})
	changed, rcode, err := applyDynamicZoneUpdate(&zone, nil, message.Ns, time.Now())
	if err != nil || rcode != dns.RcodeSuccess || !changed {
		t.Fatalf("applyDynamicZoneUpdate() = changed %t, rcode %s, error %v", changed, dns.RcodeToString[rcode], err)
	}
	if serial := zoneSOASerial(t, zone); serial != 2026080902 {
		t.Fatalf("SOA serial = %d, want 2026080902", serial)
	}
	if !hasConfiguredRecord(zone, "api", "A", "192.0.2.20") || !hasConfiguredRecord(zone, "api", "TXT", "\"managed\"") {
		t.Fatalf("added records are missing: %+v", zone.Records)
	}

	removeAuthority := new(dns.Msg)
	removeAuthority.SetUpdate("example.test.")
	removeAuthority.RemoveName([]dns.RR{mustRR(t, "example.test. 0 IN A 192.0.2.1")})
	changed, rcode, err = applyDynamicZoneUpdate(&zone, nil, removeAuthority.Ns, time.Now())
	if err != nil || rcode != dns.RcodeSuccess || changed {
		t.Fatalf("apex authority removal = changed %t, rcode %s, error %v", changed, dns.RcodeToString[rcode], err)
	}
	if !hasConfiguredRecord(zone, "@", "SOA", "") || !hasConfiguredRecord(zone, "@", "NS", "") {
		t.Fatal("apex SOA or NS was removed")
	}
}

func TestApplyDynamicZoneUpdateRejectsOutOfZoneAndMalformedOperations(t *testing.T) {
	t.Parallel()
	zone := dynamicUpdateTestZone()
	outside := new(dns.Msg)
	outside.SetUpdate("example.test.")
	outside.Insert([]dns.RR{mustRR(t, "outside.test. 60 IN A 192.0.2.30")})
	if _, rcode, _ := applyDynamicZoneUpdate(&zone, nil, outside.Ns, time.Now()); rcode != dns.RcodeNotZone {
		t.Fatalf("outside update rcode = %s, want NOTZONE", dns.RcodeToString[rcode])
	}

	malformed := &dns.A{Hdr: dns.RR_Header{Name: "bad.example.test.", Rrtype: dns.TypeA, Class: dns.ClassNONE, Ttl: 30}}
	if _, rcode, _ := applyDynamicZoneUpdate(&zone, nil, []dns.RR{malformed}, time.Now()); rcode != dns.RcodeFormatError {
		t.Fatalf("malformed update rcode = %s, want FORMERR", dns.RcodeToString[rcode])
	}
}

type dynamicUpdateTestConfiguration struct {
	zones []zonemodel.Zone
}

func (configuration *dynamicUpdateTestConfiguration) UpdateZones(_ context.Context, mutate func(*[]zonemodel.Zone) error) error {
	return mutate(&configuration.zones)
}

type dynamicUpdateTestDNS struct {
	notified chan string
}

func (service *dynamicUpdateTestDNS) NotifyZone(_ context.Context, zone string, _ []string) []error {
	service.notified <- zone
	return nil
}

type dynamicUpdateTestAuditor struct {
	events chan auth.AuditEvent
}

func (auditor *dynamicUpdateTestAuditor) RecordAuditEvent(_ context.Context, event auth.AuditEvent) error {
	auditor.events <- event
	return nil
}

func TestDynamicZoneUpdaterPersistsAuditsAndNotifies(t *testing.T) {
	configuration := &dynamicUpdateTestConfiguration{zones: []zonemodel.Zone{dynamicUpdateTestZone()}}
	configuration.zones[0].Notify = []string{"192.0.2.53:53"}
	dnsService := &dynamicUpdateTestDNS{notified: make(chan string, 1)}
	auditor := &dynamicUpdateTestAuditor{events: make(chan auth.AuditEvent, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	updater := newDynamicZoneUpdater(ctx, configuration, dnsService, auditor, slog.New(slog.NewTextHandler(io.Discard, nil)))
	updater.now = func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) }

	message := new(dns.Msg)
	message.SetUpdate("example.test.")
	message.Insert([]dns.RR{mustRR(t, "api.example.test. 60 IN A 192.0.2.20")})
	result := updater.Update(context.Background(), dnsserver.ZoneUpdateRequest{
		Zone: "example.test", Updates: message.Ns, KeyName: "update-key.", Source: "192.0.2.5",
	})
	if result.Rcode != dns.RcodeSuccess || !result.Changed {
		t.Fatalf("Update() = %+v", result)
	}
	updater.Audit(context.Background(), dnsserver.ZoneUpdateRequest{
		Zone: "example.test", Updates: message.Ns, KeyName: "update-key.", Source: "192.0.2.5",
	}, result)
	select {
	case event := <-auditor.events:
		if event.Action != "dns.update" || event.ClientIP != "192.0.2.5" {
			t.Fatalf("audit event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("dynamic update audit event was not recorded")
	}
	select {
	case zone := <-dnsService.notified:
		if zone != "example.test" {
			t.Fatalf("notified zone = %q", zone)
		}
	case <-time.After(time.Second):
		t.Fatal("post-commit NOTIFY was not sent")
	}
}

func dynamicUpdateTestZone() zonemodel.Zone {
	return zonemodel.Zone{
		Name: "example.test", Type: "primary", DefaultTTL: 300,
		TSIGKey: "update-key.", DynamicUpdates: true,
		Records: []zonemodel.Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 2026080901 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.10"},
		},
	}
}

func mustRR(t *testing.T, value string) dns.RR {
	t.Helper()
	record, err := dns.NewRR(value)
	if err != nil {
		t.Fatalf("dns.NewRR(%q): %v", value, err)
	}
	return record
}

func zoneSOASerial(t *testing.T, zone zonemodel.Zone) uint32 {
	t.Helper()
	for _, record := range zone.Records {
		if record.Type == "SOA" {
			rr, err := configuredRecordRR(zone, record)
			if err != nil {
				t.Fatal(err)
			}
			return rr.(*dns.SOA).Serial
		}
	}
	t.Fatal("SOA record is missing")
	return 0
}

func hasConfiguredRecord(zone zonemodel.Zone, name, recordType, value string) bool {
	return slices.ContainsFunc(zone.Records, func(record zonemodel.Record) bool {
		return record.Name == name && record.Type == recordType && (value == "" || record.Value == value)
	})
}

func BenchmarkDynamicUpdatePrerequisites(b *testing.B) {
	zone := dynamicUpdateTestZone()
	records, err := activeZoneRRs(zone, time.Now())
	if err != nil {
		b.Fatal(err)
	}
	message := new(dns.Msg)
	message.SetUpdate("example.test.")
	message.Used([]dns.RR{mustBenchmarkRR(b, "www.example.test. 0 IN A 192.0.2.10")})
	b.ReportAllocs()
	for b.Loop() {
		if evaluateUpdatePrerequisites(zone.Name, records, message.Answer) != dns.RcodeSuccess {
			b.Fatal("prerequisite unexpectedly failed")
		}
	}
}

func mustBenchmarkRR(b *testing.B, value string) dns.RR {
	b.Helper()
	record, err := dns.NewRR(value)
	if err != nil {
		b.Fatal(err)
	}
	return record
}
