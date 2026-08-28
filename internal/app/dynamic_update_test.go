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

func TestApplyDynamicZoneUpdateEnforcesCNAMEExclusivity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		extra   []zonemodel.Record
		insert  string
		changed bool
		verify  func(*testing.T, zonemodel.Zone)
	}{
		{
			name:    "cname add is ignored when other data exists",
			insert:  "www.example.test. 300 IN CNAME target.example.test.",
			changed: false,
			verify: func(t *testing.T, zone zonemodel.Zone) {
				if configuredRecordCount(zone, "www", "CNAME") != 0 {
					t.Fatalf("CNAME was added next to existing data: %+v", zone.Records)
				}
			},
		},
		{
			name:    "address add is ignored when a cname exists",
			extra:   []zonemodel.Record{{Name: "alias", Type: "CNAME", TTL: 300, Value: "target.example.test."}},
			insert:  "alias.example.test. 300 IN A 192.0.2.20",
			changed: false,
			verify: func(t *testing.T, zone zonemodel.Zone) {
				if configuredRecordCount(zone, "alias", "A") != 0 {
					t.Fatalf("address was added next to a CNAME: %+v", zone.Records)
				}
			},
		},
		{
			name:    "cname add replaces the existing cname",
			extra:   []zonemodel.Record{{Name: "alias", Type: "CNAME", TTL: 300, Value: "old.example.test."}},
			insert:  "alias.example.test. 300 IN CNAME new.example.test.",
			changed: true,
			verify: func(t *testing.T, zone zonemodel.Zone) {
				if configuredRecordCount(zone, "alias", "CNAME") != 1 || !hasConfiguredRecord(zone, "alias", "CNAME", "new.example.test.") {
					t.Fatalf("CNAME was not replaced: %+v", zone.Records)
				}
			},
		},
		{
			name:    "identical cname add changes nothing",
			extra:   []zonemodel.Record{{Name: "alias", Type: "CNAME", TTL: 300, Value: "target.example.test."}},
			insert:  "alias.example.test. 300 IN CNAME target.example.test.",
			changed: false,
			verify: func(t *testing.T, zone zonemodel.Zone) {
				if configuredRecordCount(zone, "alias", "CNAME") != 1 {
					t.Fatalf("CNAME record count changed: %+v", zone.Records)
				}
			},
		},
		{
			name:    "rrsig coexists with a cname",
			extra:   []zonemodel.Record{{Name: "alias", Type: "CNAME", TTL: 300, Value: "target.example.test."}},
			insert:  "alias.example.test. 300 IN RRSIG CNAME 15 3 300 20260901000000 20260801000000 12345 example.test. dGVzdA==",
			changed: true,
			verify: func(t *testing.T, zone zonemodel.Zone) {
				if configuredRecordCount(zone, "alias", "RRSIG") != 1 || configuredRecordCount(zone, "alias", "CNAME") != 1 {
					t.Fatalf("DNSSEC material did not coexist with the CNAME: %+v", zone.Records)
				}
			},
		},
		{
			name:    "disabled data does not block a cname add",
			extra:   []zonemodel.Record{{Name: "alias", Type: "A", TTL: 300, Value: "192.0.2.20", Disabled: true}},
			insert:  "alias.example.test. 300 IN CNAME target.example.test.",
			changed: true,
			verify: func(t *testing.T, zone zonemodel.Zone) {
				if configuredRecordCount(zone, "alias", "CNAME") != 1 {
					t.Fatalf("CNAME was not added next to disabled data: %+v", zone.Records)
				}
			},
		},
		{
			name:    "aname blocks a cname add",
			extra:   []zonemodel.Record{{Name: "alias", Type: "ANAME", TTL: 300, Value: "target.example.test."}},
			insert:  "alias.example.test. 300 IN CNAME other.example.test.",
			changed: false,
			verify: func(t *testing.T, zone zonemodel.Zone) {
				if configuredRecordCount(zone, "alias", "CNAME") != 0 || configuredRecordCount(zone, "alias", "ANAME") != 1 {
					t.Fatalf("ANAME was not preserved: %+v", zone.Records)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			zone := dynamicUpdateTestZone()
			zone.Records = append(zone.Records, test.extra...)
			message := new(dns.Msg)
			message.SetUpdate("example.test.")
			message.Insert([]dns.RR{mustRR(t, test.insert)})
			changed, rcode, err := applyDynamicZoneUpdate(&zone, nil, message.Ns, time.Now())
			if err != nil || rcode != dns.RcodeSuccess || changed != test.changed {
				t.Fatalf("applyDynamicZoneUpdate() = changed %t, rcode %s, error %v, want changed %t",
					changed, dns.RcodeToString[rcode], err, test.changed)
			}
			test.verify(t, zone)
		})
	}
}

func configuredRecordCount(zone zonemodel.Zone, name, recordType string) int {
	count := 0
	for _, record := range zone.Records {
		if record.Name == name && record.Type == recordType {
			count++
		}
	}
	return count
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
