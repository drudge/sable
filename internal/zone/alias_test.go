package zone

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func aliasSourceFixture() Zone {
	return Zone{
		Name: "example.test", Type: "primary", DefaultTTL: 300, ZoneTransfer: "deny",
		Records: []Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. 1 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test."},
			{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.10"},
		},
	}
}

func aliasFixture(source string) Zone {
	return Zone{
		Name: "example.lan", Type: "alias", DefaultTTL: 300, ZoneTransfer: "deny", AliasZone: source,
		Records: []Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.lan. hostmaster.example.lan. 2026081501 3600 600 1209600 300"},
		},
	}
}

func mirroredRecords(zone Zone) []Record {
	mirrored := make([]Record, 0, len(zone.Records))
	for _, record := range zone.Records {
		if record.Source == SourceAlias {
			mirrored = append(mirrored, record)
		}
	}
	return mirrored
}

func TestMaterializeAliasesRepublishesSourceRecordsBesideItsOwnSOA(t *testing.T) {
	t.Parallel()
	zones := []Zone{aliasSourceFixture(), aliasFixture("example.test")}
	if err := MaterializeAliases(&zones, time.Now()); err != nil {
		t.Fatal(err)
	}
	alias := zones[1]
	mirrored := mirroredRecords(alias)
	want := []Record{
		{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.test.", Source: SourceAlias},
		{Name: "www", Type: "A", TTL: 300, Value: "192.0.2.10", Source: SourceAlias},
	}
	if !slices.EqualFunc(mirrored, want, sameMirroredRecord) {
		t.Fatalf("mirrored records = %#v, want %#v", mirrored, want)
	}
	soaCount := 0
	for _, record := range alias.Records {
		if record.Name == "@" && record.Type == "SOA" {
			soaCount++
			if record.Source == SourceAlias {
				t.Fatal("the alias zone mirrored the source SOA instead of keeping its own")
			}
		}
	}
	if soaCount != 1 {
		t.Fatalf("alias zone has %d apex SOA records, want exactly 1", soaCount)
	}
	if err := ValidateAll(zones, nil); err != nil {
		t.Fatalf("a materialized alias zone failed validation: %v", err)
	}
}

func TestMaterializeAliasesIsIdempotent(t *testing.T) {
	t.Parallel()
	zones := []Zone{aliasSourceFixture(), aliasFixture("example.test")}
	now := time.Now()
	if err := MaterializeAliases(&zones, now); err != nil {
		t.Fatal(err)
	}
	firstSerial := zoneSerial(t, zones[1])
	for range 3 {
		if err := MaterializeAliases(&zones, now.Add(48*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if serial := zoneSerial(t, zones[1]); serial != firstSerial {
		t.Fatalf("an unchanged source advanced the alias serial from %d to %d", firstSerial, serial)
	}
}

func TestMaterializeAliasesAdvancesSerialWhenTheSourceChanges(t *testing.T) {
	t.Parallel()
	zones := []Zone{aliasSourceFixture(), aliasFixture("example.test")}
	now := time.Now()
	if err := MaterializeAliases(&zones, now); err != nil {
		t.Fatal(err)
	}
	before := zoneSerial(t, zones[1])
	zones[0].Records = append(zones[0].Records, Record{Name: "mail", Type: "A", TTL: 300, Value: "192.0.2.25"})
	if err := MaterializeAliases(&zones, now); err != nil {
		t.Fatal(err)
	}
	if serial := zoneSerial(t, zones[1]); serial <= before {
		t.Fatalf("alias serial = %d after the source changed, want more than %d", serial, before)
	}
	if len(mirroredRecords(zones[1])) != 3 {
		t.Fatalf("alias zone mirrored %d records, want 3", len(mirroredRecords(zones[1])))
	}
}

func TestMaterializeAliasesSkipsSourceDNSSECMaterial(t *testing.T) {
	t.Parallel()
	source := aliasSourceFixture()
	source.Records = append(source.Records,
		Record{Name: "@", Type: "DNSKEY", TTL: 300, Value: "257 3 15 oJB1W6WNGAtEZoBFmDXxHdaJ0nQdzYcM1BLHZUFzOnc="},
		Record{Name: "@", Type: "NSEC", TTL: 300, Value: "www.example.test. NS SOA RRSIG NSEC DNSKEY"},
	)
	zones := []Zone{source, aliasFixture("example.test")}
	if err := MaterializeAliases(&zones, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, record := range mirroredRecords(zones[1]) {
		if record.Type == "DNSKEY" || record.Type == "NSEC" {
			t.Fatalf("alias zone mirrored source DNSSEC record %s %s", record.Name, record.Type)
		}
	}
}

func TestMaterializeAliasesReanchorsFullyQualifiedOwners(t *testing.T) {
	t.Parallel()
	source := aliasSourceFixture()
	source.Records = append(source.Records,
		Record{Name: "shop.example.test.", Type: "A", TTL: 300, Value: "192.0.2.30"},
		Record{Name: "elsewhere.example.net.", Type: "A", TTL: 300, Value: "192.0.2.40"},
	)
	zones := []Zone{source, aliasFixture("example.test")}
	if err := MaterializeAliases(&zones, time.Now()); err != nil {
		t.Fatal(err)
	}
	mirrored := mirroredRecords(zones[1])
	if !slices.ContainsFunc(mirrored, func(record Record) bool { return record.Name == "shop" && record.Value == "192.0.2.30" }) {
		t.Fatalf("a fully qualified owner inside the source zone was not re-anchored: %#v", mirrored)
	}
	if slices.ContainsFunc(mirrored, func(record Record) bool { return record.Value == "192.0.2.40" }) {
		t.Fatalf("an owner outside the source zone was mirrored: %#v", mirrored)
	}
}

func TestMaterializeAliasesReplacesEveryRecordWhenTheSourceChanges(t *testing.T) {
	t.Parallel()
	first := aliasSourceFixture()
	second := Zone{
		Name: "example.org", Type: "primary", DefaultTTL: 300, ZoneTransfer: "deny",
		Records: []Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.org. hostmaster.example.org. 1 3600 600 1209600 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.org."},
			{Name: "api", Type: "A", TTL: 300, Value: "198.51.100.7"},
		},
	}
	zones := []Zone{first, second, aliasFixture("example.test")}
	if err := MaterializeAliases(&zones, time.Now()); err != nil {
		t.Fatal(err)
	}
	zones[2].AliasZone = "example.org"
	if err := MaterializeAliases(&zones, time.Now()); err != nil {
		t.Fatal(err)
	}
	mirrored := mirroredRecords(zones[2])
	if slices.ContainsFunc(mirrored, func(record Record) bool { return record.Value == "192.0.2.10" }) {
		t.Fatalf("records from the previous source survived the switch: %#v", mirrored)
	}
	if !slices.ContainsFunc(mirrored, func(record Record) bool { return record.Name == "api" }) {
		t.Fatalf("records from the new source are missing: %#v", mirrored)
	}
}

func TestValidateAllRejectsUnusableAliasSources(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		zones []Zone
		want  string
	}{
		"missing source": {
			zones: []Zone{aliasFixture("")},
			want:  `must name the zone it mirrors`,
		},
		"self reference": {
			zones: []Zone{func() Zone { alias := aliasFixture("example.lan"); return alias }()},
			want:  `cannot mirror itself`,
		},
		"unknown source": {
			zones: []Zone{aliasFixture("absent.test")},
			want:  `mirrors unknown zone`,
		},
		"chained alias": {
			zones: []Zone{
				aliasSourceFixture(),
				func() Zone { alias := aliasFixture("example.test"); alias.Name = "first.lan"; return alias }(),
				func() Zone { alias := aliasFixture("first.lan"); alias.Name = "second.lan"; return alias }(),
			},
			want: `can only mirror a primary or secondary zone`,
		},
		"source names an alias on a non-alias zone": {
			zones: []Zone{func() Zone {
				source := aliasSourceFixture()
				source.AliasZone = "somewhere.test"
				return source
			}()},
			want: `only alias zones may name a source zone`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			zones := Clone(test.zones)
			// Normalize clears AliasZone for non-alias zones, so the case that
			// checks that rule has to reach validation unnormalized.
			if name != "source names an alias on a non-alias zone" {
				NormalizeAll(zones)
			}
			_ = MaterializeAliases(&zones, time.Now())
			err := ValidateAll(zones, nil)
			if err == nil || !regexp.MustCompile(test.want).MatchString(err.Error()) {
				t.Fatalf("ValidateAll() = %v, want an error matching %q", err, test.want)
			}
		})
	}
}

// TestManagerKeepsAliasZonesInStepWithTheirSource exercises the wiring the
// application uses: mirroring runs in the manager's prepare hook, so an alias
// zone that only holds its own SOA on disk still passes validation and follows
// every later change to its source.
func TestManagerKeepsAliasZonesInStepWithTheirSource(t *testing.T) {
	t.Parallel()
	repository := &memoryRepository{zones: []Zone{aliasSourceFixture(), aliasFixture("example.test")}}
	manager, err := NewManager(
		context.Background(), repository,
		func(_ context.Context, zones *[]Zone) error { return MaterializeAliases(zones, time.Now()) },
		func(zones []Zone) error { return ValidateAll(zones, nil) },
		nil,
	)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	alias := findTestZone(t, manager.Current().Zones, "example.lan")
	if len(mirroredRecords(alias)) != 2 {
		t.Fatalf("alias zone mirrored %d records at load, want 2", len(mirroredRecords(alias)))
	}
	before := zoneSerial(t, alias)

	err = manager.UpdateZones(context.Background(), func(zones *[]Zone) error {
		source := findTestZonePointer(t, zones, "example.test")
		source.Records = append(source.Records, Record{Name: "vpn", Type: "A", TTL: 300, Value: "192.0.2.77"})
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateZones() error = %v", err)
	}
	alias = findTestZone(t, manager.Current().Zones, "example.lan")
	if !slices.ContainsFunc(mirroredRecords(alias), func(record Record) bool { return record.Name == "vpn" }) {
		t.Fatalf("alias zone did not follow its source: %#v", alias.Records)
	}
	if serial := zoneSerial(t, alias); serial <= before {
		t.Fatalf("alias serial = %d after the source changed, want more than %d", serial, before)
	}
}

func findTestZone(t *testing.T, zones []Zone, name string) Zone {
	t.Helper()
	index := slices.IndexFunc(zones, func(current Zone) bool { return current.Name == name })
	if index < 0 {
		t.Fatalf("zone %q is missing from the catalog", name)
	}
	return zones[index]
}

func findTestZonePointer(t *testing.T, zones *[]Zone, name string) *Zone {
	t.Helper()
	index := slices.IndexFunc(*zones, func(current Zone) bool { return current.Name == name })
	if index < 0 {
		t.Fatalf("zone %q is missing from the catalog", name)
	}
	return &(*zones)[index]
}

func zoneSerial(t *testing.T, current Zone) uint64 {
	t.Helper()
	for _, record := range current.Records {
		if record.Name != "@" || record.Type != "SOA" {
			continue
		}
		fields := strings.Fields(record.Value)
		if len(fields) != 7 {
			t.Fatalf("zone %q has a malformed SOA %q", current.Name, record.Value)
		}
		serial, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		return serial
	}
	t.Fatalf("zone %q has no apex SOA", current.Name)
	return 0
}
