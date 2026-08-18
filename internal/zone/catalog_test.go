package zone

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func catalogFixture(t *testing.T, records ...Record) []Record {
	t.Helper()
	return append([]Record{
		{Name: "version", Type: "TXT", TTL: 300, Value: `"2"`},
	}, records...)
}

func TestParseCatalogReadsMembersAndProperties(t *testing.T) {
	records := catalogFixture(t,
		Record{Name: "nj2xg5b.zones", Type: "PTR", TTL: 0, Value: "example.com."},
		Record{Name: "nvxxezj.zones", Type: "PTR", TTL: 0, Value: "example.net."},
		Record{Name: "group.nvxxezj.zones", Type: "TXT", TTL: 0, Value: `"operator-x-foo"`},
		Record{Name: "coo.nvxxezj.zones", Type: "PTR", TTL: 0, Value: "other.catalog."},
	)
	contents, err := ParseCatalog("catalog.invalid", records)
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	if len(contents.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(contents.Members))
	}
	if contents.Members[0].Zone != "example.com" || contents.Members[0].Label != "nj2xg5b" {
		t.Fatalf("unexpected first member %+v", contents.Members[0])
	}
	second := contents.Members[1]
	if second.Zone != "example.net" || second.Group != "operator-x-foo" || second.ChangeOwner != "other.catalog" {
		t.Fatalf("unexpected second member %+v", second)
	}
}

func TestParseCatalogAcceptsFullyQualifiedOwners(t *testing.T) {
	records := []Record{
		{Name: "version.catalog.invalid.", Type: "TXT", TTL: 0, Value: `"2"`},
		{Name: "nj2xg5b.zones.catalog.invalid.", Type: "PTR", TTL: 0, Value: "example.com."},
	}
	contents, err := ParseCatalog("catalog.invalid", records)
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	if len(contents.Members) != 1 || contents.Members[0].Zone != "example.com" {
		t.Fatalf("unexpected members %+v", contents.Members)
	}
}

func TestParseCatalogRejectsBrokenCatalogs(t *testing.T) {
	tests := []struct {
		name    string
		records []Record
		message string
	}{
		{
			name:    "missing version",
			records: []Record{{Name: "nj2xg5b.zones", Type: "PTR", Value: "example.com."}},
			message: "no version property",
		},
		{
			name: "two version records",
			records: []Record{
				{Name: "version", Type: "TXT", Value: `"2"`},
				{Name: "version", Type: "TXT", Value: `"2"`},
			},
			message: "more than one record",
		},
		{
			name:    "unsupported version",
			records: []Record{{Name: "version", Type: "TXT", Value: `"3"`}},
			message: "unsupported catalog schema version",
		},
		{
			name: "duplicate member zone",
			records: catalogFixture(t,
				Record{Name: "aaa.zones", Type: "PTR", Value: "example.com."},
				Record{Name: "bbb.zones", Type: "PTR", Value: "example.com."},
			),
			message: "listed under both",
		},
		{
			name: "member with two pointers",
			records: catalogFixture(t,
				Record{Name: "aaa.zones", Type: "PTR", Value: "example.com."},
				Record{Name: "aaa.zones", Type: "PTR", Value: "example.net."},
			),
			message: "more than one PTR record",
		},
		{
			name: "catalog lists itself",
			records: catalogFixture(t,
				Record{Name: "aaa.zones", Type: "PTR", Value: "catalog.invalid."},
			),
			message: "lists itself",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseCatalog("catalog.invalid", test.records); err == nil {
				t.Fatal("expected a broken catalog error")
			} else if !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected %q in error, got %v", test.message, err)
			}
		})
	}
}

func TestParseCatalogIgnoresDisabledAndUnknownRecords(t *testing.T) {
	records := catalogFixture(t,
		Record{Name: "aaa.zones", Type: "PTR", Value: "example.com."},
		Record{Name: "bbb.zones", Type: "PTR", Value: "example.net.", Disabled: true},
		Record{Name: "sable.ext.aaa.zones", Type: "TXT", Value: `"custom"`},
		Record{Name: "unrelated", Type: "TXT", Value: `"noise"`},
	)
	contents, err := ParseCatalog("catalog.invalid", records)
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	if len(contents.Members) != 1 || contents.Members[0].Zone != "example.com" {
		t.Fatalf("unexpected members %+v", contents.Members)
	}
}

func TestParseCatalogIgnoresAmbiguousChangeOfOwnership(t *testing.T) {
	records := catalogFixture(t,
		Record{Name: "aaa.zones", Type: "PTR", Value: "example.com."},
		Record{Name: "coo.aaa.zones", Type: "PTR", Value: "one.catalog."},
		Record{Name: "coo.aaa.zones", Type: "PTR", Value: "two.catalog."},
	)
	contents, err := ParseCatalog("catalog.invalid", records)
	if err != nil {
		t.Fatalf("parse catalog: %v", err)
	}
	if contents.Members[0].ChangeOwner != "" {
		t.Fatalf("expected the ambiguous handoff to be ignored, got %q", contents.Members[0].ChangeOwner)
	}
}

func TestMaterializeCatalogsPublishesMembers(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	catalog, err := NewCatalog("catalog.invalid", now)
	if err != nil {
		t.Fatalf("new catalog: %v", err)
	}
	member, err := NewPrimary("example.com", 300, "ns1.example.com", "hostmaster@example.com", now)
	if err != nil {
		t.Fatalf("new primary: %v", err)
	}
	member.CatalogZone = "catalog.invalid"
	member.CatalogGroup = "operator-x-foo"
	zones := []Zone{catalog, member}
	if err := MaterializeCatalogs(&zones, now); err != nil {
		t.Fatalf("materialize: %v", err)
	}

	label := MemberLabel("example.com")
	if zones[1].CatalogMemberID != label {
		t.Fatalf("expected member label %q, got %q", label, zones[1].CatalogMemberID)
	}
	contents, err := ParseCatalog("catalog.invalid", zones[0].Records)
	if err != nil {
		t.Fatalf("parse published catalog: %v", err)
	}
	if len(contents.Members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(contents.Members))
	}
	if contents.Members[0].Zone != "example.com" || contents.Members[0].Group != "operator-x-foo" {
		t.Fatalf("unexpected member %+v", contents.Members[0])
	}
}

func TestMaterializeCatalogsIsIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	catalog, _ := NewCatalog("catalog.invalid", now)
	member, _ := NewPrimary("example.com", 300, "ns1.example.com", "hostmaster@example.com", now)
	member.CatalogZone = "catalog.invalid"
	zones := []Zone{catalog, member}
	if err := MaterializeCatalogs(&zones, now); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	first := soaSerial(t, zones[0])
	if err := MaterializeCatalogs(&zones, now); err != nil {
		t.Fatalf("materialize again: %v", err)
	}
	if second := soaSerial(t, zones[0]); second != first {
		t.Fatalf("serial advanced without a membership change: %q then %q", first, second)
	}

	zones[1].CatalogZone = ""
	if err := MaterializeCatalogs(&zones, now); err != nil {
		t.Fatalf("materialize after removal: %v", err)
	}
	if third := soaSerial(t, zones[0]); third == first {
		t.Fatalf("serial did not advance after the member left: %q", third)
	}
	contents, err := ParseCatalog("catalog.invalid", zones[0].Records)
	if err != nil {
		t.Fatalf("parse published catalog: %v", err)
	}
	if len(contents.Members) != 0 {
		t.Fatalf("expected an empty catalog, got %+v", contents.Members)
	}
}

func TestMaterializeCatalogsSkipsDisabledMembers(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	catalog, _ := NewCatalog("catalog.invalid", now)
	member, _ := NewPrimary("example.com", 300, "ns1.example.com", "hostmaster@example.com", now)
	member.CatalogZone = "catalog.invalid"
	member.Disabled = true
	zones := []Zone{catalog, member}
	if err := MaterializeCatalogs(&zones, now); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	contents, err := ParseCatalog("catalog.invalid", zones[0].Records)
	if err != nil {
		t.Fatalf("parse published catalog: %v", err)
	}
	if len(contents.Members) != 0 {
		t.Fatalf("expected a disabled member to stay unpublished, got %+v", contents.Members)
	}
}

func TestMaterializeCatalogsLeavesConsumerLabelsAlone(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	consumer, _ := NewCatalog("catalog.example", now)
	consumer.PrimaryServers = []string{"192.0.2.1"}
	consumer.PrimaryProtocol = "tcp"
	member, _ := NewPrimary("example.com", 300, "ns1.example.com", "hostmaster@example.com", now)
	member.Type = "secondary"
	member.CatalogZone = "catalog.example"
	member.CatalogMemberID = "producerlabel"
	zones := []Zone{consumer, member}
	if err := MaterializeCatalogs(&zones, now); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if zones[1].CatalogMemberID != "producerlabel" {
		t.Fatalf("consumer member label was overwritten with %q", zones[1].CatalogMemberID)
	}
}

func TestMemberLabelIsStableAndLegal(t *testing.T) {
	first := MemberLabel("example.com")
	if first != MemberLabel("EXAMPLE.COM.") {
		t.Fatal("label is not stable across equivalent zone names")
	}
	if first == MemberLabel("example.net") {
		t.Fatal("different zones produced the same label")
	}
	if len(first) == 0 || len(first) > 63 {
		t.Fatalf("label %q is not a legal DNS label length", first)
	}
	for _, character := range first {
		if (character < '0' || character > '9') && (character < 'a' || character > 'z') {
			t.Fatalf("label %q contains an unexpected character %q", first, character)
		}
	}
}

func soaSerial(t *testing.T, current Zone) string {
	t.Helper()
	for _, record := range current.Records {
		if record.Name == "@" && record.Type == "SOA" {
			fields := strings.Fields(record.Value)
			if len(fields) != 7 {
				t.Fatalf("unexpected SOA value %q", record.Value)
			}
			return fields[2]
		}
	}
	t.Fatal("zone has no apex SOA")
	return ""
}

func consumerCatalog(t *testing.T, name string, records ...Record) Zone {
	t.Helper()
	catalog, err := NewCatalog(name, time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new catalog: %v", err)
	}
	catalog.PrimaryServers = []string{"192.0.2.1"}
	catalog.PrimaryProtocol = "tcp"
	catalog.TSIGKey = "transfer.key."
	catalog.Records = append(catalog.Records, catalogFixture(t, records...)...)
	return catalog
}

func findByName(zones []Zone, name string) *Zone {
	for index := range zones {
		if zones[index].Name == name {
			return &zones[index]
		}
	}
	return nil
}

func TestReconcileCatalogsProvisionsMembers(t *testing.T) {
	zones := []Zone{consumerCatalog(t, "catalog.example",
		Record{Name: "aaa.zones", Type: "PTR", Value: "example.com."},
		Record{Name: "group.aaa.zones", Type: "TXT", Value: `"eu"`},
	)}
	events := ReconcileCatalogs(&zones)

	member := findByName(zones, "example.com")
	if member == nil {
		t.Fatal("catalog did not provision the member zone")
	}
	if member.Type != "secondary" {
		t.Fatalf("expected a secondary member, got %q", member.Type)
	}
	if member.CatalogZone != "catalog.example" || member.CatalogGroup != "eu" || member.CatalogMemberID != "aaa" {
		t.Fatalf("unexpected membership on %+v", member)
	}
	if len(member.PrimaryServers) != 1 || member.PrimaryServers[0] != "192.0.2.1" || member.TSIGKey != "transfer.key." {
		t.Fatalf("member did not inherit the catalog transfer settings: %+v", member)
	}
	if !AwaitingFirstTransfer(*member) {
		t.Fatal("a freshly provisioned member should be awaiting its first transfer")
	}
	if len(events) != 1 || events[0].Kind != CatalogMemberAdded || events[0].Zone != "example.com" {
		t.Fatalf("unexpected events %+v", events)
	}
}

func TestReconcileCatalogsWithdrawsMembersItProvisioned(t *testing.T) {
	zones := []Zone{consumerCatalog(t, "catalog.example",
		Record{Name: "aaa.zones", Type: "PTR", Value: "example.com."},
	)}
	ReconcileCatalogs(&zones)
	if findByName(zones, "example.com") == nil {
		t.Fatal("member was not provisioned")
	}

	catalog := findByName(zones, "catalog.example")
	catalog.Records = slices.DeleteFunc(catalog.Records, func(record Record) bool {
		return record.Name == "aaa.zones"
	})
	events := ReconcileCatalogs(&zones)
	if findByName(zones, "example.com") != nil {
		t.Fatal("member was not withdrawn after leaving the catalog")
	}
	if len(events) != 1 || events[0].Kind != CatalogMemberRemoved {
		t.Fatalf("unexpected events %+v", events)
	}
}

func TestReconcileCatalogsNeverTouchesForeignZones(t *testing.T) {
	local, err := NewPrimary("example.com", 300, "ns1.example.com", "hostmaster@example.com", time.Now())
	if err != nil {
		t.Fatalf("new primary: %v", err)
	}
	zones := []Zone{
		consumerCatalog(t, "catalog.example", Record{Name: "aaa.zones", Type: "PTR", Value: "example.com."}),
		local,
	}
	events := ReconcileCatalogs(&zones)

	member := findByName(zones, "example.com")
	if member == nil {
		t.Fatal("the locally configured zone was removed")
	}
	if member.Type != "primary" || member.CatalogZone != "" {
		t.Fatalf("the locally configured zone was adopted: %+v", member)
	}
	if len(events) != 1 || events[0].Kind != CatalogMemberConflict {
		t.Fatalf("expected a conflict event, got %+v", events)
	}
}

func TestReconcileCatalogsLeavesEverythingAloneWhenBroken(t *testing.T) {
	zones := []Zone{consumerCatalog(t, "catalog.example",
		Record{Name: "aaa.zones", Type: "PTR", Value: "example.com."},
	)}
	ReconcileCatalogs(&zones)
	if findByName(zones, "example.com") == nil {
		t.Fatal("member was not provisioned")
	}

	// A truncated or malformed transfer must never tear down live zones.
	catalog := findByName(zones, "catalog.example")
	catalog.Records = slices.DeleteFunc(catalog.Records, func(record Record) bool {
		return record.Name == "version"
	})
	events := ReconcileCatalogs(&zones)
	if findByName(zones, "example.com") == nil {
		t.Fatal("a broken catalog removed a member it had provisioned")
	}
	if len(events) != 1 || events[0].Kind != CatalogBroken {
		t.Fatalf("expected a broken-catalog event, got %+v", events)
	}
}

func TestReconcileCatalogsRefusesTakeoverWithoutChangeOfOwnership(t *testing.T) {
	zones := []Zone{
		consumerCatalog(t, "one.catalog", Record{Name: "aaa.zones", Type: "PTR", Value: "example.com."}),
		consumerCatalog(t, "two.catalog", Record{Name: "bbb.zones", Type: "PTR", Value: "example.com."}),
	}
	events := ReconcileCatalogs(&zones)

	member := findByName(zones, "example.com")
	if member == nil {
		t.Fatal("member was not provisioned")
	}
	if member.CatalogZone != "one.catalog" {
		t.Fatalf("member changed hands without a coo property: %+v", member)
	}
	if !slices.ContainsFunc(events, func(event CatalogEvent) bool { return event.Kind == CatalogMemberConflict }) {
		t.Fatalf("expected a conflict event, got %+v", events)
	}
}

func TestReconcileCatalogsHandsOverMemberOnChangeOfOwnership(t *testing.T) {
	zones := []Zone{
		consumerCatalog(t, "one.catalog",
			Record{Name: "aaa.zones", Type: "PTR", Value: "example.com."},
			Record{Name: "coo.aaa.zones", Type: "PTR", Value: "two.catalog."},
		),
		consumerCatalog(t, "two.catalog", Record{Name: "bbb.zones", Type: "PTR", Value: "example.com."}),
	}
	events := ReconcileCatalogs(&zones)

	member := findByName(zones, "example.com")
	if member == nil {
		t.Fatal("member disappeared during the handoff")
	}
	if member.CatalogZone != "two.catalog" || member.CatalogMemberID != "bbb" {
		t.Fatalf("member was not handed over: %+v", member)
	}
	if !slices.ContainsFunc(events, func(event CatalogEvent) bool { return event.Kind == CatalogMemberHandedOver }) {
		t.Fatalf("expected a handover event, got %+v", events)
	}

	// The old catalog keeps listing the member until its producer drops the
	// entry. That is the normal end of a handoff, so it must stay quiet rather
	// than warn about a conflict on every refresh.
	settled := ReconcileCatalogs(&zones)
	if slices.ContainsFunc(settled, func(event CatalogEvent) bool { return event.Kind == CatalogMemberConflict }) {
		t.Fatalf("a settled handoff still reports a conflict: %+v", settled)
	}
	if findByName(zones, "example.com").CatalogZone != "two.catalog" {
		t.Fatal("the member drifted back to the old catalog")
	}
}

func TestReconcileCatalogsRefetchesOnMemberLabelChange(t *testing.T) {
	zones := []Zone{consumerCatalog(t, "catalog.example",
		Record{Name: "aaa.zones", Type: "PTR", Value: "example.com."},
	)}
	ReconcileCatalogs(&zones)
	member := findByName(zones, "example.com")
	member.Records = []Record{{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.com. hostmaster.example.com. 7 3600 600 1209600 300"}}

	catalog := findByName(zones, "catalog.example")
	for index := range catalog.Records {
		if catalog.Records[index].Name == "aaa.zones" {
			catalog.Records[index].Name = "ccc.zones"
		}
	}
	ReconcileCatalogs(&zones)

	member = findByName(zones, "example.com")
	if member == nil {
		t.Fatal("member disappeared after its label changed")
	}
	if member.CatalogMemberID != "ccc" {
		t.Fatalf("expected the new label, got %q", member.CatalogMemberID)
	}
	if len(member.Records) != 0 {
		t.Fatal("a changed member label must force a fresh transfer")
	}
}

func TestReconcileCatalogsIgnoresDisabledCatalogs(t *testing.T) {
	catalog := consumerCatalog(t, "catalog.example",
		Record{Name: "aaa.zones", Type: "PTR", Value: "example.com."},
	)
	catalog.Disabled = true
	zones := []Zone{catalog}
	if events := ReconcileCatalogs(&zones); len(events) != 0 {
		t.Fatalf("a disabled catalog was processed: %+v", events)
	}
	if findByName(zones, "example.com") != nil {
		t.Fatal("a disabled catalog provisioned a member")
	}
}

// TestCatalogRoundTripsBetweenProducerAndConsumer is the interop check that
// matters: whatever the publishing side writes must be exactly what the
// subscribing side can read back.
func TestCatalogRoundTripsBetweenProducerAndConsumer(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	producerCatalog, _ := NewCatalog("catalog.invalid", now)
	first, _ := NewPrimary("example.com", 300, "ns1.example.com", "hostmaster@example.com", now)
	first.CatalogZone = "catalog.invalid"
	first.CatalogGroup = "operator-x-foo"
	second, _ := NewPrimary("example.net", 300, "ns1.example.net", "hostmaster@example.net", now)
	second.CatalogZone = "catalog.invalid"

	published := []Zone{producerCatalog, first, second}
	NormalizeAll(published)
	if err := MaterializeCatalogs(&published, now); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	NormalizeAll(published)
	if err := ValidateAll(published, nil); err != nil {
		t.Fatalf("published catalog does not validate: %v", err)
	}

	// The subscriber receives exactly the records the publisher serves.
	subscribed := findByName(published, "catalog.invalid")
	consumer := Zone{
		Name: "catalog.invalid", Type: "catalog", DefaultTTL: 300,
		PrimaryServers: []string{"192.0.2.1"}, PrimaryProtocol: "tcp",
		Records: slices.Clone(subscribed.Records),
	}
	consumed := []Zone{consumer}
	NormalizeAll(consumed)
	events := ReconcileCatalogs(&consumed)

	for _, name := range []string{"example.com", "example.net"} {
		member := findByName(consumed, name)
		if member == nil {
			t.Fatalf("the subscriber did not provision %q", name)
		}
		if member.Type != "secondary" || member.CatalogZone != "catalog.invalid" {
			t.Fatalf("unexpected provisioned member %+v", member)
		}
	}
	if group := findByName(consumed, "example.com").CatalogGroup; group != "operator-x-foo" {
		t.Fatalf("the group property did not survive the round trip, got %q", group)
	}
	if len(events) != 2 {
		t.Fatalf("expected two provisioning events, got %+v", events)
	}
	NormalizeAll(consumed)
	if err := ValidateAll(consumed, nil); err != nil {
		t.Fatalf("the provisioned zone set does not validate: %v", err)
	}
}

func TestCatalogZonesRejectUnsupportedFeatures(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	base, _ := NewCatalog("catalog.invalid", now)

	tests := map[string]func(*Zone){
		"signing":         func(current *Zone) { current.DNSSEC = true },
		"dynamic updates": func(current *Zone) { current.DynamicUpdates = true; current.TSIGKey = "key." },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Records = slices.Clone(base.Records)
			mutate(&candidate)
			zones := []Zone{candidate}
			NormalizeAll(zones)
			if err := ValidateAll(zones, []string{"key."}); err == nil {
				t.Fatalf("a catalog zone with %s was accepted", name)
			}
		})
	}
}

func TestCatalogZonesCannotMirrorAnotherZone(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	catalog, _ := NewCatalog("catalog.invalid", now)
	catalog.AliasZone = "example.com"
	catalog.CatalogZone = "other.invalid"

	zones := []Zone{catalog}
	NormalizeAll(zones)
	if zones[0].AliasZone != "" {
		t.Fatal("a catalog zone kept a mirror source")
	}
	if zones[0].CatalogZone != "" {
		t.Fatal("a catalog zone kept a membership of its own")
	}
}

func TestCatalogMembershipRequiresACatalogZone(t *testing.T) {
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	member, _ := NewPrimary("example.com", 300, "ns1.example.com", "hostmaster@example.com", now)
	member.CatalogZone = "catalog.invalid"

	zones := []Zone{member}
	NormalizeAll(zones)
	if err := ValidateAll(zones, nil); err == nil {
		t.Fatal("membership of a zone that does not exist was accepted")
	}

	other, _ := NewPrimary("catalog.invalid", 300, "ns1.catalog.invalid", "hostmaster@catalog.invalid", now)
	zones = []Zone{member, other}
	NormalizeAll(zones)
	if err := ValidateAll(zones, nil); err == nil {
		t.Fatal("membership of a zone that is not a catalog was accepted")
	}
}
