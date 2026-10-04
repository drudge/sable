package zone

import "testing"

func TestCatalogReconciliationPreservesSecondaryForwarder(t *testing.T) {
	current := Zone{Name: "example.test", Type: TypeSecondaryForwarder, CatalogMemberID: "old", Records: []Record{{Name: "@", Type: "FWD", Value: "udp 0 this-server"}}}
	catalog := Zone{Name: "catalog.test", Type: "catalog", PrimaryServers: []string{"192.0.2.53:53"}, PrimaryProtocol: "tcp"}
	member := CatalogMember{Label: "old", Zone: current.Name}
	applyCatalogMembership(&current, catalog, member)
	if current.Type != TypeSecondaryForwarder || len(current.Records) != 1 || current.CatalogZone != catalog.Name {
		t.Fatalf("reconciliation lost forwarding state: %+v", current)
	}
	member.Label = "new"
	applyCatalogMembership(&current, catalog, member)
	if current.Type != TypeSecondaryForwarder || !AwaitingFirstTransfer(current) {
		t.Fatalf("replaced member did not await a new transfer: %+v", current)
	}
}

func TestValidateAllAllowsDynamicUpdatesOnForwarderZones(t *testing.T) {
	t.Parallel()
	forwarder := Zone{
		Name: "private.test", Type: "forwarder", DefaultTTL: 300, ZoneTransfer: "deny",
		TSIGKey: "update-key.", DynamicUpdates: true,
		Records: []Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.private.test. hostmaster.private.test. 1 3600 600 1209600 300"},
			{Name: "@", Type: "FWD", TTL: 300, Value: "udp 0 10.2.0.245:53"},
		},
	}
	if err := ValidateAll([]Zone{forwarder}, []string{"update-key."}); err != nil {
		t.Fatalf("ValidateAll() rejected dynamic updates on a forwarder zone: %v", err)
	}
	forwarder.TSIGKey = ""
	if err := ValidateAll([]Zone{forwarder}, []string{"update-key."}); err == nil {
		t.Fatal("ValidateAll() accepted forwarder dynamic updates without a TSIG key")
	}
}

func TestAcceptsDynamicUpdates(t *testing.T) {
	t.Parallel()
	for kind, want := range map[string]bool{
		"primary": true, "forwarder": true,
		"secondary": false, TypeSecondaryForwarder: false, "stub": false, "alias": false, "catalog": false,
	} {
		if got := AcceptsDynamicUpdates(kind); got != want {
			t.Errorf("AcceptsDynamicUpdates(%q) = %t, want %t", kind, got, want)
		}
	}
}
