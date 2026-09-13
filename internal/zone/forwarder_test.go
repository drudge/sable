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
