package app

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"github.com/drudge/sable/internal/config"
)

func dhcpPrimary(t *testing.T) config.Config {
	t.Helper()
	primary := config.Defaults()
	primary.DHCP = config.DHCP{Scopes: []config.DHCPScope{{
		ID: "lan", Name: "LAN", Subnet: "10.0.7.0/24",
		Ranges: []config.DHCPRange{{Start: "10.0.7.100", End: "10.0.7.199"}},
	}}}
	if err := primary.DHCP.Validate(); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return primary
}

// A member that predates DHCP decodes the snapshot strictly, so while DHCP is
// unused the section must not be in it.
func TestReplicatedSnapshotLeavesOutUnusedDHCP(t *testing.T) {
	encoded, err := toml.Marshal(replicatedRuntimeConfiguration(config.Defaults()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "dhcp") {
		t.Fatalf("snapshot mentions dhcp while it is unset:\n%s", encoded)
	}
	decoder := toml.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(snapshotBeforeDHCP()); err != nil {
		t.Fatalf("a member without DHCP can't decode the snapshot: %v", err)
	}
}

func TestReplicatedSnapshotCarriesDHCPScopes(t *testing.T) {
	encoded, err := toml.Marshal(replicatedRuntimeConfiguration(dhcpPrimary(t)))
	if err != nil {
		t.Fatal(err)
	}
	var decoded clusterRuntimeConfiguration
	if err := toml.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	candidate := config.Defaults()
	applyReplicatedRuntimeConfiguration(&candidate, decoded)
	if !reflect.DeepEqual(candidate.DHCP, dhcpPrimary(t).DHCP) {
		t.Fatalf("replica dhcp = %+v", candidate.DHCP)
	}
	// The primary removed its last scope: the replica must not keep serving it.
	applyReplicatedRuntimeConfiguration(&candidate, replicatedRuntimeConfiguration(config.Defaults()))
	if !candidate.DHCP.IsZero() {
		t.Fatalf("replica kept scopes the primary removed: %+v", candidate.DHCP)
	}
}

// snapshotBeforeDHCP is the snapshot type as a member without DHCP has it:
// every field but DHCP.
func snapshotBeforeDHCP() any {
	current := reflect.TypeFor[clusterRuntimeConfiguration]()
	var fields []reflect.StructField
	for index := range current.NumField() {
		if field := current.Field(index); field.Name != "DHCP" {
			fields = append(fields, field)
		}
	}
	return reflect.New(reflect.StructOf(fields)).Interface()
}
