package app

import (
	"context"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/zone"
)

func TestPrepareRecoveryAdvancesOnlySerialsSableOwns(t *testing.T) {
	soa := func(serial string) []zone.Record {
		return []zone.Record{
			{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.com. hostmaster.example.com. " + serial + " 3600 600 604800 300"},
			{Name: "@", Type: "NS", TTL: 300, Value: "ns1.example.com."},
		}
	}
	owned := zone.Zone{ID: "owned", Name: "example.com", Type: "primary", DefaultTTL: 300, Records: soa("2026110804")}
	transferred := zone.Zone{
		ID: "transferred", Name: "example.net", Type: "secondary", DefaultTTL: 300,
		PrimaryServers: []string{"192.0.2.53"}, Records: soa("7"),
	}
	zones := newTestZoneManager(t, []zone.Zone{owned, transferred})
	replicator := newClusterStateReplicator(newTestConfigurationManager(t, config.Defaults()), zones, nil, newTestTSIGStore(), newTestUniFiCredentials(), newTestOIDCSecrets())
	if err := replicator.PrepareRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, current := range zones.CurrentRef().Zones {
		serial := ""
		for _, record := range current.Records {
			if record.Type == "SOA" {
				serial = strings.Fields(record.Value)[2]
			}
		}
		want := map[string]string{"owned": "2026110904", "transferred": "7"}[current.ID]
		if serial != want {
			t.Fatalf("%s serial after recovery = %s, want %s", current.Name, serial, want)
		}
	}
}
