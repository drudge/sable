package app

import (
	"context"
	"testing"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/zone"
)

func restoreSerialZones(primarySerial, secondarySerial, address string) []zone.Zone {
	soa := func(serial string) zone.Record {
		return zone.Record{Name: "@", Type: "SOA", TTL: 300, Value: "ns1.example.test. hostmaster.example.test. " + serial + " 3600 600 604800 300"}
	}
	return []zone.Zone{
		{ID: "zone-1", Name: "example.test", Type: "primary", DefaultTTL: 300, Records: []zone.Record{
			soa(primarySerial), {Name: "www", Type: "A", TTL: 300, Value: address},
		}},
		{ID: "zone-2", Name: "upstream.test", Type: "secondary", DefaultTTL: 300,
			PrimaryServers: []string{"192.0.2.53"}, Records: []zone.Record{soa(secondarySerial)}},
	}
}

func replaceRestoreSerialZones(t *testing.T, configurationPath string, next []zone.Zone) {
	t.Helper()
	ctx := context.Background()
	configuration, err := config.Load(configurationPath)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	database, err := store.Open(ctx, configuration.Database.Driver, configuration.Database.DSN)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	defer database.Close()
	current, err := database.ListZones(ctx)
	if err != nil {
		t.Fatalf("ListZones() error = %v", err)
	}
	if _, err := database.ReplaceZones(ctx, current, next); err != nil {
		t.Fatalf("ReplaceZones() error = %v", err)
	}
}

func listRestoreSerialZones(t *testing.T, configurationPath string) map[string]zone.Zone {
	t.Helper()
	ctx := context.Background()
	configuration, err := config.Load(configurationPath)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	database, err := store.Open(ctx, configuration.Database.Driver, configuration.Database.DSN)
	if err != nil {
		t.Fatalf("store.Open() error = %v", err)
	}
	defer database.Close()
	zones, err := database.ListZones(ctx)
	if err != nil {
		t.Fatalf("ListZones() error = %v", err)
	}
	byName := make(map[string]zone.Zone, len(zones))
	for _, current := range zones {
		byName[current.Name] = current
	}
	return byName
}

// TestRestoreMovesZoneSerialsPastTheDisplacedZones restores an older backup
// over a node that has since published newer serials (#590). The content
// goes back, but each zone Sable issues must come back under a serial
// greater than the one it displaced, or secondaries never transfer it.
func TestRestoreMovesZoneSerialsPastTheDisplacedZones(t *testing.T) {
	ctx := context.Background()
	configurationPath := newBackupDeployment(t)
	replaceRestoreSerialZones(t, configurationPath, restoreSerialZones("2026110805", "50", "192.0.2.5"))
	sealed, err := CreateBackup(ctx, BackupOptions{ConfigurationPath: configurationPath, Passphrase: backupTestPassphrase})
	if err != nil {
		t.Fatalf("CreateBackup() error = %v", err)
	}
	replaceRestoreSerialZones(t, configurationPath, restoreSerialZones("2026110807", "60", "192.0.2.7"))

	if _, err := RestoreBackup(ctx, RestoreOptions{
		ConfigurationPath: configurationPath, Contents: sealed,
		Passphrase: backupTestPassphrase, KeepConfiguration: true,
	}); err != nil {
		t.Fatalf("RestoreBackup() error = %v", err)
	}

	zones := listRestoreSerialZones(t, configurationPath)
	primary := zones["example.test"]
	if serial, _ := zone.Serial(primary); int32(serial-2026110807) <= 0 {
		t.Fatalf("restored primary serial = %d, want past the displaced 2026110807", serial)
	}
	if got := primary.Records[1].Value; got != "192.0.2.5" {
		t.Fatalf("restored www = %q, want the backup's 192.0.2.5", got)
	}
	if serial, _ := zone.Serial(zones["upstream.test"]); serial != 50 {
		t.Fatalf("restored secondary serial = %d, want the backup's 50 (its upstream owns it)", serial)
	}
}
