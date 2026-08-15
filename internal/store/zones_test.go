package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/drudge/sable/internal/zone"
)

func TestZoneStoreMigratesLegacyRecordTable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "legacy-zones.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE sable_zone_records (
    zone_name TEXT NOT NULL,
    ordinal BIGINT NOT NULL,
    owner_name TEXT NOT NULL,
    record_type TEXT NOT NULL,
    record_value TEXT NOT NULL,
    ttl BIGINT NOT NULL,
    comments TEXT NOT NULL,
    disabled BOOLEAN NOT NULL,
    expires_at_ns BIGINT,
    PRIMARY KEY (zone_name, ordinal)
);
INSERT INTO sable_zone_records
    (zone_name, ordinal, owner_name, record_type, record_value, ttl, comments, disabled)
VALUES ('legacy.test', 0, '@', 'A', '192.0.2.10', 300, '', FALSE)`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	storage, err := Open(ctx, "sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	var recordKey string
	if err := storage.database.QueryRowContext(ctx,
		"SELECT record_key FROM sable_zone_records WHERE zone_name = ? AND ordinal = ?",
		"legacy.test", 0,
	).Scan(&recordKey); err != nil {
		storage.Close()
		t.Fatal(err)
	}
	wantKey := zoneRecordKey(zone.Record{Name: "@", Type: "A", Value: "192.0.2.10", TTL: 300})
	if recordKey != wantKey {
		storage.Close()
		t.Fatalf("record key = %q, want %q", recordKey, wantKey)
	}
	if _, err := storage.ReplaceZones(ctx, nil, []zone.Zone{testStoredZone(1)}); err != nil {
		storage.Close()
		t.Fatalf("write after migration: %v", err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening proves the schema upgrade and index creation are idempotent.
	storage, err = Open(ctx, "sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
}

func TestZoneStoreCompletesPartialRecordKeyMigration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "partial-zone-migration.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE sable_zone_records (
    zone_name TEXT NOT NULL,
    ordinal BIGINT NOT NULL,
    owner_name TEXT NOT NULL,
    record_type TEXT NOT NULL,
    record_value TEXT NOT NULL,
    ttl BIGINT NOT NULL,
    comments TEXT NOT NULL,
    disabled BOOLEAN NOT NULL,
    expires_at_ns BIGINT,
    record_key TEXT,
    PRIMARY KEY (zone_name, ordinal)
);
INSERT INTO sable_zone_records
    (zone_name, ordinal, owner_name, record_type, record_value, ttl, comments, disabled, record_key)
VALUES ('partial.test', 0, 'www', 'AAAA', '2001:db8::10', 600, '', FALSE, NULL)`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	storage, err := Open(ctx, "sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	var recordKey string
	if err := storage.database.QueryRowContext(ctx,
		"SELECT record_key FROM sable_zone_records WHERE zone_name = ? AND ordinal = ?",
		"partial.test", 0,
	).Scan(&recordKey); err != nil {
		t.Fatal(err)
	}
	if want := zoneRecordKey(zone.Record{Name: "www", Type: "AAAA", Value: "2001:db8::10", TTL: 600}); recordKey != want {
		t.Fatalf("record key = %q, want %q", recordKey, want)
	}
}

func TestZoneStorePersistsAtomicPerZoneRevisions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	storage, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "zones.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	created, err := storage.ReplaceZones(ctx, nil, []zone.Zone{testStoredZone(2)})
	if err != nil {
		t.Fatal(err)
	}
	if created[0].Revision != 1 {
		t.Fatalf("created revision = %d, want 1", created[0].Revision)
	}
	if created[0].ID == "" {
		t.Fatal("created zone has no immutable ID")
	}
	loaded, err := storage.ListZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, created) {
		t.Fatalf("loaded zone differs:\n got %#v\nwant %#v", loaded, created)
	}

	updated := zone.Clone(loaded)
	updated[0].Records[2].Value = "192.0.2.99"
	updated, err = storage.ReplaceZones(ctx, loaded, updated)
	if err != nil {
		t.Fatal(err)
	}
	if updated[0].Revision != 2 {
		t.Fatalf("updated revision = %d, want 2", updated[0].Revision)
	}
	if updated[0].ID != created[0].ID {
		t.Fatalf("zone ID changed during update: got %q want %q", updated[0].ID, created[0].ID)
	}
	unchanged, err := storage.ReplaceZones(ctx, updated, zone.Clone(updated))
	if err != nil {
		t.Fatal(err)
	}
	if unchanged[0].Revision != 2 {
		t.Fatalf("unchanged revision = %d, want 2", unchanged[0].Revision)
	}

	var revisions int
	if err := storage.database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sable_zone_revisions WHERE zone_name = ?", "example.test",
	).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	if revisions != 2 {
		t.Fatalf("stored revisions = %d, want 2", revisions)
	}
	if _, err := storage.ReplaceZones(ctx, unchanged, nil); err != nil {
		t.Fatal(err)
	}
	remaining, err := storage.ListZones(ctx)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("zones after delete = %#v, %v", remaining, err)
	}
}

func TestZoneStoreRollsBackInvalidRecordBatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	storage, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "zones.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	created, err := storage.ReplaceZones(ctx, nil, []zone.Zone{testStoredZone(1)})
	if err != nil {
		t.Fatal(err)
	}
	invalid := zone.Clone(created)
	duplicate := testStoredZone(1)
	duplicate.Name = "duplicate.test"
	invalid = append(invalid, duplicate, duplicate)
	// Force a duplicate-primary-key failure inside the transaction.
	if _, err := storage.ReplaceZones(ctx, created, invalid); err == nil {
		t.Fatal("ReplaceZones() accepted an empty primary key")
	}
	loaded, err := storage.ListZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, created) {
		t.Fatalf("rollback changed durable zone: got %#v want %#v", loaded, created)
	}
}

func BenchmarkZoneStoreLoadTenThousandRecords(b *testing.B) {
	ctx := context.Background()
	storage, err := Open(ctx, "sqlite", filepath.Join(b.TempDir(), "zones.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer storage.Close()
	configured := testStoredZone(10_000)
	if _, err := storage.ReplaceZones(ctx, nil, []zone.Zone{configured}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		zones, err := storage.ListZones(ctx)
		if err != nil || len(zones) != 1 || len(zones[0].Records) != 10_002 {
			b.Fatalf("ListZones() = %d zones, %v", len(zones), err)
		}
	}
}

func testStoredZone(addressRecords int) zone.Zone {
	records := []zone.Record{
		{Name: "@", Type: "SOA", Value: "ns1.example.test. hostmaster.example.test. 1 3600 600 1209600 300", TTL: 300},
		{Name: "@", Type: "NS", Value: "ns1.example.test.", TTL: 300},
	}
	for index := range addressRecords {
		records = append(records, zone.Record{
			Name: fmt.Sprintf("host-%05d", index), Type: "A",
			Value: fmt.Sprintf("192.0.2.%d", index%254+1), TTL: 300,
			Comments: "benchmark", ExpiresAt: time.Time{},
		})
	}
	return zone.Zone{
		Name: "example.test", Type: "primary", DefaultTTL: 300, ZoneTransfer: "deny",
		Records: records,
	}
}

func TestZoneStoreAddsDNSSECValidationColumnToExistingDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "validation-zones.db")
	storage, err := Open(ctx, "sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.database.ExecContext(ctx,
		"ALTER TABLE sable_zones DROP COLUMN dnssec_validation_disabled"); err != nil {
		storage.Close()
		t.Fatalf("simulate pre-upgrade schema: %v", err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	storage, err = Open(ctx, "sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	forwarder := zone.Zone{
		Name: "private.test", Type: "forwarder", DefaultTTL: 300, ZoneTransfer: "deny",
		DNSSECValidationDisabled: true,
		Records: []zone.Record{
			{Name: "@", Type: "SOA", Value: "ns1.private.test. hostmaster.private.test. 1 3600 600 1209600 300", TTL: 300},
			{Name: "@", Type: "FWD", Value: "udp 0 10.2.0.245:53", TTL: 300},
		},
	}
	if _, err := storage.ReplaceZones(ctx, nil, []zone.Zone{forwarder}); err != nil {
		t.Fatal(err)
	}
	stored, err := storage.ListZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || !stored[0].DNSSECValidationDisabled {
		t.Fatalf("stored zones = %#v, want the DNSSEC validation opt-out preserved", stored)
	}
	updated := zone.Clone(stored)
	updated[0].DNSSECValidationDisabled = false
	if _, err := storage.ReplaceZones(ctx, stored, updated); err != nil {
		t.Fatal(err)
	}
	reread, err := storage.ListZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(reread) != 1 || reread[0].DNSSECValidationDisabled {
		t.Fatalf("updated zones = %#v, want validation re-enabled", reread)
	}
}

func TestZoneStoreAddsRecordSourceColumnToExistingDatabase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "source-zones.db")
	storage, err := Open(ctx, "sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.database.ExecContext(ctx,
		"ALTER TABLE sable_zone_records DROP COLUMN source"); err != nil {
		storage.Close()
		t.Fatalf("simulate pre-upgrade schema: %v", err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	storage, err = Open(ctx, "sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	synchronized := zone.Zone{
		Name: "clients.example.test", Type: "primary", DefaultTTL: 300, ZoneTransfer: "deny",
		Records: []zone.Record{
			{Name: "@", Type: "SOA", Value: "ns1.clients.example.test. hostmaster.clients.example.test. 1 3600 600 1209600 300", TTL: 300},
			{Name: "@", Type: "NS", Value: "ns1.clients.example.test.", TTL: 300},
			{Name: "printer", Type: "A", Value: "192.0.2.10", TTL: 300, Source: zone.SourceUniFi},
			{Name: "nas", Type: "A", Value: "192.0.2.20", TTL: 300},
		},
	}
	if _, err := storage.ReplaceZones(ctx, nil, []zone.Zone{synchronized}); err != nil {
		t.Fatal(err)
	}
	stored, err := storage.ListZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sources := make(map[string]string, len(stored[0].Records))
	for _, record := range stored[0].Records {
		sources[record.Name] = record.Source
	}
	if sources["printer"] != zone.SourceUniFi {
		t.Fatalf("printer source = %q, want %q", sources["printer"], zone.SourceUniFi)
	}
	if sources["nas"] != "" {
		t.Fatalf("hand-authored record carries source %q", sources["nas"])
	}

	// Handing a record back to its author must clear the marker, not keep the
	// stale one from the previous row.
	updated := zone.Clone(stored)
	for index := range updated[0].Records {
		if updated[0].Records[index].Name == "printer" {
			updated[0].Records[index].Source = ""
			updated[0].Records[index].Value = "192.0.2.11"
		}
	}
	if _, err := storage.ReplaceZones(ctx, stored, updated); err != nil {
		t.Fatal(err)
	}
	reread, err := storage.ListZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range reread[0].Records {
		if record.Name == "printer" && record.Source != "" {
			t.Fatalf("printer source = %q, want it cleared", record.Source)
		}
	}
}
