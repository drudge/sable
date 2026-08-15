package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/drudge/sable/internal/zone"
)

const retainedZoneRevisions = 128

func (store *Store) zoneTables() []string {
	return []string{`
CREATE TABLE IF NOT EXISTS sable_zones (
	id TEXT NOT NULL UNIQUE,
    name TEXT PRIMARY KEY,
    zone_type TEXT NOT NULL,
    default_ttl BIGINT NOT NULL,
    disabled BOOLEAN NOT NULL,
    zone_transfer TEXT NOT NULL,
    transfer_acl TEXT NOT NULL,
    notify_targets TEXT NOT NULL,
    primary_servers TEXT NOT NULL,
    primary_protocol TEXT NOT NULL,
    tsig_key TEXT NOT NULL,
    dynamic_updates BOOLEAN NOT NULL,
    dnssec BOOLEAN NOT NULL,
    dnssec_algorithm TEXT NOT NULL,
    dnssec_denial TEXT NOT NULL,
    nsec3_iterations BIGINT NOT NULL,
    nsec3_salt TEXT NOT NULL,
    zsk_lifetime_ns BIGINT NOT NULL,
    ksk_lifetime_ns BIGINT NOT NULL,
    key_prepublish_ns BIGINT NOT NULL,
    key_retire_after_ns BIGINT NOT NULL,
    parent_ds_key_tag BIGINT NOT NULL,
    revision BIGINT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
)`, `
CREATE TABLE IF NOT EXISTS sable_zone_records (
    zone_name TEXT NOT NULL REFERENCES sable_zones(name) ON DELETE CASCADE,
    record_key TEXT NOT NULL,
    ordinal BIGINT NOT NULL,
    owner_name TEXT NOT NULL,
    record_type TEXT NOT NULL,
    record_value TEXT NOT NULL,
    ttl BIGINT NOT NULL,
    comments TEXT NOT NULL,
    disabled BOOLEAN NOT NULL,
    expires_at_ns BIGINT,
    PRIMARY KEY (zone_name, record_key)
)`, `
CREATE INDEX IF NOT EXISTS sable_zone_records_lookup_idx
ON sable_zone_records (zone_name, owner_name, record_type)`, `
CREATE TABLE IF NOT EXISTS sable_zone_revisions (
    zone_name TEXT NOT NULL,
    revision BIGINT NOT NULL,
    change_kind TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    PRIMARY KEY (zone_name, revision)
)`}
}

// migrateZoneRecordSchema upgrades databases created before record_key became
// the stable identity for a resource record. CREATE TABLE IF NOT EXISTS cannot
// evolve an existing table, so the upgrade must be explicit and idempotent.
func (store *Store) migrateZoneRecordSchema(ctx context.Context) error {
	hasRecordKey, err := store.zoneRecordsHaveRecordKey(ctx)
	if err != nil {
		return err
	}
	if err := store.ensureZoneRecordKeys(ctx, !hasRecordKey); err != nil {
		return err
	}
	if _, err := store.database.ExecContext(ctx, `
CREATE UNIQUE INDEX IF NOT EXISTS sable_zone_records_key_idx
ON sable_zone_records (zone_name, record_key)`); err != nil {
		return fmt.Errorf("create zone record key index: %w", err)
	}
	return nil
}

func (store *Store) migrateZoneIdentitySchema(ctx context.Context) error {
	hasID, err := store.tableHasColumn(ctx, "sable_zones", "id")
	if err != nil {
		return err
	}
	if !hasID {
		if _, err := store.database.ExecContext(ctx, "ALTER TABLE sable_zones ADD COLUMN id TEXT"); err != nil {
			return fmt.Errorf("add zone identity: %w", err)
		}
	}
	rows, err := store.database.QueryContext(ctx, "SELECT name FROM sable_zones WHERE id IS NULL OR id = ''")
	if err != nil {
		return fmt.Errorf("list zones missing identities: %w", err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("scan zone missing identity: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, name := range names {
		id, err := newZoneID()
		if err != nil {
			return err
		}
		if _, err := store.database.ExecContext(ctx, "UPDATE sable_zones SET id = "+store.placeholder(1)+" WHERE name = "+store.placeholder(2), id, name); err != nil {
			return fmt.Errorf("backfill identity for zone %q: %w", name, err)
		}
	}
	if _, err := store.database.ExecContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS sable_zones_id_idx ON sable_zones (id)"); err != nil {
		return fmt.Errorf("index zone identities: %w", err)
	}
	if store.driver == "postgres" && !hasID {
		if _, err := store.database.ExecContext(ctx, "ALTER TABLE sable_zones ALTER COLUMN id SET NOT NULL"); err != nil {
			return fmt.Errorf("require zone identities: %w", err)
		}
	}
	return nil
}

func newZoneID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate zone identity: %w", err)
	}
	return "zone_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (store *Store) zoneRecordsHaveRecordKey(ctx context.Context) (bool, error) {
	if store.driver == "postgres" {
		var exists bool
		err := store.database.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'sable_zone_records'
      AND column_name = 'record_key'
)`).Scan(&exists)
		if err != nil {
			return false, fmt.Errorf("inspect zone record schema: %w", err)
		}
		return exists, nil
	}

	rows, err := store.database.QueryContext(ctx, "PRAGMA table_info(sable_zone_records)")
	if err != nil {
		return false, fmt.Errorf("inspect zone record schema: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var columnID, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&columnID, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, fmt.Errorf("scan zone record schema: %w", err)
		}
		if name == "record_key" {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate zone record schema: %w", err)
	}
	return false, nil
}

func (store *Store) ensureZoneRecordKeys(ctx context.Context, addColumn bool) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin zone record schema upgrade: %w", err)
	}
	defer transaction.Rollback()

	if addColumn {
		if _, err := transaction.ExecContext(ctx, "ALTER TABLE sable_zone_records ADD COLUMN record_key TEXT"); err != nil {
			return fmt.Errorf("add zone record key column: %w", err)
		}
	}
	type legacyRecord struct {
		zoneName, ownerName, recordType, recordValue string
		ordinal, ttl                                 int64
	}
	rows, err := transaction.QueryContext(ctx, `
SELECT zone_name, ordinal, owner_name, record_type, record_value, ttl
FROM sable_zone_records
WHERE record_key IS NULL OR record_key = ''
ORDER BY zone_name, ordinal`)
	if err != nil {
		return fmt.Errorf("read legacy zone records: %w", err)
	}
	records := make([]legacyRecord, 0)
	for rows.Next() {
		var record legacyRecord
		if err := rows.Scan(&record.zoneName, &record.ordinal, &record.ownerName, &record.recordType, &record.recordValue, &record.ttl); err != nil {
			rows.Close()
			return fmt.Errorf("scan legacy zone record: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate legacy zone records: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy zone records: %w", err)
	}

	for _, record := range records {
		key := zoneRecordKey(zone.Record{
			Name: record.ownerName, Type: record.recordType,
			Value: record.recordValue, TTL: uint32(record.ttl),
		})
		if _, err := transaction.ExecContext(ctx, `
UPDATE sable_zone_records SET record_key = `+store.placeholder(1)+`
WHERE zone_name = `+store.placeholder(2)+` AND ordinal = `+store.placeholder(3),
			key, record.zoneName, record.ordinal,
		); err != nil {
			return fmt.Errorf("backfill zone record key for %q record %d: %w", record.zoneName, record.ordinal, err)
		}
	}
	if store.driver == "postgres" && addColumn {
		if _, err := transaction.ExecContext(ctx, "ALTER TABLE sable_zone_records ALTER COLUMN record_key SET NOT NULL"); err != nil {
			return fmt.Errorf("require zone record keys: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit zone record schema upgrade: %w", err)
	}
	return nil
}

func (store *Store) ListZones(ctx context.Context) ([]zone.Zone, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT id, name, zone_type, default_ttl, disabled, zone_transfer, transfer_acl,
       notify_targets, primary_servers, primary_protocol, tsig_key,
       dynamic_updates, dnssec, dnssec_algorithm, dnssec_denial,
       nsec3_iterations, nsec3_salt, zsk_lifetime_ns, ksk_lifetime_ns,
       key_prepublish_ns, key_retire_after_ns, parent_ds_key_tag, revision
FROM sable_zones ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}
	defer rows.Close()

	zones := make([]zone.Zone, 0)
	for rows.Next() {
		current, scanErr := scanZone(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		zones = append(zones, current)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate zones: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close zone rows: %w", err)
	}
	records, err := store.listAllZoneRecords(ctx)
	if err != nil {
		return nil, err
	}
	for index := range zones {
		zones[index].Records = records[zones[index].Name]
	}
	return zones, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanZone(row rowScanner) (zone.Zone, error) {
	var current zone.Zone
	var transferACL, notifyTargets, primaryServers string
	var defaultTTL, nsec3Iterations, zskLifetime, kskLifetime, keyPrepublish, keyRetireAfter, parentDSKeyTag, revision int64
	if err := row.Scan(
		&current.ID, &current.Name, &current.Type, &defaultTTL, &current.Disabled, &current.ZoneTransfer,
		&transferACL, &notifyTargets, &primaryServers, &current.PrimaryProtocol, &current.TSIGKey,
		&current.DynamicUpdates, &current.DNSSEC, &current.DNSSECAlgorithm, &current.DNSSECDenial,
		&nsec3Iterations, &current.NSEC3Salt, &zskLifetime, &kskLifetime,
		&keyPrepublish, &keyRetireAfter, &parentDSKeyTag, &revision,
	); err != nil {
		return zone.Zone{}, fmt.Errorf("scan zone: %w", err)
	}
	if err := decodeStringList(transferACL, &current.TransferACL); err != nil {
		return zone.Zone{}, fmt.Errorf("decode transfer ACL for zone %q: %w", current.Name, err)
	}
	if err := decodeStringList(notifyTargets, &current.Notify); err != nil {
		return zone.Zone{}, fmt.Errorf("decode notify targets for zone %q: %w", current.Name, err)
	}
	if err := decodeStringList(primaryServers, &current.PrimaryServers); err != nil {
		return zone.Zone{}, fmt.Errorf("decode primary servers for zone %q: %w", current.Name, err)
	}
	current.DefaultTTL = uint32(defaultTTL)
	current.NSEC3Iterations = uint16(nsec3Iterations)
	current.ZSKLifetime.Duration = time.Duration(zskLifetime)
	current.KSKLifetime.Duration = time.Duration(kskLifetime)
	current.KeyPrepublish.Duration = time.Duration(keyPrepublish)
	current.KeyRetireAfter.Duration = time.Duration(keyRetireAfter)
	current.ParentDSKeyTag = uint16(parentDSKeyTag)
	current.Revision = uint64(revision)
	return current, nil
}

func (store *Store) listAllZoneRecords(ctx context.Context) (map[string][]zone.Record, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT zone_name, owner_name, record_type, record_value, ttl, comments, disabled, expires_at_ns
FROM sable_zone_records ORDER BY zone_name, ordinal`)
	if err != nil {
		return nil, fmt.Errorf("list zone records: %w", err)
	}
	defer rows.Close()
	records := make(map[string][]zone.Record)
	for rows.Next() {
		var zoneName string
		var record zone.Record
		var ttl int64
		var expiresAt sql.NullInt64
		if err := rows.Scan(&zoneName, &record.Name, &record.Type, &record.Value, &ttl, &record.Comments, &record.Disabled, &expiresAt); err != nil {
			return nil, fmt.Errorf("scan zone record: %w", err)
		}
		record.TTL = uint32(ttl)
		if expiresAt.Valid {
			record.ExpiresAt = time.Unix(0, expiresAt.Int64).UTC()
		}
		records[zoneName] = append(records[zoneName], record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate zone records: %w", err)
	}
	return records, nil
}

func (store *Store) ReplaceZones(ctx context.Context, previous, candidate []zone.Zone) ([]zone.Zone, error) {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin zone transaction: %w", err)
	}
	defer transaction.Rollback()

	previousByName := zoneMap(previous)
	candidateByName := zoneMap(candidate)
	now := time.Now().UTC()
	for name, oldZone := range previousByName {
		_, found := candidateByName[name]
		if found {
			continue
		}
		tombstone := oldZone
		tombstone.Revision = oldZone.Revision + 1
		if err := store.appendZoneRevision(ctx, transaction, tombstone, tombstone.Revision, "deleted", now); err != nil {
			return nil, err
		}
		if err := store.pruneZoneRevisions(ctx, transaction, oldZone.Name, tombstone.Revision); err != nil {
			return nil, err
		}
		if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_zones WHERE name = "+store.placeholder(1), name); err != nil {
			return nil, fmt.Errorf("delete zone %q: %w", name, err)
		}
		if _, err := transaction.ExecContext(ctx, `
DELETE FROM sable_role_grants
WHERE resource_type = `+store.placeholder(1)+` AND resource_id = `+store.placeholder(2), "zone", oldZone.ID); err != nil {
			return nil, fmt.Errorf("delete authorization grants for zone %q: %w", name, err)
		}
	}

	persisted := zone.Clone(candidate)
	for index := range persisted {
		current := &persisted[index]
		oldZone, existed := previousByName[current.Name]
		if existed && zoneContentEqual(oldZone, *current) {
			current.Revision = oldZone.Revision
			continue
		}
		current.Revision = 1
		changeKind := "created"
		if existed {
			current.Revision = oldZone.Revision + 1
			changeKind = "updated"
		} else {
			if current.ID == "" {
				current.ID, err = newZoneID()
				if err != nil {
					return nil, err
				}
			}
			current.Revision, err = store.nextZoneRevision(ctx, transaction, current.Name)
			if err != nil {
				return nil, err
			}
		}
		if existed {
			if err := store.updateZone(ctx, transaction, oldZone, *current, now); err != nil {
				return nil, err
			}
		} else {
			if err := store.insertZone(ctx, transaction, *current, now); err != nil {
				return nil, err
			}
		}
		if err := store.appendZoneRevision(ctx, transaction, *current, current.Revision, changeKind, now); err != nil {
			return nil, err
		}
		if err := store.pruneZoneRevisions(ctx, transaction, current.Name, current.Revision); err != nil {
			return nil, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return nil, fmt.Errorf("commit zone transaction: %w", err)
	}
	return persisted, nil
}

func (store *Store) nextZoneRevision(ctx context.Context, transaction *sql.Tx, zoneName string) (uint64, error) {
	var latest int64
	if err := transaction.QueryRowContext(ctx, `
SELECT COALESCE(MAX(revision), 0) FROM sable_zone_revisions WHERE zone_name = `+store.placeholder(1), zoneName).Scan(&latest); err != nil {
		return 0, fmt.Errorf("read latest revision for zone %q: %w", zoneName, err)
	}
	return uint64(latest) + 1, nil
}

func (store *Store) insertZone(ctx context.Context, transaction *sql.Tx, current zone.Zone, now time.Time) error {
	transferACL, err := encodeStringList(current.TransferACL)
	if err != nil {
		return err
	}
	notifyTargets, err := encodeStringList(current.Notify)
	if err != nil {
		return err
	}
	primaryServers, err := encodeStringList(current.PrimaryServers)
	if err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `
INSERT INTO sable_zones (
	id, name, zone_type, default_ttl, disabled, zone_transfer, transfer_acl,
    notify_targets, primary_servers, primary_protocol, tsig_key,
    dynamic_updates, dnssec, dnssec_algorithm, dnssec_denial,
    nsec3_iterations, nsec3_salt, zsk_lifetime_ns, ksk_lifetime_ns,
    key_prepublish_ns, key_retire_after_ns, parent_ds_key_tag, revision,
    created_at, updated_at
) VALUES (`+store.placeholders(25)+`)`,
		current.ID, current.Name, current.Type, current.DefaultTTL, current.Disabled, current.ZoneTransfer, transferACL,
		notifyTargets, primaryServers, current.PrimaryProtocol, current.TSIGKey,
		current.DynamicUpdates, current.DNSSEC, current.DNSSECAlgorithm, current.DNSSECDenial,
		current.NSEC3Iterations, current.NSEC3Salt, current.ZSKLifetime.Duration.Nanoseconds(),
		current.KSKLifetime.Duration.Nanoseconds(), current.KeyPrepublish.Duration.Nanoseconds(),
		current.KeyRetireAfter.Duration.Nanoseconds(), current.ParentDSKeyTag, current.Revision, now, now,
	)
	if err != nil {
		return fmt.Errorf("insert zone %q: %w", current.Name, err)
	}
	return store.updateZoneRecords(ctx, transaction, nil, current)
}

func (store *Store) updateZone(ctx context.Context, transaction *sql.Tx, previous, current zone.Zone, now time.Time) error {
	transferACL, err := encodeStringList(current.TransferACL)
	if err != nil {
		return err
	}
	notifyTargets, err := encodeStringList(current.Notify)
	if err != nil {
		return err
	}
	primaryServers, err := encodeStringList(current.PrimaryServers)
	if err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `
UPDATE sable_zones SET
    zone_type = `+store.placeholder(1)+`, default_ttl = `+store.placeholder(2)+`, disabled = `+store.placeholder(3)+`,
    zone_transfer = `+store.placeholder(4)+`, transfer_acl = `+store.placeholder(5)+`, notify_targets = `+store.placeholder(6)+`,
    primary_servers = `+store.placeholder(7)+`, primary_protocol = `+store.placeholder(8)+`, tsig_key = `+store.placeholder(9)+`,
    dynamic_updates = `+store.placeholder(10)+`, dnssec = `+store.placeholder(11)+`, dnssec_algorithm = `+store.placeholder(12)+`,
    dnssec_denial = `+store.placeholder(13)+`, nsec3_iterations = `+store.placeholder(14)+`, nsec3_salt = `+store.placeholder(15)+`,
    zsk_lifetime_ns = `+store.placeholder(16)+`, ksk_lifetime_ns = `+store.placeholder(17)+`,
    key_prepublish_ns = `+store.placeholder(18)+`, key_retire_after_ns = `+store.placeholder(19)+`,
    parent_ds_key_tag = `+store.placeholder(20)+`, revision = `+store.placeholder(21)+`, updated_at = `+store.placeholder(22)+`
WHERE name = `+store.placeholder(23),
		current.Type, current.DefaultTTL, current.Disabled, current.ZoneTransfer, transferACL, notifyTargets,
		primaryServers, current.PrimaryProtocol, current.TSIGKey, current.DynamicUpdates, current.DNSSEC,
		current.DNSSECAlgorithm, current.DNSSECDenial, current.NSEC3Iterations, current.NSEC3Salt,
		current.ZSKLifetime.Duration.Nanoseconds(), current.KSKLifetime.Duration.Nanoseconds(),
		current.KeyPrepublish.Duration.Nanoseconds(), current.KeyRetireAfter.Duration.Nanoseconds(),
		current.ParentDSKeyTag, current.Revision, now, current.Name,
	)
	if err != nil {
		return fmt.Errorf("update zone %q: %w", current.Name, err)
	}
	return store.updateZoneRecords(ctx, transaction, previous.Records, current)
}

func (store *Store) updateZoneRecords(ctx context.Context, transaction *sql.Tx, previous []zone.Record, current zone.Zone) error {
	currentByKey := make(map[string]struct{}, len(current.Records))
	for _, record := range current.Records {
		currentByKey[zoneRecordKey(record)] = struct{}{}
	}
	for _, record := range previous {
		key := zoneRecordKey(record)
		if _, found := currentByKey[key]; found {
			continue
		}
		if _, err := transaction.ExecContext(ctx, `DELETE FROM sable_zone_records WHERE zone_name = `+store.placeholder(1)+` AND record_key = `+store.placeholder(2), current.Name, key); err != nil {
			return fmt.Errorf("delete record from zone %q: %w", current.Name, err)
		}
	}
	previousByKey := make(map[string]struct {
		record  zone.Record
		ordinal int
	}, len(previous))
	for ordinal, record := range previous {
		previousByKey[zoneRecordKey(record)] = struct {
			record  zone.Record
			ordinal int
		}{record: record, ordinal: ordinal}
	}
	for ordinal, record := range current.Records {
		key := zoneRecordKey(record)
		if old, found := previousByKey[key]; found && old.ordinal == ordinal && reflect.DeepEqual(old.record, record) {
			continue
		}
		var expiresAt any
		if !record.ExpiresAt.IsZero() {
			expiresAt = record.ExpiresAt.UnixNano()
		}
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_zone_records (
    zone_name, record_key, ordinal, owner_name, record_type, record_value, ttl, comments, disabled, expires_at_ns
) VALUES (`+store.placeholders(10)+`)
ON CONFLICT(zone_name, record_key) DO UPDATE SET
    ordinal = excluded.ordinal, owner_name = excluded.owner_name, record_type = excluded.record_type,
    record_value = excluded.record_value, ttl = excluded.ttl, comments = excluded.comments,
    disabled = excluded.disabled, expires_at_ns = excluded.expires_at_ns`, current.Name, key, ordinal, record.Name, record.Type, record.Value,
			record.TTL, record.Comments, record.Disabled, expiresAt); err != nil {
			return fmt.Errorf("insert record %d for zone %q: %w", ordinal, current.Name, err)
		}
	}
	return nil
}

func zoneRecordKey(record zone.Record) string {
	identity := record.Name + "\x00" + record.Type + "\x00" + record.Value
	return fmt.Sprintf("%x", sha256.Sum256([]byte(identity)))
}

func (store *Store) appendZoneRevision(ctx context.Context, transaction *sql.Tx, current zone.Zone, revision uint64, changeKind string, now time.Time) error {
	snapshot, err := json.Marshal(current)
	if err != nil {
		return fmt.Errorf("encode revision for zone %q: %w", current.Name, err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_zone_revisions (zone_name, revision, change_kind, snapshot_json, created_at)
VALUES (`+store.placeholders(5)+`)`, current.Name, revision, changeKind, string(snapshot), now); err != nil {
		return fmt.Errorf("append revision for zone %q: %w", current.Name, err)
	}
	return nil
}

func (store *Store) pruneZoneRevisions(ctx context.Context, transaction *sql.Tx, zoneName string, revision uint64) error {
	if revision <= retainedZoneRevisions {
		return nil
	}
	if _, err := transaction.ExecContext(ctx, `
DELETE FROM sable_zone_revisions WHERE zone_name = `+store.placeholder(1)+` AND revision <= `+store.placeholder(2),
		zoneName, revision-retainedZoneRevisions); err != nil {
		return fmt.Errorf("prune revisions for zone %q: %w", zoneName, err)
	}
	return nil
}

func zoneMap(zones []zone.Zone) map[string]zone.Zone {
	result := make(map[string]zone.Zone, len(zones))
	for _, current := range zones {
		result[current.Name] = current
	}
	return result
}

func zoneContentEqual(left, right zone.Zone) bool {
	left.Revision = 0
	right.Revision = 0
	return reflect.DeepEqual(left, right)
}

func encodeStringList(values []string) (string, error) {
	encoded, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("encode string list: %w", err)
	}
	return string(encoded), nil
}

func decodeStringList(encoded string, destination *[]string) error {
	if encoded == "" || encoded == "null" {
		*destination = nil
		return nil
	}
	return json.Unmarshal([]byte(encoded), destination)
}
