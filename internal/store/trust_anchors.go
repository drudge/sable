package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/drudge/sable/internal/trustanchor"
)

func trustAnchorTables() []string {
	return []string{`
CREATE TABLE IF NOT EXISTS sable_dnssec_trust_points (
    owner TEXT PRIMARY KEY,
    initialized BOOLEAN NOT NULL,
    last_success TIMESTAMP NULL,
    next_refresh TIMESTAMP NULL,
    last_error TEXT NOT NULL,
    original_ttl_seconds BIGINT NOT NULL,
    signature_validity_seconds BIGINT NOT NULL
)`, `
CREATE TABLE IF NOT EXISTS sable_dnssec_trust_anchors (
    owner TEXT NOT NULL,
    key_id TEXT NOT NULL,
    dnskey TEXT NOT NULL,
    state TEXT NOT NULL,
    first_seen TIMESTAMP NULL,
    hold_down_until TIMESTAMP NULL,
    last_seen TIMESTAMP NULL,
    revoked_at TIMESTAMP NULL,
    source_key_ids TEXT NOT NULL,
    PRIMARY KEY (owner, key_id)
)`}
}

func (store *Store) LoadTrustAnchorSnapshot(ctx context.Context, owner string) (trustanchor.Snapshot, error) {
	snapshot := trustanchor.Snapshot{Status: trustanchor.Status{Owner: owner}}
	row := store.database.QueryRowContext(ctx, `
SELECT initialized, last_success, next_refresh, last_error, original_ttl_seconds, signature_validity_seconds
FROM sable_dnssec_trust_points WHERE owner = `+store.placeholder(1), owner)
	var lastSuccess, nextRefresh sql.NullTime
	if err := row.Scan(
		&snapshot.Status.Initialized,
		&lastSuccess,
		&nextRefresh,
		&snapshot.Status.LastError,
		&snapshot.Status.OriginalTTLSeconds,
		&snapshot.Status.SignatureValiditySeconds,
	); err != nil && err != sql.ErrNoRows {
		return trustanchor.Snapshot{}, fmt.Errorf("load DNSSEC trust point: %w", err)
	}
	if lastSuccess.Valid {
		snapshot.Status.LastSuccess = lastSuccess.Time.UTC()
	}
	if nextRefresh.Valid {
		snapshot.Status.NextRefresh = nextRefresh.Time.UTC()
	}

	rows, err := store.database.QueryContext(ctx, `
SELECT key_id, dnskey, state, first_seen, hold_down_until, last_seen, revoked_at, source_key_ids
FROM sable_dnssec_trust_anchors
WHERE owner = `+store.placeholder(1)+` ORDER BY key_id`, owner)
	if err != nil {
		return trustanchor.Snapshot{}, fmt.Errorf("load DNSSEC trust anchors: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		anchor := trustanchor.Anchor{Owner: owner}
		var firstSeen, holdDownUntil, lastSeen, revokedAt sql.NullTime
		var sourceKeyIDs string
		if err := rows.Scan(
			&anchor.KeyID,
			&anchor.DNSKEY,
			&anchor.State,
			&firstSeen,
			&holdDownUntil,
			&lastSeen,
			&revokedAt,
			&sourceKeyIDs,
		); err != nil {
			return trustanchor.Snapshot{}, fmt.Errorf("scan DNSSEC trust anchor: %w", err)
		}
		anchor.FirstSeen = nullableTime(firstSeen)
		anchor.HoldDownUntil = nullableTime(holdDownUntil)
		anchor.LastSeen = nullableTime(lastSeen)
		anchor.RevokedAt = nullableTime(revokedAt)
		if sourceKeyIDs != "" {
			if err := json.Unmarshal([]byte(sourceKeyIDs), &anchor.SourceKeyIDs); err != nil {
				return trustanchor.Snapshot{}, fmt.Errorf("decode DNSSEC source keys: %w", err)
			}
		}
		snapshot.Anchors = append(snapshot.Anchors, anchor)
	}
	if err := rows.Err(); err != nil {
		return trustanchor.Snapshot{}, fmt.Errorf("iterate DNSSEC trust anchors: %w", err)
	}
	countTrustAnchorStates(&snapshot)
	return snapshot, nil
}

func (store *Store) SaveTrustAnchorSnapshot(ctx context.Context, snapshot trustanchor.Snapshot) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin DNSSEC trust-anchor transaction: %w", err)
	}
	rollback := func(failure error) error {
		_ = transaction.Rollback()
		return failure
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_dnssec_trust_anchors WHERE owner = "+store.placeholder(1), snapshot.Status.Owner); err != nil {
		return rollback(fmt.Errorf("replace DNSSEC trust anchors: %w", err))
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_dnssec_trust_points WHERE owner = "+store.placeholder(1), snapshot.Status.Owner); err != nil {
		return rollback(fmt.Errorf("replace DNSSEC trust point: %w", err))
	}
	pointInsert := `INSERT INTO sable_dnssec_trust_points
(owner, initialized, last_success, next_refresh, last_error, original_ttl_seconds, signature_validity_seconds)
VALUES (` + store.placeholders(7) + `)`
	if _, err := transaction.ExecContext(
		ctx,
		pointInsert,
		snapshot.Status.Owner,
		snapshot.Status.Initialized,
		nullTime(snapshot.Status.LastSuccess),
		nullTime(snapshot.Status.NextRefresh),
		snapshot.Status.LastError,
		snapshot.Status.OriginalTTLSeconds,
		snapshot.Status.SignatureValiditySeconds,
	); err != nil {
		return rollback(fmt.Errorf("insert DNSSEC trust point: %w", err))
	}
	anchorInsert := `INSERT INTO sable_dnssec_trust_anchors
(owner, key_id, dnskey, state, first_seen, hold_down_until, last_seen, revoked_at, source_key_ids)
VALUES (` + store.placeholders(9) + `)`
	for _, anchor := range snapshot.Anchors {
		sourceKeyIDs, err := json.Marshal(anchor.SourceKeyIDs)
		if err != nil {
			return rollback(fmt.Errorf("encode DNSSEC source keys: %w", err))
		}
		if _, err := transaction.ExecContext(
			ctx,
			anchorInsert,
			snapshot.Status.Owner,
			anchor.KeyID,
			anchor.DNSKEY,
			anchor.State,
			nullTime(anchor.FirstSeen),
			nullTime(anchor.HoldDownUntil),
			nullTime(anchor.LastSeen),
			nullTime(anchor.RevokedAt),
			string(sourceKeyIDs),
		); err != nil {
			return rollback(fmt.Errorf("insert DNSSEC trust anchor: %w", err))
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit DNSSEC trust anchors: %w", err)
	}
	return nil
}

func nullableTime(value sql.NullTime) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time.UTC()
}

func nullTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func countTrustAnchorStates(snapshot *trustanchor.Snapshot) {
	for _, anchor := range snapshot.Anchors {
		switch anchor.State {
		case trustanchor.StateValid:
			snapshot.Status.Active++
		case trustanchor.StateMissing:
			snapshot.Status.Active++
			snapshot.Status.Missing++
		case trustanchor.StateAddPending:
			snapshot.Status.Pending++
		case trustanchor.StateRevoked:
			snapshot.Status.Revoked++
		}
	}
}
