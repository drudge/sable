package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/go-webauthn/webauthn/webauthn"
)

const passkeyTable = `CREATE TABLE IF NOT EXISTS sable_passkeys (
 id TEXT PRIMARY KEY,
 user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
 data TEXT NOT NULL
)`

func (store *Store) PasskeysForUser(ctx context.Context, userID int64) ([]auth.Passkey, error) {
	rows, err := store.database.QueryContext(ctx, "SELECT data FROM sable_passkeys WHERE user_id = "+store.placeholder(1)+" ORDER BY id", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []auth.Passkey{}
	for rows.Next() {
		var data string
		var key auth.Passkey
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (store *Store) UserForPasskey(ctx context.Context, id string) (auth.User, error) {
	var username string
	err := store.database.QueryRowContext(ctx, `SELECT users.username FROM sable_users users
 JOIN sable_passkeys keys ON keys.user_id = users.id
 JOIN sable_user_profiles profiles ON profiles.user_id = users.id
 WHERE profiles.disabled = FALSE AND keys.id = `+store.placeholder(1), id).Scan(&username)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, auth.ErrNotFound
	}
	if err != nil {
		return auth.User{}, err
	}
	return store.UserByUsername(ctx, username)
}

// Serialize sign-in method changes across accounts as the last local
// administrator check depends on more than the account being edited.
func (store *Store) lockSignInMethods(ctx context.Context, transaction *sql.Tx) error {
	_, err := transaction.ExecContext(ctx, "UPDATE sable_metadata SET value = value WHERE key = 'security_initialized'")
	return err
}

func (store *Store) SavePasskey(ctx context.Context, key auth.Passkey) error {
	data, err := json.Marshal(key)
	if err != nil {
		return err
	}
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if err := store.lockSignInMethods(ctx, transaction); err != nil {
		return err
	}
	var count int
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM sable_passkeys WHERE user_id = "+store.placeholder(1), key.UserID).Scan(&count); err != nil {
		return err
	}
	if count >= auth.MaximumPasskeys {
		return errors.New("maximum number of passkeys reached")
	}
	if _, err := transaction.ExecContext(ctx, "INSERT INTO sable_passkeys (id, user_id, data) VALUES ("+store.placeholders(3)+")", key.ID, key.UserID, string(data)); err != nil {
		return err
	}
	return transaction.Commit()
}

func (store *Store) UpdatePasskey(ctx context.Context, key auth.Passkey, credential webauthn.Credential, now time.Time) error {
	old, err := json.Marshal(key)
	if err != nil {
		return err
	}
	key.Credential, key.LastUsedAt = credential, now
	data, err := json.Marshal(key)
	if err != nil {
		return err
	}
	result, err := store.database.ExecContext(ctx, "UPDATE sable_passkeys SET data = "+store.placeholder(1)+" WHERE id = "+store.placeholder(2)+" AND data = "+store.placeholder(3), string(data), key.ID, string(old))
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return auth.ErrUnauthorized
	}
	return nil
}

func (store *Store) DeletePasskey(ctx context.Context, userID int64, id string) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if err := store.lockSignInMethods(ctx, transaction); err != nil {
		return err
	}
	var password bool
	if err := transaction.QueryRowContext(ctx, "SELECT password_login FROM sable_user_profiles WHERE user_id = "+store.placeholder(1), userID).Scan(&password); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.ErrNotFound
		}
		return err
	}
	result, err := transaction.ExecContext(ctx, "DELETE FROM sable_passkeys WHERE user_id = "+store.placeholder(1)+" AND id = "+store.placeholder(2), userID, id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return auth.ErrNotFound
	}
	if !password {
		var remaining int
		if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM sable_passkeys WHERE user_id = "+store.placeholder(1), userID).Scan(&remaining); err != nil {
			return err
		}
		// Requiring another local method also covers an unavailable OIDC provider.
		if remaining == 0 {
			return errors.New("keep at least one passkey while password sign-in is disabled")
		}
	}
	return transaction.Commit()
}

func (store *Store) passkeysInTransaction(ctx context.Context, transaction *sql.Tx) (map[string]auth.Passkey, error) {
	rows, err := transaction.QueryContext(ctx, "SELECT data FROM sable_passkeys")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make(map[string]auth.Passkey)
	for rows.Next() {
		var data string
		var key auth.Passkey
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &key); err != nil {
			return nil, err
		}
		keys[key.ID] = key
	}
	return keys, rows.Err()
}

// Replica sign-ins can advance an authenticator beyond the primary's last
// snapshot. Restoring that snapshot must not roll its replay counter back.
func preservePasskeyActivity(incoming, local auth.Passkey) auth.Passkey {
	if incoming.UserID != local.UserID || incoming.RPID != local.RPID || !bytes.Equal(incoming.UserHandle, local.UserHandle) || !bytes.Equal(incoming.Credential.PublicKey, local.Credential.PublicKey) {
		return incoming
	}
	if local.Credential.Authenticator.SignCount > incoming.Credential.Authenticator.SignCount {
		incoming.Credential.Authenticator.SignCount = local.Credential.Authenticator.SignCount
	}
	if local.LastUsedAt.After(incoming.LastUsedAt) {
		incoming.LastUsedAt = local.LastUsedAt
	}
	return incoming
}
