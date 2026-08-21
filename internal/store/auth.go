package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
)

func (store *Store) authenticationTables() []string {
	primaryKey := "INTEGER PRIMARY KEY AUTOINCREMENT"
	blob := "BLOB"
	if store.driver == "postgres" {
		primaryKey = "BIGSERIAL PRIMARY KEY"
		blob = "BYTEA"
	}
	return []string{
		fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS sable_users (
    id %s,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
)`, primaryKey), `
CREATE TABLE IF NOT EXISTS sable_user_profiles (
    user_id BIGINT PRIMARY KEY REFERENCES sable_users(id) ON DELETE CASCADE,
	display_name TEXT NOT NULL,
	email TEXT NOT NULL DEFAULT '',
	disabled BOOLEAN NOT NULL,
	password_login BOOLEAN NOT NULL DEFAULT TRUE,
	avatar_etag TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL
)`, fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS sable_user_avatars (
    user_id BIGINT PRIMARY KEY REFERENCES sable_users(id) ON DELETE CASCADE,
    content_type TEXT NOT NULL,
    image %s NOT NULL,
    source_url TEXT NOT NULL,
    etag TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL
)`, blob), fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS sable_roles (
    id %s,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    built_in BOOLEAN NOT NULL,
    created_at TIMESTAMP NOT NULL
)`, primaryKey), `
CREATE TABLE IF NOT EXISTS sable_role_grants (
    role_id BIGINT NOT NULL REFERENCES sable_roles(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    surface TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (role_id, permission, surface, resource_type, resource_id)
)`, `
CREATE TABLE IF NOT EXISTS sable_user_roles (
    user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES sable_roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
)`, `
CREATE TABLE IF NOT EXISTS sable_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL
)`, `
CREATE INDEX IF NOT EXISTS sable_sessions_expires_at_idx
ON sable_sessions (expires_at)`, fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS sable_api_tokens (
    id %s,
    token_hash TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP
)`, primaryKey), `
CREATE TABLE IF NOT EXISTS sable_api_token_roles (
    token_id BIGINT NOT NULL REFERENCES sable_api_tokens(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES sable_roles(id) ON DELETE CASCADE,
    PRIMARY KEY (token_id, role_id)
)`, `
CREATE INDEX IF NOT EXISTS sable_api_tokens_expires_at_idx
ON sable_api_tokens (expires_at)`, fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS sable_audit_log (
    id %s,
    occurred_at TIMESTAMP NOT NULL,
    user_id BIGINT REFERENCES sable_users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    details TEXT NOT NULL
)`, primaryKey), `
CREATE INDEX IF NOT EXISTS sable_audit_log_occurred_at_idx
ON sable_audit_log (occurred_at)`, `
CREATE TABLE IF NOT EXISTS sable_secrets (
    name TEXT PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL
)`, `
CREATE TABLE IF NOT EXISTS sable_user_identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    linked_at TIMESTAMP NOT NULL,
    last_login_at TIMESTAMP,
    PRIMARY KEY (provider, subject)
)`, `
CREATE INDEX IF NOT EXISTS sable_user_identities_user_id_idx
ON sable_user_identities (user_id)`,
	}
}

func (store *Store) migrateAuthenticationSchema(ctx context.Context) error {
	hasEmail, err := store.userProfilesHaveEmail(ctx)
	if err != nil {
		return err
	}
	if !hasEmail {
		if _, err := store.database.ExecContext(ctx, "ALTER TABLE sable_user_profiles ADD COLUMN email TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("add user profile email: %w", err)
		}
	}
	// Accounts that predate single sign-on all have a password, so the column
	// defaults to true. Only a user who later opts into SSO-only has it
	// cleared, which is what keeps an upgrade from locking anybody out.
	hasPasswordLogin, err := store.tableHasColumn(ctx, "sable_user_profiles", "password_login")
	if err != nil {
		return err
	}
	if !hasPasswordLogin {
		if _, err := store.database.ExecContext(ctx, "ALTER TABLE sable_user_profiles ADD COLUMN password_login BOOLEAN NOT NULL DEFAULT TRUE"); err != nil {
			return fmt.Errorf("add user profile password login: %w", err)
		}
	}
	// The avatar tag lives on the profile rather than with the image so a
	// session lookup can tell whether a picture exists without reading one.
	hasAvatarETag, err := store.tableHasColumn(ctx, "sable_user_profiles", "avatar_etag")
	if err != nil {
		return err
	}
	if !hasAvatarETag {
		if _, err := store.database.ExecContext(ctx, "ALTER TABLE sable_user_profiles ADD COLUMN avatar_etag TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("add user profile avatar tag: %w", err)
		}
	}
	hasScopes, err := store.tableHasColumn(ctx, "sable_api_tokens", "scopes")
	if err != nil {
		return err
	}
	if hasScopes {
		if err := store.rebuildAPITokensWithoutScopes(ctx); err != nil {
			return err
		}
	}
	nullableExpiration, err := store.apiTokenExpirationNullable(ctx)
	if err != nil {
		return err
	}
	if !nullableExpiration {
		if err := store.makeAPITokenExpirationNullable(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (store *Store) rebuildAPITokensWithoutScopes(ctx context.Context) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin API token authorization migration: %w", err)
	}
	defer transaction.Rollback()
	// Pre-release tokens used coarse scopes and cannot be translated safely to
	// group grants. Revoke them while preserving the clean final schema.
	if _, err := transaction.ExecContext(ctx, "DROP TABLE IF EXISTS sable_api_token_roles"); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, "DROP TABLE sable_api_tokens"); err != nil {
		return fmt.Errorf("drop scoped API tokens: %w", err)
	}
	primaryKey := "INTEGER PRIMARY KEY AUTOINCREMENT"
	if store.driver == "postgres" {
		primaryKey = "BIGSERIAL PRIMARY KEY"
	}
	statements := []string{fmt.Sprintf(`CREATE TABLE sable_api_tokens (
    id %s,
    token_hash TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP
)`, primaryKey), `CREATE TABLE sable_api_token_roles (
    token_id BIGINT NOT NULL REFERENCES sable_api_tokens(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES sable_roles(id) ON DELETE CASCADE,
    PRIMARY KEY (token_id, role_id)
)`, `CREATE INDEX sable_api_tokens_expires_at_idx ON sable_api_tokens (expires_at)`}
	for _, statement := range statements {
		if _, err := transaction.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("rebuild API token authorization: %w", err)
		}
	}
	return transaction.Commit()
}

func (store *Store) apiTokenExpirationNullable(ctx context.Context) (bool, error) {
	if store.driver == "postgres" {
		var nullable string
		err := store.database.QueryRowContext(ctx, `
SELECT is_nullable FROM information_schema.columns
WHERE table_schema = current_schema() AND table_name = 'sable_api_tokens' AND column_name = 'expires_at'`).Scan(&nullable)
		return nullable == "YES", err
	}
	rows, err := store.database.QueryContext(ctx, "PRAGMA table_info(sable_api_tokens)")
	if err != nil {
		return false, fmt.Errorf("inspect API token expiration: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ordinal, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&ordinal, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if name == "expires_at" {
			return notNull == 0, nil
		}
	}
	return false, errors.New("API token expiration column is missing")
}

func (store *Store) makeAPITokenExpirationNullable(ctx context.Context) error {
	if store.driver == "postgres" {
		_, err := store.database.ExecContext(ctx, "ALTER TABLE sable_api_tokens ALTER COLUMN expires_at DROP NOT NULL")
		return err
	}
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin API token expiration migration: %w", err)
	}
	defer transaction.Rollback()
	statements := []string{
		`CREATE TEMP TABLE sable_api_token_roles_backup AS SELECT token_id, role_id FROM sable_api_token_roles`,
		`DROP TABLE sable_api_token_roles`,
		`CREATE TABLE sable_api_tokens_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP
)`,
		`INSERT INTO sable_api_tokens_new (id, token_hash, user_id, name, created_at, expires_at, last_used_at)
SELECT id, token_hash, user_id, name, created_at, expires_at, last_used_at FROM sable_api_tokens`,
		`DROP TABLE sable_api_tokens`,
		`ALTER TABLE sable_api_tokens_new RENAME TO sable_api_tokens`,
		`CREATE TABLE sable_api_token_roles (
    token_id BIGINT NOT NULL REFERENCES sable_api_tokens(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES sable_roles(id) ON DELETE CASCADE,
    PRIMARY KEY (token_id, role_id)
)`,
		`INSERT INTO sable_api_token_roles (token_id, role_id) SELECT token_id, role_id FROM sable_api_token_roles_backup`,
		`DROP TABLE sable_api_token_roles_backup`,
		`CREATE INDEX IF NOT EXISTS sable_api_tokens_expires_at_idx ON sable_api_tokens (expires_at)`,
	}
	for _, statement := range statements {
		if _, err := transaction.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate API token expiration: %w", err)
		}
	}
	return transaction.Commit()
}

func (store *Store) userProfilesHaveEmail(ctx context.Context) (bool, error) {
	if store.driver == "postgres" {
		var exists bool
		err := store.database.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'sable_user_profiles'
      AND column_name = 'email'
)`).Scan(&exists)
		return exists, err
	}
	rows, err := store.database.QueryContext(ctx, "PRAGMA table_info(sable_user_profiles)")
	if err != nil {
		return false, fmt.Errorf("inspect user profile columns: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var columnID, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&columnID, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, fmt.Errorf("scan user profile column: %w", err)
		}
		if name == "email" {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (store *Store) seedAuthorization(ctx context.Context) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin authorization seed: %w", err)
	}
	defer transaction.Rollback()
	now := time.Now().UTC()
	for _, definition := range auth.BuiltInRoles {
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_roles (name, description, built_in, created_at)
VALUES (`+store.placeholders(4)+`)
ON CONFLICT(name) DO UPDATE SET description = excluded.description, built_in = excluded.built_in`,
			definition.Name, definition.Description, true, now,
		); err != nil {
			return fmt.Errorf("seed role %q: %w", definition.Name, err)
		}
		var roleID int64
		if err := transaction.QueryRowContext(ctx,
			"SELECT id FROM sable_roles WHERE name = "+store.placeholder(1), definition.Name,
		).Scan(&roleID); err != nil {
			return fmt.Errorf("read seeded role %q: %w", definition.Name, err)
		}
		if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_role_grants WHERE role_id = "+store.placeholder(1), roleID); err != nil {
			return fmt.Errorf("reset grants for role %q: %w", definition.Name, err)
		}
		surfaces := definition.Surfaces
		if len(surfaces) == 0 {
			surfaces = []auth.Surface{auth.SurfaceWeb, auth.SurfaceAPI}
		}
		for _, permission := range definition.Permissions {
			for _, surface := range surfaces {
				resourceType, resourceID := "", ""
				if strings.HasPrefix(permission, "zones.") && permission != auth.PermissionZonesCreate {
					resourceType, resourceID = auth.ResourceZone, auth.ResourceAll
				}
				if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_role_grants (role_id, permission, surface, resource_type, resource_id)
VALUES (`+store.placeholders(5)+`)`, roleID, permission, surface, resourceType, resourceID); err != nil {
					return fmt.Errorf("seed %s grant %q for role %q: %w", surface, permission, definition.Name, err)
				}
			}
		}
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_user_profiles (user_id, display_name, disabled, updated_at)
SELECT id, username, FALSE, `+store.placeholder(1)+` FROM sable_users
WHERE 1 = 1
ON CONFLICT(user_id) DO NOTHING`, now); err != nil {
		return fmt.Errorf("seed user profiles: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_user_roles (user_id, role_id)
SELECT users.id, roles.id
FROM sable_users AS users
CROSS JOIN sable_roles AS roles
WHERE roles.name = 'Administrator'
  AND NOT EXISTS (SELECT 1 FROM sable_user_roles WHERE user_id = users.id)
ON CONFLICT(user_id, role_id) DO NOTHING`); err != nil {
		return fmt.Errorf("seed administrator assignments: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit authorization seed: %w", err)
	}
	return nil
}

func (store *Store) AdminExists(ctx context.Context) (bool, error) {
	var value string
	err := store.database.QueryRowContext(
		ctx, "SELECT value FROM sable_metadata WHERE key = "+store.placeholder(1), "security_initialized",
	).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check administrator setup: %w", err)
	}
	return value == "true", nil
}

func (store *Store) CreateInitialAdmin(
	ctx context.Context,
	username, passwordHash string,
	createdAt time.Time,
) (auth.User, error) {
	transaction, err := store.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return auth.User{}, fmt.Errorf("begin administrator setup: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(
		ctx,
		"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholder(1)+", "+store.placeholder(2)+") ON CONFLICT(key) DO NOTHING",
		"security_initialized", "true",
	)
	if err != nil {
		return auth.User{}, fmt.Errorf("reserve administrator setup: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return auth.User{}, fmt.Errorf("inspect administrator setup: %w", err)
	}
	if inserted == 0 {
		return auth.User{}, auth.ErrSetupComplete
	}
	user := auth.User{Username: username, PasswordHash: passwordHash, LoginAllowed: true}
	err = transaction.QueryRowContext(
		ctx,
		"INSERT INTO sable_users (username, password_hash, created_at) VALUES ("+
			store.placeholder(1)+", "+store.placeholder(2)+", "+store.placeholder(3)+") RETURNING id",
		username, passwordHash, createdAt.UTC(),
	).Scan(&user.ID)
	if err != nil {
		return auth.User{}, fmt.Errorf("create initial administrator: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_user_profiles (user_id, display_name, disabled, updated_at)
VALUES (`+store.placeholders(4)+`)`, user.ID, username, false, createdAt.UTC()); err != nil {
		return auth.User{}, fmt.Errorf("create administrator profile: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_user_roles (user_id, role_id)
SELECT `+store.placeholder(1)+`, id FROM sable_roles WHERE name = 'Administrator'`, user.ID); err != nil {
		return auth.User{}, fmt.Errorf("assign administrator role: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return auth.User{}, fmt.Errorf("commit administrator setup: %w", err)
	}
	return user, nil
}

func (store *Store) UserByUsername(ctx context.Context, username string) (auth.User, error) {
	var user auth.User
	err := store.database.QueryRowContext(
		ctx,
		`SELECT users.id, users.username, profiles.display_name, profiles.email, users.password_hash,
       profiles.password_login, EXISTS (
    SELECT 1 FROM sable_user_roles AS memberships
    JOIN sable_role_grants AS grants ON grants.role_id = memberships.role_id
    WHERE memberships.user_id = users.id AND grants.surface = `+store.placeholder(1)+`
)
FROM sable_users AS users
JOIN sable_user_profiles AS profiles ON profiles.user_id = users.id
WHERE users.username = `+store.placeholder(2),
		auth.SurfaceWeb, username,
	).Scan(&user.ID, &user.Username, &user.DisplayName, &user.Email, &user.PasswordHash, &user.PasswordLogin, &user.LoginAllowed)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, auth.ErrNotFound
	}
	if err != nil {
		return auth.User{}, fmt.Errorf("find user: %w", err)
	}
	return user, nil
}

func (store *Store) CreateSession(
	ctx context.Context,
	tokenHash string,
	userID int64,
	csrfToken string,
	createdAt, expiresAt time.Time,
) error {
	_, err := store.database.ExecContext(
		ctx,
		"INSERT INTO sable_sessions (token_hash, user_id, csrf_token, created_at, expires_at) VALUES ("+
			store.placeholders(5)+")",
		tokenHash, userID, csrfToken, createdAt.UTC(), expiresAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (store *Store) SessionByHash(ctx context.Context, tokenHash string, now time.Time) (auth.StoredSession, error) {
	var session auth.StoredSession
	err := store.database.QueryRowContext(ctx, `
SELECT users.id, users.username, profiles.display_name, profiles.email,
       COALESCE(profiles.avatar_etag, ''), sessions.csrf_token, sessions.expires_at
FROM sable_sessions AS sessions
JOIN sable_users AS users ON users.id = sessions.user_id
LEFT JOIN sable_user_profiles AS profiles ON profiles.user_id = users.id
WHERE sessions.token_hash = `+store.placeholder(1)+` AND sessions.expires_at > `+store.placeholder(2)+`
  AND COALESCE(profiles.disabled, FALSE) = FALSE
  AND EXISTS (
      SELECT 1 FROM sable_user_roles AS memberships
      JOIN sable_role_grants AS grants ON grants.role_id = memberships.role_id
      WHERE memberships.user_id = users.id AND grants.surface = `+store.placeholder(3)+`
  )`,
		tokenHash, now.UTC(), auth.SurfaceWeb,
	).Scan(
		&session.User.ID, &session.User.Username, &session.User.DisplayName, &session.User.Email,
		&session.User.AvatarETag, &session.CSRFToken, &session.Expires,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.StoredSession{}, auth.ErrNotFound
	}
	if err != nil {
		return auth.StoredSession{}, fmt.Errorf("find session: %w", err)
	}
	return session, nil
}

func (store *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := store.database.ExecContext(
		ctx, "DELETE FROM sable_sessions WHERE token_hash = "+store.placeholder(1), tokenHash,
	); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (store *Store) CreateAPIToken(
	ctx context.Context,
	tokenHash string,
	userID int64,
	name string,
	groups []string,
	createdAt, expiresAt time.Time,
) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin API token creation: %w", err)
	}
	defer transaction.Rollback()
	var tokenID int64
	var expiration any
	if !expiresAt.IsZero() {
		expiration = expiresAt.UTC()
	}
	if err := transaction.QueryRowContext(ctx, `
INSERT INTO sable_api_tokens (token_hash, user_id, name, created_at, expires_at)
VALUES (`+store.placeholders(5)+`) RETURNING id`, tokenHash, userID, name, createdAt.UTC(), expiration).Scan(&tokenID); err != nil {
		return fmt.Errorf("create API token: %w", err)
	}
	for _, group := range groups {
		result, err := transaction.ExecContext(ctx, `
INSERT INTO sable_api_token_roles (token_id, role_id)
SELECT `+store.placeholder(1)+`, roles.id
FROM sable_roles AS roles
JOIN sable_user_roles AS membership ON membership.role_id = roles.id
JOIN sable_users AS users ON users.id = membership.user_id
LEFT JOIN sable_user_profiles AS profiles ON profiles.user_id = users.id
WHERE membership.user_id = `+store.placeholder(2)+` AND roles.name = `+store.placeholder(3)+`
  AND COALESCE(profiles.disabled, FALSE) = FALSE
  AND EXISTS (
      SELECT 1 FROM sable_role_grants AS grants
      WHERE grants.role_id = roles.id AND grants.surface = `+store.placeholder(4)+`
  )`, tokenID, userID, group, auth.SurfaceAPI)
		if err != nil {
			return fmt.Errorf("assign API token group %q: %w", group, err)
		}
		assigned, _ := result.RowsAffected()
		if assigned != 1 {
			return fmt.Errorf("group %q is not assigned to this active user or has no API permissions", group)
		}
	}
	return transaction.Commit()
}

func (store *Store) APITokenByHash(ctx context.Context, tokenHash string, now time.Time) (auth.StoredAPIToken, error) {
	var token auth.StoredAPIToken
	var expiration sql.NullTime
	err := store.database.QueryRowContext(ctx, `
SELECT tokens.id, users.id, users.username, tokens.expires_at
FROM sable_api_tokens AS tokens
JOIN sable_users AS users ON users.id = tokens.user_id
LEFT JOIN sable_user_profiles AS profiles ON profiles.user_id = users.id
WHERE tokens.token_hash = `+store.placeholder(1)+` AND (tokens.expires_at IS NULL OR tokens.expires_at > `+store.placeholder(2)+`)
  AND COALESCE(profiles.disabled, FALSE) = FALSE`,
		tokenHash, now.UTC(),
	).Scan(&token.ID, &token.User.ID, &token.User.Username, &expiration)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.StoredAPIToken{}, auth.ErrNotFound
	}
	if err != nil {
		return auth.StoredAPIToken{}, fmt.Errorf("find API token: %w", err)
	}
	if expiration.Valid {
		token.Expires = expiration.Time
	}
	rows, err := store.database.QueryContext(ctx, `
SELECT roles.name FROM sable_api_token_roles AS assignments
JOIN sable_roles AS roles ON roles.id = assignments.role_id
JOIN sable_user_roles AS membership ON membership.role_id = roles.id AND membership.user_id = `+store.placeholder(1)+`
WHERE assignments.token_id = `+store.placeholder(2)+` ORDER BY roles.name`, token.User.ID, token.ID)
	if err != nil {
		return auth.StoredAPIToken{}, fmt.Errorf("list API token groups: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var group string
		if err := rows.Scan(&group); err != nil {
			return auth.StoredAPIToken{}, err
		}
		token.Groups = append(token.Groups, group)
	}
	if err := rows.Err(); err != nil {
		return auth.StoredAPIToken{}, fmt.Errorf("iterate API token groups: %w", err)
	}
	if err := rows.Close(); err != nil {
		return auth.StoredAPIToken{}, fmt.Errorf("close API token groups: %w", err)
	}
	if len(token.Groups) == 0 {
		return auth.StoredAPIToken{}, auth.ErrForbidden
	}
	_, _ = store.database.ExecContext(
		ctx,
		"UPDATE sable_api_tokens SET last_used_at = "+store.placeholder(1)+" WHERE token_hash = "+store.placeholder(2),
		now.UTC(), tokenHash,
	)
	return token, nil
}

func (store *Store) GrantsForUser(ctx context.Context, userID int64, surface auth.Surface) ([]auth.Grant, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT DISTINCT grants.permission, grants.surface, grants.resource_type, grants.resource_id
FROM sable_role_grants AS grants
JOIN sable_user_roles AS membership ON membership.role_id = grants.role_id
WHERE membership.user_id = `+store.placeholder(1)+` AND grants.surface = `+store.placeholder(2)+`
ORDER BY grants.permission, grants.resource_type, grants.resource_id`, userID, surface)
	if err != nil {
		return nil, fmt.Errorf("list user grants: %w", err)
	}
	defer rows.Close()
	return scanGrants(rows, "user")
}

func (store *Store) GrantsForToken(ctx context.Context, tokenID, userID int64, surface auth.Surface) ([]auth.Grant, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT DISTINCT grants.permission, grants.surface, grants.resource_type, grants.resource_id
FROM sable_role_grants AS grants
JOIN sable_api_token_roles AS token_groups ON token_groups.role_id = grants.role_id
JOIN sable_user_roles AS membership
  ON membership.role_id = grants.role_id AND membership.user_id = `+store.placeholder(1)+`
WHERE token_groups.token_id = `+store.placeholder(2)+` AND grants.surface = `+store.placeholder(3)+`
ORDER BY grants.permission, grants.resource_type, grants.resource_id`, userID, tokenID, surface)
	if err != nil {
		return nil, fmt.Errorf("list API token grants: %w", err)
	}
	defer rows.Close()
	return scanGrants(rows, "API token")
}

func scanGrants(rows *sql.Rows, subject string) ([]auth.Grant, error) {
	grants := make([]auth.Grant, 0)
	for rows.Next() {
		var grant auth.Grant
		if err := rows.Scan(&grant.Permission, &grant.Surface, &grant.ResourceType, &grant.ResourceID); err != nil {
			return nil, fmt.Errorf("scan %s grant: %w", subject, err)
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s grants: %w", subject, err)
	}
	return grants, nil
}

func (store *Store) PruneExpiredAuthentication(ctx context.Context, now time.Time) error {
	for _, table := range []string{"sable_sessions", "sable_api_tokens"} {
		if _, err := store.database.ExecContext(
			ctx, "DELETE FROM "+table+" WHERE expires_at <= "+store.placeholder(1), now.UTC(),
		); err != nil {
			return fmt.Errorf("prune expired authentication from %s: %w", table, err)
		}
	}
	return nil
}

func (store *Store) RecordAuditEvent(ctx context.Context, event auth.AuditEvent) error {
	_, err := store.database.ExecContext(ctx, `
INSERT INTO sable_audit_log (occurred_at, user_id, action, client_ip, user_agent, details)
VALUES (`+store.placeholders(6)+`)`,
		event.OccurredAt.UTC(), event.UserID, event.Action, event.ClientIP, event.UserAgent, event.Details,
	)
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

func (store *Store) PutEncryptedSecret(ctx context.Context, name, ciphertext string, updatedAt time.Time) error {
	_, err := store.database.ExecContext(ctx, `
INSERT INTO sable_secrets (name, ciphertext, updated_at)
VALUES (`+store.placeholders(3)+`)
ON CONFLICT(name) DO UPDATE SET ciphertext = excluded.ciphertext, updated_at = excluded.updated_at`,
		name, ciphertext, updatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("store encrypted secret: %w", err)
	}
	return nil
}

// DeleteEncryptedSecret retires a stored secret. Removing the row rather than
// blanking it means a deleted TSIG key leaves nothing behind in a backup.
func (store *Store) DeleteEncryptedSecret(ctx context.Context, name string) error {
	_, err := store.database.ExecContext(
		ctx, "DELETE FROM sable_secrets WHERE name = "+store.placeholder(1), name,
	)
	if err != nil {
		return fmt.Errorf("delete encrypted secret: %w", err)
	}
	return nil
}

func (store *Store) EncryptedSecret(ctx context.Context, name string) (string, error) {
	var ciphertext string
	err := store.database.QueryRowContext(
		ctx, "SELECT ciphertext FROM sable_secrets WHERE name = "+store.placeholder(1), name,
	).Scan(&ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return "", auth.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read encrypted secret: %w", err)
	}
	return ciphertext, nil
}

func (store *Store) placeholder(index int) string {
	if store.driver == "postgres" {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func (store *Store) placeholders(count int) string {
	values := make([]string, count)
	for index := range count {
		values[index] = store.placeholder(index + 1)
	}
	return strings.Join(values, ", ")
}
