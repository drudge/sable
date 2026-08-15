package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/drudge/sable/internal/auth"
)

func (store *Store) ListUsers(ctx context.Context) ([]auth.ManagedUser, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT users.id, users.username, profiles.display_name, profiles.email,
       profiles.disabled, users.created_at, profiles.updated_at
FROM sable_users AS users
JOIN sable_user_profiles AS profiles ON profiles.user_id = users.id
ORDER BY users.username`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	users := make([]auth.ManagedUser, 0)
	for rows.Next() {
		var user auth.ManagedUser
		if err := rows.Scan(&user.ID, &user.Username, &user.DisplayName, &user.Email, &user.Disabled, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close user rows: %w", err)
	}
	roleRows, err := store.database.QueryContext(ctx, `
SELECT assignments.user_id, roles.name
FROM sable_user_roles AS assignments
JOIN sable_roles AS roles ON roles.id = assignments.role_id
ORDER BY assignments.user_id, roles.name`)
	if err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	defer roleRows.Close()
	rolesByUser := make(map[int64][]string, len(users))
	for roleRows.Next() {
		var userID int64
		var name string
		if err := roleRows.Scan(&userID, &name); err != nil {
			return nil, fmt.Errorf("scan user role: %w", err)
		}
		rolesByUser[userID] = append(rolesByUser[userID], name)
	}
	if err := roleRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user roles: %w", err)
	}
	for index := range users {
		users[index].Roles = rolesByUser[users[index].ID]
	}
	return users, nil
}

func (store *Store) ListRoles(ctx context.Context) ([]auth.Role, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT roles.id, roles.name, roles.description, roles.built_in, COUNT(assignments.user_id)
FROM sable_roles AS roles
LEFT JOIN sable_user_roles AS assignments ON assignments.role_id = roles.id
GROUP BY roles.id, roles.name, roles.description, roles.built_in
ORDER BY roles.built_in DESC, roles.name`)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()
	roles := make([]auth.Role, 0)
	for rows.Next() {
		var role auth.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.BuiltIn, &role.Users); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate roles: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close role rows: %w", err)
	}
	grantRows, err := store.database.QueryContext(ctx, `
SELECT role_id, permission, surface, resource_type, resource_id
FROM sable_role_grants
ORDER BY role_id, permission, surface, resource_type, resource_id`)
	if err != nil {
		return nil, fmt.Errorf("list role grants: %w", err)
	}
	defer grantRows.Close()
	grantsByRole := make(map[int64][]auth.Grant, len(roles))
	permissionsByRole := make(map[int64][]string, len(roles))
	for grantRows.Next() {
		var roleID int64
		var grant auth.Grant
		if err := grantRows.Scan(&roleID, &grant.Permission, &grant.Surface, &grant.ResourceType, &grant.ResourceID); err != nil {
			return nil, fmt.Errorf("scan role grant: %w", err)
		}
		grantsByRole[roleID] = append(grantsByRole[roleID], grant)
		if !slices.Contains(permissionsByRole[roleID], grant.Permission) {
			permissionsByRole[roleID] = append(permissionsByRole[roleID], grant.Permission)
		}
	}
	if err := grantRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate role grants: %w", err)
	}
	for index := range roles {
		roles[index].Permissions = permissionsByRole[roles[index].ID]
		roles[index].Grants = grantsByRole[roles[index].ID]
	}
	return roles, nil
}

func (store *Store) RolesHaveSurface(ctx context.Context, roles []string, surface auth.Surface) (bool, error) {
	hasSurface := false
	for _, role := range roles {
		var exists, granted bool
		err := store.database.QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM sable_roles WHERE name = `+store.placeholder(1)+`),
       EXISTS (
           SELECT 1 FROM sable_roles AS roles
           JOIN sable_role_grants AS grants ON grants.role_id = roles.id
           WHERE roles.name = `+store.placeholder(2)+` AND grants.surface = `+store.placeholder(3)+`
       )`, role, role, surface).Scan(&exists, &granted)
		if err != nil {
			return false, fmt.Errorf("inspect role %q surface: %w", role, err)
		}
		if !exists {
			return false, fmt.Errorf("role %q was not found", role)
		}
		hasSurface = hasSurface || granted
	}
	return hasSurface, nil
}

func (store *Store) ListSessions(ctx context.Context, now time.Time) ([]auth.Session, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT SUBSTR(sessions.token_hash, 1, 12), users.id, users.username, sessions.created_at, sessions.expires_at
FROM sable_sessions AS sessions
JOIN sable_users AS users ON users.id = sessions.user_id
WHERE sessions.expires_at > `+store.placeholder(1)+`
ORDER BY sessions.created_at DESC`, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()
	sessions := make([]auth.Session, 0)
	for rows.Next() {
		var session auth.Session
		if err := rows.Scan(&session.HashPrefix, &session.UserID, &session.Username, &session.CreatedAt, &session.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (store *Store) ListAPITokens(ctx context.Context, now time.Time) ([]auth.APIToken, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT tokens.id, users.id, users.username, tokens.name,
       tokens.created_at, tokens.expires_at, tokens.last_used_at
FROM sable_api_tokens AS tokens
JOIN sable_users AS users ON users.id = tokens.user_id
WHERE tokens.expires_at IS NULL OR tokens.expires_at > `+store.placeholder(1)+`
ORDER BY tokens.created_at DESC`, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("list API tokens: %w", err)
	}
	defer rows.Close()
	tokens := make([]auth.APIToken, 0)
	for rows.Next() {
		var token auth.APIToken
		var expiration, lastUsed sql.NullTime
		if err := rows.Scan(&token.ID, &token.UserID, &token.Username, &token.Name, &token.CreatedAt, &expiration, &lastUsed); err != nil {
			return nil, fmt.Errorf("scan API token: %w", err)
		}
		if expiration.Valid {
			token.ExpiresAt = expiration.Time
		}
		if lastUsed.Valid {
			token.LastUsedAt = lastUsed.Time
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate API tokens: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close API token rows: %w", err)
	}
	groupRows, err := store.database.QueryContext(ctx, `
SELECT assignments.token_id, roles.name
FROM sable_api_token_roles AS assignments
JOIN sable_roles AS roles ON roles.id = assignments.role_id
ORDER BY assignments.token_id, roles.name`)
	if err != nil {
		return nil, fmt.Errorf("list API token groups: %w", err)
	}
	defer groupRows.Close()
	groupsByToken := make(map[int64][]string, len(tokens))
	for groupRows.Next() {
		var tokenID int64
		var group string
		if err := groupRows.Scan(&tokenID, &group); err != nil {
			return nil, fmt.Errorf("scan API token group: %w", err)
		}
		groupsByToken[tokenID] = append(groupsByToken[tokenID], group)
	}
	if err := groupRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate API token groups: %w", err)
	}
	for index := range tokens {
		tokens[index].Groups = groupsByToken[tokens[index].ID]
	}
	return tokens, nil
}

func (store *Store) ListAuditRecords(ctx context.Context, limit int) ([]auth.AuditRecord, error) {
	if limit <= 0 {
		return []auth.AuditRecord{}, nil
	}
	rows, err := store.database.QueryContext(ctx, `
SELECT audit.id, audit.occurred_at, COALESCE(users.username, 'system'),
       audit.action, audit.client_ip, audit.details
FROM sable_audit_log AS audit
LEFT JOIN sable_users AS users ON users.id = audit.user_id
ORDER BY audit.id DESC LIMIT `+store.placeholder(1), limit)
	if err != nil {
		return nil, fmt.Errorf("list audit records: %w", err)
	}
	defer rows.Close()
	records := make([]auth.AuditRecord, 0, limit)
	for rows.Next() {
		var record auth.AuditRecord
		if err := rows.Scan(&record.ID, &record.OccurredAt, &record.Username, &record.Action, &record.ClientIP, &record.Details); err != nil {
			return nil, fmt.Errorf("scan audit record: %w", err)
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (store *Store) CreateUser(ctx context.Context, username, displayName, email, passwordHash string, roles []string, now time.Time) (auth.ManagedUser, error) {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return auth.ManagedUser{}, fmt.Errorf("begin user creation: %w", err)
	}
	defer transaction.Rollback()
	var user auth.ManagedUser
	err = transaction.QueryRowContext(ctx, `
INSERT INTO sable_users (username, password_hash, created_at)
VALUES (`+store.placeholders(3)+`) RETURNING id`, username, passwordHash, now.UTC()).Scan(&user.ID)
	if err != nil {
		return auth.ManagedUser{}, fmt.Errorf("create user %q: %w", username, err)
	}
	if displayName == "" {
		displayName = username
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_user_profiles (user_id, display_name, email, disabled, updated_at)
VALUES (`+store.placeholders(5)+`)`, user.ID, displayName, email, false, now.UTC()); err != nil {
		return auth.ManagedUser{}, fmt.Errorf("create profile for %q: %w", username, err)
	}
	if err := store.replaceUserRoles(ctx, transaction, user.ID, roles); err != nil {
		return auth.ManagedUser{}, err
	}
	if err := transaction.Commit(); err != nil {
		return auth.ManagedUser{}, fmt.Errorf("commit user creation: %w", err)
	}
	user.Username, user.DisplayName, user.Email, user.Roles = username, displayName, email, append([]string(nil), roles...)
	user.CreatedAt, user.UpdatedAt = now.UTC(), now.UTC()
	return user, nil
}

func (store *Store) UpdateUserProfile(ctx context.Context, userID int64, username, displayName, email string, now time.Time) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin user profile update: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx,
		"UPDATE sable_users SET username = "+store.placeholder(1)+" WHERE id = "+store.placeholder(2), username, userID)
	if err != nil {
		return fmt.Errorf("update username: %w", err)
	}
	updated, _ := result.RowsAffected()
	if updated != 1 {
		return auth.ErrNotFound
	}
	result, err = transaction.ExecContext(ctx, `
UPDATE sable_user_profiles
SET display_name = `+store.placeholder(1)+`, email = `+store.placeholder(2)+`, updated_at = `+store.placeholder(3)+`
WHERE user_id = `+store.placeholder(4), displayName, email, now.UTC(), userID)
	if err != nil {
		return fmt.Errorf("update user profile: %w", err)
	}
	updated, _ = result.RowsAffected()
	if updated != 1 {
		return auth.ErrNotFound
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit user profile update: %w", err)
	}
	return nil
}

func (store *Store) SetUserRoles(ctx context.Context, userID int64, roles []string, now time.Time) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin role assignment: %w", err)
	}
	defer transaction.Rollback()
	if err := store.replaceUserRoles(ctx, transaction, userID, roles); err != nil {
		return err
	}
	if err := store.ensureAdministratorRemains(ctx, transaction); err != nil {
		return err
	}
	var hasWebAccess bool
	if err := transaction.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1 FROM sable_user_roles AS memberships
    JOIN sable_role_grants AS grants ON grants.role_id = memberships.role_id
    WHERE memberships.user_id = `+store.placeholder(1)+` AND grants.surface = `+store.placeholder(2)+`
)`, userID, auth.SurfaceWeb).Scan(&hasWebAccess); err != nil {
		return fmt.Errorf("inspect user Web UI access: %w", err)
	}
	if !hasWebAccess {
		if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_sessions WHERE user_id = "+store.placeholder(1), userID); err != nil {
			return fmt.Errorf("revoke API-only user sessions: %w", err)
		}
	}
	if _, err := transaction.ExecContext(ctx,
		"UPDATE sable_user_profiles SET updated_at = "+store.placeholder(1)+" WHERE user_id = "+store.placeholder(2), now.UTC(), userID,
	); err != nil {
		return fmt.Errorf("update user role timestamp: %w", err)
	}
	return transaction.Commit()
}

func (store *Store) replaceUserRoles(ctx context.Context, transaction *sql.Tx, userID int64, roles []string) error {
	if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_user_roles WHERE user_id = "+store.placeholder(1), userID); err != nil {
		return fmt.Errorf("clear user roles: %w", err)
	}
	for _, role := range roles {
		result, err := transaction.ExecContext(ctx, `
INSERT INTO sable_user_roles (user_id, role_id)
SELECT `+store.placeholder(1)+`, id FROM sable_roles WHERE name = `+store.placeholder(2), userID, role)
		if err != nil {
			return fmt.Errorf("assign role %q: %w", role, err)
		}
		assigned, err := result.RowsAffected()
		if err != nil || assigned != 1 {
			return fmt.Errorf("role %q was not found", role)
		}
	}
	return nil
}

func (store *Store) SetUserDisabled(ctx context.Context, userID int64, disabled bool, now time.Time) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin user status update: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, `
UPDATE sable_user_profiles SET disabled = `+store.placeholder(1)+`, updated_at = `+store.placeholder(2)+`
WHERE user_id = `+store.placeholder(3), disabled, now.UTC(), userID)
	if err != nil {
		return fmt.Errorf("update user status: %w", err)
	}
	updated, _ := result.RowsAffected()
	if updated != 1 {
		return auth.ErrNotFound
	}
	if disabled {
		if err := store.ensureAdministratorRemains(ctx, transaction); err != nil {
			return err
		}
		if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_sessions WHERE user_id = "+store.placeholder(1), userID); err != nil {
			return fmt.Errorf("revoke disabled user sessions: %w", err)
		}
	}
	return transaction.Commit()
}

func (store *Store) SetUserPassword(ctx context.Context, userID int64, passwordHash string, now time.Time) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin password reset: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx,
		"UPDATE sable_users SET password_hash = "+store.placeholder(1)+" WHERE id = "+store.placeholder(2), passwordHash, userID)
	if err != nil {
		return fmt.Errorf("reset user password: %w", err)
	}
	updated, _ := result.RowsAffected()
	if updated != 1 {
		return auth.ErrNotFound
	}
	if _, err := transaction.ExecContext(ctx,
		"UPDATE sable_user_profiles SET updated_at = "+store.placeholder(1)+" WHERE user_id = "+store.placeholder(2), now.UTC(), userID); err != nil {
		return fmt.Errorf("update password timestamp: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_sessions WHERE user_id = "+store.placeholder(1), userID); err != nil {
		return fmt.Errorf("revoke password-reset sessions: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit password reset: %w", err)
	}
	return nil
}

func (store *Store) DeleteUser(ctx context.Context, userID int64) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin user deletion: %w", err)
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, "DELETE FROM sable_users WHERE id = "+store.placeholder(1), userID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	deleted, _ := result.RowsAffected()
	if deleted != 1 {
		return auth.ErrNotFound
	}
	if err := store.ensureAdministratorRemains(ctx, transaction); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit user deletion: %w", err)
	}
	return nil
}

func (store *Store) ensureAdministratorRemains(ctx context.Context, transaction *sql.Tx) error {
	var count int
	err := transaction.QueryRowContext(ctx, `
SELECT COUNT(*) FROM sable_users AS users
JOIN sable_user_profiles AS profiles ON profiles.user_id = users.id AND profiles.disabled = FALSE
JOIN sable_user_roles AS assignments ON assignments.user_id = users.id
JOIN sable_roles AS roles ON roles.id = assignments.role_id
WHERE roles.name = 'Administrator'`).Scan(&count)
	if err != nil {
		return fmt.Errorf("count active administrators: %w", err)
	}
	if count == 0 {
		return errors.New("at least one active administrator is required")
	}
	return nil
}

func (store *Store) CreateRole(ctx context.Context, name, description string, grants []auth.Grant, now time.Time) (auth.Role, error) {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return auth.Role{}, fmt.Errorf("begin role creation: %w", err)
	}
	defer transaction.Rollback()
	role := auth.Role{Name: name, Description: description, Grants: append([]auth.Grant(nil), grants...)}
	err = transaction.QueryRowContext(ctx, `
INSERT INTO sable_roles (name, description, built_in, created_at)
VALUES (`+store.placeholders(4)+`) RETURNING id`, name, description, false, now.UTC()).Scan(&role.ID)
	if err != nil {
		return auth.Role{}, fmt.Errorf("create role %q: %w", name, err)
	}
	for _, grant := range grants {
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_role_grants (role_id, permission, surface, resource_type, resource_id)
VALUES (`+store.placeholders(5)+`)`, role.ID, grant.Permission, grant.Surface, grant.ResourceType, grant.ResourceID); err != nil {
			return auth.Role{}, fmt.Errorf("assign role grant %q: %w", grant.Permission, err)
		}
		if !slices.Contains(role.Permissions, grant.Permission) {
			role.Permissions = append(role.Permissions, grant.Permission)
		}
	}
	if err := transaction.Commit(); err != nil {
		return auth.Role{}, fmt.Errorf("commit role creation: %w", err)
	}
	return role, nil
}

func (store *Store) SetRoleGrants(ctx context.Context, roleID int64, grants []auth.Grant, _ time.Time) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin role grant update: %w", err)
	}
	defer transaction.Rollback()
	var builtIn bool
	if err := transaction.QueryRowContext(ctx,
		"SELECT built_in FROM sable_roles WHERE id = "+store.placeholder(1), roleID,
	).Scan(&builtIn); errors.Is(err, sql.ErrNoRows) {
		return auth.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("inspect role: %w", err)
	}
	if builtIn {
		return errors.New("built-in groups cannot be changed")
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_role_grants WHERE role_id = "+store.placeholder(1), roleID); err != nil {
		return fmt.Errorf("clear role grants: %w", err)
	}
	for _, grant := range grants {
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_role_grants (role_id, permission, surface, resource_type, resource_id)
VALUES (`+store.placeholders(5)+`)`, roleID, grant.Permission, grant.Surface, grant.ResourceType, grant.ResourceID); err != nil {
			return fmt.Errorf("assign role grant %q: %w", grant.Permission, err)
		}
	}
	return transaction.Commit()
}

func (store *Store) DeleteRole(ctx context.Context, roleID int64) error {
	var builtIn bool
	var users int
	err := store.database.QueryRowContext(ctx, `
SELECT roles.built_in, COUNT(assignments.user_id)
FROM sable_roles AS roles
LEFT JOIN sable_user_roles AS assignments ON assignments.role_id = roles.id
WHERE roles.id = `+store.placeholder(1)+`
GROUP BY roles.built_in`, roleID).Scan(&builtIn, &users)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("inspect role: %w", err)
	}
	if builtIn {
		return errors.New("built-in roles cannot be deleted")
	}
	if users > 0 {
		return errors.New("remove all users from this role before deleting it")
	}
	_, err = store.database.ExecContext(ctx, "DELETE FROM sable_roles WHERE id = "+store.placeholder(1), roleID)
	return err
}

func (store *Store) RevokeSession(ctx context.Context, hashPrefix string) error {
	result, err := store.database.ExecContext(ctx,
		"DELETE FROM sable_sessions WHERE token_hash LIKE "+store.placeholder(1), hashPrefix+"%")
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	deleted, _ := result.RowsAffected()
	if deleted != 1 {
		return auth.ErrNotFound
	}
	return nil
}

func (store *Store) DeleteAPIToken(ctx context.Context, tokenID int64) error {
	result, err := store.database.ExecContext(ctx, "DELETE FROM sable_api_tokens WHERE id = "+store.placeholder(1), tokenID)
	if err != nil {
		return fmt.Errorf("revoke API token: %w", err)
	}
	deleted, _ := result.RowsAffected()
	if deleted != 1 {
		return auth.ErrNotFound
	}
	return nil
}
