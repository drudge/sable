package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
)

// UserByIdentity finds the account an identity provider's subject is bound to.
// This is the only lookup a repeat sign-in performs: the subject is stable
// where a username or an email address at the provider is not.
func (store *Store) UserByIdentity(ctx context.Context, provider, subject string) (auth.User, error) {
	var user auth.User
	err := store.database.QueryRowContext(
		ctx,
		`SELECT users.id, users.username, profiles.display_name, profiles.email, users.password_hash,
       profiles.password_login, EXISTS (
    SELECT 1 FROM sable_user_roles AS memberships
    JOIN sable_role_grants AS grants ON grants.role_id = memberships.role_id
    WHERE memberships.user_id = users.id AND grants.surface = `+store.placeholder(1)+`
)
FROM sable_user_identities AS identities
JOIN sable_users AS users ON users.id = identities.user_id
JOIN sable_user_profiles AS profiles ON profiles.user_id = users.id
WHERE identities.provider = `+store.placeholder(2)+` AND identities.subject = `+store.placeholder(3),
		auth.SurfaceWeb, provider, subject,
	).Scan(&user.ID, &user.Username, &user.DisplayName, &user.Email, &user.PasswordHash, &user.PasswordLogin, &user.LoginAllowed)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, auth.ErrNotFound
	}
	if err != nil {
		return auth.User{}, fmt.Errorf("find linked identity: %w", err)
	}
	return user, nil
}

// UserByEmail finds an account by its stored email address. It exists only for
// the one-time link a first federated sign-in may perform, and the caller must
// have confirmed the provider asserted the address is verified before calling.
func (store *Store) UserByEmail(ctx context.Context, email string) (auth.User, error) {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" {
		return auth.User{}, auth.ErrNotFound
	}
	var user auth.User
	// LOWER on both sides rather than a case-sensitive compare: the local part
	// of an address is technically case sensitive, but no provider treats it
	// that way and neither does anyone typing one into the console.
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
WHERE LOWER(profiles.email) = `+store.placeholder(2),
		auth.SurfaceWeb, normalized,
	).Scan(&user.ID, &user.Username, &user.DisplayName, &user.Email, &user.PasswordHash, &user.PasswordLogin, &user.LoginAllowed)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, auth.ErrNotFound
	}
	if err != nil {
		return auth.User{}, fmt.Errorf("find user by email: %w", err)
	}
	return user, nil
}

// LinkIdentity binds a provider subject to an account. A subject already bound
// to a different account is refused rather than moved: silently repointing it
// would transfer one person's sessions, tokens, and grants to another.
func (store *Store) LinkIdentity(ctx context.Context, provider, subject, issuer string, userID int64, now time.Time) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin identity link: %w", err)
	}
	defer transaction.Rollback()
	var existing int64
	err = transaction.QueryRowContext(ctx,
		"SELECT user_id FROM sable_user_identities WHERE provider = "+store.placeholder(1)+" AND subject = "+store.placeholder(2),
		provider, subject).Scan(&existing)
	switch {
	case err == nil && existing != userID:
		return fmt.Errorf("identity %s/%s is already linked to another account", provider, subject)
	case err == nil:
		if _, err := transaction.ExecContext(ctx,
			"UPDATE sable_user_identities SET issuer = "+store.placeholder(1)+", last_login_at = "+store.placeholder(2)+
				" WHERE provider = "+store.placeholder(3)+" AND subject = "+store.placeholder(4),
			issuer, now.UTC(), provider, subject); err != nil {
			return fmt.Errorf("refresh identity link: %w", err)
		}
	case errors.Is(err, sql.ErrNoRows):
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_user_identities (provider, subject, user_id, issuer, linked_at, last_login_at)
VALUES (`+store.placeholders(6)+`)`, provider, subject, userID, issuer, now.UTC(), now.UTC()); err != nil {
			return fmt.Errorf("link identity: %w", err)
		}
	default:
		return fmt.Errorf("inspect identity link: %w", err)
	}
	return transaction.Commit()
}

// TouchIdentity records that a linked identity signed in, which is what the
// console shows as the provider's last successful sign-in.
func (store *Store) TouchIdentity(ctx context.Context, provider, subject string, now time.Time) error {
	if _, err := store.database.ExecContext(ctx,
		"UPDATE sable_user_identities SET last_login_at = "+store.placeholder(1)+
			" WHERE provider = "+store.placeholder(2)+" AND subject = "+store.placeholder(3),
		now.UTC(), provider, subject); err != nil {
		return fmt.Errorf("record identity sign-in: %w", err)
	}
	return nil
}

// UnlinkIdentity detaches an account from a provider. It refuses to strip the
// last way in: an account with no password and no identity can never sign in
// again, and recovering it needs a database edit.
func (store *Store) UnlinkIdentity(ctx context.Context, userID int64, provider string) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin identity unlink: %w", err)
	}
	defer transaction.Rollback()
	var passwordLogin bool
	if err := transaction.QueryRowContext(ctx,
		"SELECT password_login FROM sable_user_profiles WHERE user_id = "+store.placeholder(1), userID,
	).Scan(&passwordLogin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.ErrNotFound
		}
		return fmt.Errorf("inspect account sign-in methods: %w", err)
	}
	var remaining int
	if err := transaction.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sable_user_identities WHERE user_id = "+store.placeholder(1)+" AND provider <> "+store.placeholder(2),
		userID, provider).Scan(&remaining); err != nil {
		return fmt.Errorf("count remaining identities: %w", err)
	}
	if !passwordLogin && remaining == 0 {
		return errors.New("this account signs in only through that provider; turn password sign-in back on first")
	}
	if _, err := transaction.ExecContext(ctx,
		"DELETE FROM sable_user_identities WHERE user_id = "+store.placeholder(1)+" AND provider = "+store.placeholder(2),
		userID, provider); err != nil {
		return fmt.Errorf("unlink identity: %w", err)
	}
	return transaction.Commit()
}

// IdentitiesForUser lists the providers one account is linked to.
func (store *Store) IdentitiesForUser(ctx context.Context, userID int64) ([]auth.LinkedIdentity, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT provider, subject, issuer, linked_at, last_login_at
FROM sable_user_identities
WHERE user_id = `+store.placeholder(1)+`
ORDER BY provider`, userID)
	if err != nil {
		return nil, fmt.Errorf("list linked identities: %w", err)
	}
	defer rows.Close()
	return scanIdentities(rows)
}

// AllIdentities lists every link on the node, keyed by account. The console
// uses it so the user table can show one badge per row without a query per row.
func (store *Store) AllIdentities(ctx context.Context) (map[int64][]auth.LinkedIdentity, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT user_id, provider, subject, issuer, linked_at, last_login_at
FROM sable_user_identities
ORDER BY user_id, provider`)
	if err != nil {
		return nil, fmt.Errorf("list identities: %w", err)
	}
	defer rows.Close()
	identities := make(map[int64][]auth.LinkedIdentity)
	for rows.Next() {
		var userID int64
		var identity auth.LinkedIdentity
		var lastLogin sql.NullTime
		if err := rows.Scan(&userID, &identity.Provider, &identity.Subject, &identity.Issuer, &identity.LinkedAt, &lastLogin); err != nil {
			return nil, fmt.Errorf("scan identity: %w", err)
		}
		if lastLogin.Valid {
			identity.LastLoginAt = lastLogin.Time
		}
		identities[userID] = append(identities[userID], identity)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identities: %w", err)
	}
	return identities, nil
}

func scanIdentities(rows *sql.Rows) ([]auth.LinkedIdentity, error) {
	identities := make([]auth.LinkedIdentity, 0)
	for rows.Next() {
		var identity auth.LinkedIdentity
		var lastLogin sql.NullTime
		if err := rows.Scan(&identity.Provider, &identity.Subject, &identity.Issuer, &identity.LinkedAt, &lastLogin); err != nil {
			return nil, fmt.Errorf("scan identity: %w", err)
		}
		if lastLogin.Valid {
			identity.LastLoginAt = lastLogin.Time
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identities: %w", err)
	}
	return identities, nil
}

// CreateFederatedUser provisions an account for someone signing in through an
// identity provider for the first time. It has no password hash and password
// sign-in is off, so the only way into it is the provider that created it.
func (store *Store) CreateFederatedUser(
	ctx context.Context,
	username, displayName, email string,
	roles []string,
	provider, subject, issuer string,
	now time.Time,
) (auth.ManagedUser, error) {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return auth.ManagedUser{}, fmt.Errorf("begin federated user creation: %w", err)
	}
	defer transaction.Rollback()
	var user auth.ManagedUser
	if err := transaction.QueryRowContext(ctx, `
INSERT INTO sable_users (username, password_hash, created_at)
VALUES (`+store.placeholders(3)+`) RETURNING id`, username, "", now.UTC()).Scan(&user.ID); err != nil {
		return auth.ManagedUser{}, fmt.Errorf("create federated user %q: %w", username, err)
	}
	if displayName == "" {
		displayName = username
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_user_profiles (user_id, display_name, email, disabled, password_login, updated_at)
VALUES (`+store.placeholders(6)+`)`, user.ID, displayName, email, false, false, now.UTC()); err != nil {
		return auth.ManagedUser{}, fmt.Errorf("create profile for %q: %w", username, err)
	}
	if err := store.replaceUserRoles(ctx, transaction, user.ID, roles); err != nil {
		return auth.ManagedUser{}, err
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_user_identities (provider, subject, user_id, issuer, linked_at, last_login_at)
VALUES (`+store.placeholders(6)+`)`, provider, subject, user.ID, issuer, now.UTC(), now.UTC()); err != nil {
		return auth.ManagedUser{}, fmt.Errorf("link identity for %q: %w", username, err)
	}
	if err := transaction.Commit(); err != nil {
		return auth.ManagedUser{}, fmt.Errorf("commit federated user creation: %w", err)
	}
	user.Username, user.DisplayName, user.Email = username, displayName, email
	user.Roles = append([]string(nil), roles...)
	user.CreatedAt, user.UpdatedAt = now.UTC(), now.UTC()
	return user, nil
}

// SetPasswordLogin turns password sign-in on or off for one account. Turning
// it off is refused unless the account has an identity to sign in with, so
// nobody can strip their own last way in.
func (store *Store) SetPasswordLogin(ctx context.Context, userID int64, allowed bool, now time.Time) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sign-in method update: %w", err)
	}
	defer transaction.Rollback()
	if !allowed {
		var identities int
		if err := transaction.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM sable_user_identities WHERE user_id = "+store.placeholder(1), userID,
		).Scan(&identities); err != nil {
			return fmt.Errorf("count linked identities: %w", err)
		}
		if identities == 0 {
			return errors.New("link an identity provider to this account before turning off password sign-in")
		}
		if err := store.ensurePasswordAdministratorRemains(ctx, transaction, userID); err != nil {
			return err
		}
	}
	result, err := transaction.ExecContext(ctx,
		"UPDATE sable_user_profiles SET password_login = "+store.placeholder(1)+", updated_at = "+store.placeholder(2)+
			" WHERE user_id = "+store.placeholder(3), allowed, now.UTC(), userID)
	if err != nil {
		return fmt.Errorf("update sign-in method: %w", err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return auth.ErrNotFound
	}
	return transaction.Commit()
}

// ensurePasswordAdministratorRemains keeps one administrator able to sign in
// with a password. Single sign-on depends on a service Sable does not run: if
// the provider is down, its certificate expires, or a group claim changes
// shape, an all-SSO deployment has nobody who can get in and fix it.
func (store *Store) ensurePasswordAdministratorRemains(ctx context.Context, transaction *sql.Tx, excluding int64) error {
	var count int
	err := transaction.QueryRowContext(ctx, `
SELECT COUNT(*) FROM sable_users AS users
JOIN sable_user_profiles AS profiles ON profiles.user_id = users.id
    AND profiles.disabled = FALSE AND profiles.password_login = TRUE
JOIN sable_user_roles AS assignments ON assignments.user_id = users.id
JOIN sable_roles AS roles ON roles.id = assignments.role_id
WHERE roles.name = 'Administrator' AND users.id <> `+store.placeholder(1)+`
    AND users.password_hash <> ''`, excluding).Scan(&count)
	if err != nil {
		return fmt.Errorf("count password administrators: %w", err)
	}
	if count == 0 {
		return errors.New(
			"at least one administrator must keep password sign-in, so a problem at the identity provider cannot lock everyone out")
	}
	return nil
}

// ReconcileManagedRoles applies the roles an identity provider grants without
// disturbing anything assigned by hand. Only roles named in managed are added
// or removed; a per-zone role somebody set up in the console is outside that
// set and survives untouched.
func (store *Store) ReconcileManagedRoles(ctx context.Context, userID int64, managed, granted []string, now time.Time) ([]string, error) {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin role reconcile: %w", err)
	}
	defer transaction.Rollback()
	rows, err := transaction.QueryContext(ctx, `
SELECT roles.name FROM sable_user_roles AS assignments
JOIN sable_roles AS roles ON roles.id = assignments.role_id
WHERE assignments.user_id = `+store.placeholder(1), userID)
	if err != nil {
		return nil, fmt.Errorf("read current roles: %w", err)
	}
	current := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan current role: %w", err)
		}
		current = append(current, name)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate current roles: %w", err)
	}
	rows.Close()

	desired := make([]string, 0, len(current)+len(granted))
	for _, role := range current {
		// A role the provider manages is kept only if it is still granted;
		// a role outside the managed set is always kept.
		if !slices.Contains(managed, role) || slices.Contains(granted, role) {
			desired = append(desired, role)
		}
	}
	for _, role := range granted {
		if !slices.Contains(desired, role) {
			desired = append(desired, role)
		}
	}
	slices.Sort(desired)
	slices.Sort(current)
	if slices.Equal(current, desired) {
		return current, nil
	}
	if err := store.replaceUserRoles(ctx, transaction, userID, desired); err != nil {
		return nil, err
	}
	if err := store.ensureAdministratorRemains(ctx, transaction); err != nil {
		return nil, err
	}
	if _, err := transaction.ExecContext(ctx,
		"UPDATE sable_user_profiles SET updated_at = "+store.placeholder(1)+" WHERE user_id = "+store.placeholder(2),
		now.UTC(), userID); err != nil {
		return nil, fmt.Errorf("update role timestamp: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return nil, fmt.Errorf("commit role reconcile: %w", err)
	}
	return desired, nil
}

// UpdateFederatedProfile refreshes the display name and email a provider
// asserts. The username is left alone: it is what an operator sees in the
// console and in audit records, and renaming it under them on every sign-in
// would make those records hard to follow.
func (store *Store) UpdateFederatedProfile(ctx context.Context, userID int64, displayName, email string, now time.Time) error {
	if strings.TrimSpace(displayName) == "" && strings.TrimSpace(email) == "" {
		return nil
	}
	name := strings.TrimSpace(displayName)
	address := strings.ToLower(strings.TrimSpace(email))
	// Each value is bound twice because SQLite placeholders are positional:
	// the same index cannot be referenced from two places the way $1 can in
	// PostgreSQL, so the argument list repeats instead.
	if _, err := store.database.ExecContext(ctx, `
UPDATE sable_user_profiles
SET display_name = CASE WHEN `+store.placeholder(1)+` = '' THEN display_name ELSE `+store.placeholder(2)+` END,
    email = CASE WHEN `+store.placeholder(3)+` = '' THEN email ELSE `+store.placeholder(4)+` END,
    updated_at = `+store.placeholder(5)+`
WHERE user_id = `+store.placeholder(6),
		name, name, address, address, now.UTC(), userID); err != nil {
		return fmt.Errorf("refresh federated profile: %w", err)
	}
	return nil
}
