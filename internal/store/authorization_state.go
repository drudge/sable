package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
)

// AuthorizationState is the durable authentication and authorization state
// shared by every cluster node. Browser sessions, audit history, and token
// usage timestamps deliberately remain local to each console.
type AuthorizationState struct {
	Initialized bool                 `json:"initialized"`
	Users       []AuthorizationUser  `json:"users"`
	Roles       []AuthorizationRole  `json:"roles"`
	Tokens      []AuthorizationToken `json:"tokens"`
}

type AuthorizationUser struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	DisplayName  string    `json:"display_name"`
	Email        string    `json:"email"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	RoleIDs      []int64   `json:"role_ids"`
	// PasswordLogin defaults to true so a snapshot written before single
	// sign-on existed restores accounts that can still sign in.
	PasswordLogin bool `json:"password_login"`
	// Identities travel with the account. Without them a promoted replica
	// would not know which provider subject owns which account, and every
	// federated user would silently provision a second account on failover.
	Identities []AuthorizationIdentity `json:"identities,omitempty"`
	Passkeys   []auth.Passkey          `json:"passkeys,omitempty"`
}

// AuthorizationIdentity is one replicated link between an identity provider
// subject and a Sable account.
type AuthorizationIdentity struct {
	Provider string    `json:"provider"`
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	LinkedAt time.Time `json:"linked_at"`
}

type AuthorizationRole struct {
	ID          int64        `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	BuiltIn     bool         `json:"built_in"`
	CreatedAt   time.Time    `json:"created_at"`
	Grants      []auth.Grant `json:"grants"`
}

type AuthorizationToken struct {
	ID        int64      `json:"id"`
	TokenHash string     `json:"token_hash"`
	UserID    int64      `json:"user_id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RoleIDs   []int64    `json:"role_ids"`
}

func (store *Store) ExportAuthorizationState(ctx context.Context) (AuthorizationState, error) {
	initialized, err := store.AdminExists(ctx)
	if err != nil {
		return AuthorizationState{}, err
	}
	state := AuthorizationState{Initialized: initialized, Users: []AuthorizationUser{}, Roles: []AuthorizationRole{}, Tokens: []AuthorizationToken{}}
	// Grants, memberships and identities attach to the users and roles read
	// before them, so the order matters.
	for _, export := range []func(context.Context, *AuthorizationState) error{
		store.exportAuthorizationUsers,
		store.exportAuthorizationRoles,
		store.exportAuthorizationGrants,
		store.exportAuthorizationMemberships,
		store.exportAuthorizationIdentities,
		store.exportAuthorizationPasskeys,
		store.exportAPITokens,
		store.exportAPITokenGroups,
	} {
		if err := export(ctx, &state); err != nil {
			return AuthorizationState{}, err
		}
	}
	return state, nil
}

// exportRows runs one export query, scanning each row into dest and then
// calling row. Database failures are wrapped as "export <plural>", "scan
// <singular>", "close <plural>" and "iterate <plural>"; an error from row is
// returned as it is.
func (store *Store) exportRows(ctx context.Context, plural, singular, query string, dest []any, row func() error) error {
	rows, err := store.database.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("export %s: %w", plural, err)
	}
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			rows.Close()
			return fmt.Errorf("scan %s: %w", singular, err)
		}
		if err := row(); err != nil {
			rows.Close()
			return err
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close %s: %w", plural, err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate %s: %w", plural, err)
	}
	return nil
}

func (store *Store) exportAuthorizationUsers(ctx context.Context, state *AuthorizationState) error {
	var user AuthorizationUser
	return store.exportRows(ctx, "authorization users", "authorization user", `
SELECT users.id, users.username, users.password_hash, users.created_at,
       profiles.display_name, profiles.email, profiles.disabled, profiles.password_login, profiles.updated_at
FROM sable_users AS users
JOIN sable_user_profiles AS profiles ON profiles.user_id = users.id
ORDER BY users.id`,
		[]any{&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt, &user.DisplayName,
			&user.Email, &user.Disabled, &user.PasswordLogin, &user.UpdatedAt},
		func() error {
			exported := user
			exported.CreatedAt = exported.CreatedAt.UTC()
			exported.UpdatedAt = exported.UpdatedAt.UTC()
			exported.RoleIDs = []int64{}
			exported.Identities = []AuthorizationIdentity{}
			state.Users = append(state.Users, exported)
			return nil
		})
}

func (store *Store) exportAuthorizationRoles(ctx context.Context, state *AuthorizationState) error {
	var role AuthorizationRole
	return store.exportRows(ctx, "authorization roles", "authorization role", `
SELECT id, name, description, built_in, created_at
FROM sable_roles ORDER BY id`,
		[]any{&role.ID, &role.Name, &role.Description, &role.BuiltIn, &role.CreatedAt},
		func() error {
			exported := role
			exported.CreatedAt = exported.CreatedAt.UTC()
			exported.Grants = []auth.Grant{}
			state.Roles = append(state.Roles, exported)
			return nil
		})
}

func (store *Store) exportAuthorizationGrants(ctx context.Context, state *AuthorizationState) error {
	roleIndex := make(map[int64]int, len(state.Roles))
	for index := range state.Roles {
		roleIndex[state.Roles[index].ID] = index
	}
	var roleID int64
	var grant auth.Grant
	return store.exportRows(ctx, "authorization grants", "authorization grant", `
SELECT role_id, permission, surface, resource_type, resource_id
FROM sable_role_grants
ORDER BY role_id, permission, surface, resource_type, resource_id`,
		[]any{&roleID, &grant.Permission, &grant.Surface, &grant.ResourceType, &grant.ResourceID},
		func() error {
			index, found := roleIndex[roleID]
			if !found {
				return fmt.Errorf("authorization grant references missing role %d", roleID)
			}
			state.Roles[index].Grants = append(state.Roles[index].Grants, grant)
			return nil
		})
}

func authorizationUserIndex(state *AuthorizationState) map[int64]int {
	userIndex := make(map[int64]int, len(state.Users))
	for index := range state.Users {
		userIndex[state.Users[index].ID] = index
	}
	return userIndex
}

func (store *Store) exportAuthorizationMemberships(ctx context.Context, state *AuthorizationState) error {
	userIndex := authorizationUserIndex(state)
	var userID, roleID int64
	return store.exportRows(ctx, "authorization memberships", "authorization membership",
		`SELECT user_id, role_id FROM sable_user_roles ORDER BY user_id, role_id`,
		[]any{&userID, &roleID},
		func() error {
			index, found := userIndex[userID]
			if !found {
				return fmt.Errorf("authorization membership references missing user %d", userID)
			}
			state.Users[index].RoleIDs = append(state.Users[index].RoleIDs, roleID)
			return nil
		})
}

func (store *Store) exportAuthorizationIdentities(ctx context.Context, state *AuthorizationState) error {
	userIndex := authorizationUserIndex(state)
	var userID int64
	var identity AuthorizationIdentity
	return store.exportRows(ctx, "authorization identities", "authorization identity", `
SELECT user_id, provider, subject, issuer, linked_at
FROM sable_user_identities ORDER BY user_id, provider`,
		[]any{&userID, &identity.Provider, &identity.Subject, &identity.Issuer, &identity.LinkedAt},
		func() error {
			index, found := userIndex[userID]
			if !found {
				return fmt.Errorf("authorization identity references missing user %d", userID)
			}
			exported := identity
			exported.LinkedAt = exported.LinkedAt.UTC()
			state.Users[index].Identities = append(state.Users[index].Identities, exported)
			return nil
		})
}

func (store *Store) exportAuthorizationPasskeys(ctx context.Context, state *AuthorizationState) error {
	for index := range state.Users {
		keys, err := store.PasskeysForUser(ctx, state.Users[index].ID)
		if err != nil {
			return err
		}
		state.Users[index].Passkeys = keys
	}
	return nil
}

func (store *Store) exportAPITokens(ctx context.Context, state *AuthorizationState) error {
	var token AuthorizationToken
	var expiresAt sql.NullTime
	return store.exportRows(ctx, "API tokens", "API token", `
SELECT id, token_hash, user_id, name, created_at, expires_at
FROM sable_api_tokens ORDER BY id`,
		[]any{&token.ID, &token.TokenHash, &token.UserID, &token.Name, &token.CreatedAt, &expiresAt},
		func() error {
			exported := token
			exported.CreatedAt = exported.CreatedAt.UTC()
			if expiresAt.Valid {
				expires := expiresAt.Time.UTC()
				exported.ExpiresAt = &expires
			}
			exported.RoleIDs = []int64{}
			state.Tokens = append(state.Tokens, exported)
			return nil
		})
}

func (store *Store) exportAPITokenGroups(ctx context.Context, state *AuthorizationState) error {
	tokenIndex := make(map[int64]int, len(state.Tokens))
	for index := range state.Tokens {
		tokenIndex[state.Tokens[index].ID] = index
	}
	var tokenID, roleID int64
	return store.exportRows(ctx, "API token groups", "API token group",
		`SELECT token_id, role_id FROM sable_api_token_roles ORDER BY token_id, role_id`,
		[]any{&tokenID, &roleID},
		func() error {
			index, found := tokenIndex[tokenID]
			if !found {
				return fmt.Errorf("API token group references missing token %d", tokenID)
			}
			state.Tokens[index].RoleIDs = append(state.Tokens[index].RoleIDs, roleID)
			return nil
		})
}

// ReplaceAuthorizationState atomically reconciles durable authorization data
// with the primary. Existing local browser sessions remain valid unless their
// user was removed or their password hash changed.
func (store *Store) ReplaceAuthorizationState(ctx context.Context, state AuthorizationState) error {
	if err := validateAuthorizationState(state); err != nil {
		return err
	}
	return store.withTxOptions(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable}, "authorization state replacement", func(transaction *sql.Tx) error {
		localPasskeys, err := store.passkeysInTransaction(ctx, transaction)
		if err != nil {
			return err
		}
		passwords, err := localPasswordHashes(ctx, transaction)
		if err != nil {
			return err
		}
		activity, err := localAPITokenActivity(ctx, transaction)
		if err != nil {
			return err
		}
		if err := clearReplicatedAuthorization(ctx, transaction); err != nil {
			return err
		}
		if err := store.replaceAuthorizationUsers(ctx, transaction, state.Users, passwords); err != nil {
			return err
		}
		if err := store.replaceAuthorizationRoles(ctx, transaction, state.Roles); err != nil {
			return err
		}
		if err := store.replaceAuthorizationLinks(ctx, transaction, state.Users, localPasskeys); err != nil {
			return err
		}
		if err := store.replaceAPITokens(ctx, transaction, state.Tokens, activity); err != nil {
			return err
		}
		return store.finishAuthorizationReplacement(ctx, transaction, state.Initialized)
	})
}

// localPasswordHashes reads each local user's password hash, so a user whose
// hash changes on the primary loses their local sessions.
func localPasswordHashes(ctx context.Context, transaction *sql.Tx) (map[int64]string, error) {
	passwords := map[int64]string{}
	rows, err := transaction.QueryContext(ctx, `SELECT id, password_hash FROM sable_users`)
	if err != nil {
		return nil, fmt.Errorf("read existing authorization users: %w", err)
	}
	for rows.Next() {
		var id int64
		var passwordHash string
		if err := rows.Scan(&id, &passwordHash); err != nil {
			rows.Close()
			return nil, err
		}
		passwords[id] = passwordHash
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return passwords, nil
}

// apiTokenActivity is when a local API token was last used, kept across a
// replacement while the token's hash is unchanged.
type apiTokenActivity struct {
	hash string
	at   sql.NullTime
}

func localAPITokenActivity(ctx context.Context, transaction *sql.Tx) (map[int64]apiTokenActivity, error) {
	activity := map[int64]apiTokenActivity{}
	rows, err := transaction.QueryContext(ctx, `SELECT id, token_hash, last_used_at FROM sable_api_tokens`)
	if err != nil {
		return nil, fmt.Errorf("read existing API token activity: %w", err)
	}
	for rows.Next() {
		var id int64
		var token apiTokenActivity
		if err := rows.Scan(&id, &token.hash, &token.at); err != nil {
			rows.Close()
			return nil, err
		}
		activity[id] = token
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return activity, nil
}

func clearReplicatedAuthorization(ctx context.Context, transaction *sql.Tx) error {
	for _, statement := range []string{
		"DELETE FROM sable_api_token_roles",
		"DELETE FROM sable_api_tokens",
		"DELETE FROM sable_user_identities",
		"DELETE FROM sable_passkeys",
		"DELETE FROM sable_user_roles",
		"DELETE FROM sable_role_grants",
		"DELETE FROM sable_roles",
		// The incoming built-in roles may come from another Sable version,
		// so the next start writes this build's again, as it always did.
		"DELETE FROM sable_metadata WHERE key = '" + builtInRolesKey + "'",
	} {
		if _, err := transaction.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("clear replicated authorization state: %w", err)
		}
	}
	return nil
}

// replaceAuthorizationUsers removes local users the primary no longer has and
// writes the rest under the primary's IDs. Users are updated in place rather
// than deleted so their local sessions survive unless the password changed.
func (store *Store) replaceAuthorizationUsers(ctx context.Context, transaction *sql.Tx, users []AuthorizationUser, passwords map[int64]string) error {
	incomingUsers := make(map[int64]AuthorizationUser, len(users))
	for _, user := range users {
		incomingUsers[user.ID] = user
	}
	for id := range passwords {
		if _, found := incomingUsers[id]; !found {
			if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_users WHERE id = "+store.placeholder(1), id); err != nil {
				return fmt.Errorf("remove obsolete authorization user: %w", err)
			}
		}
	}
	// Free usernames before applying the primary's stable ID mapping.
	// The staging prefix exceeds Sable's maximum username length, so it cannot
	// collide with a valid replicated identity while unique names are remapped.
	if _, err := transaction.ExecContext(ctx, `UPDATE sable_users SET username = '__sable_cluster_replication_staging_username_that_exceeds_sixty_four_characters__' || id`); err != nil {
		return fmt.Errorf("stage authorization usernames: %w", err)
	}
	for _, user := range users {
		_, err := transaction.ExecContext(ctx, `
INSERT INTO sable_users (id, username, password_hash, created_at)
VALUES (`+store.placeholders(4)+`)
ON CONFLICT(id) DO UPDATE SET username = excluded.username, password_hash = excluded.password_hash, created_at = excluded.created_at`,
			user.ID, user.Username, user.PasswordHash, user.CreatedAt.UTC())
		if err != nil {
			return fmt.Errorf("replace authorization user %q: %w", user.Username, err)
		}
		_, err = transaction.ExecContext(ctx, `
INSERT INTO sable_user_profiles (user_id, display_name, email, disabled, password_login, updated_at)
VALUES (`+store.placeholders(6)+`)
ON CONFLICT(user_id) DO UPDATE SET display_name = excluded.display_name, email = excluded.email,
disabled = excluded.disabled, password_login = excluded.password_login, updated_at = excluded.updated_at`,
			user.ID, user.DisplayName, user.Email, user.Disabled, user.PasswordLogin, user.UpdatedAt.UTC())
		if err != nil {
			return fmt.Errorf("replace authorization profile %q: %w", user.Username, err)
		}
		if previous, found := passwords[user.ID]; found && previous != user.PasswordHash {
			if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_sessions WHERE user_id = "+store.placeholder(1), user.ID); err != nil {
				return fmt.Errorf("revoke sessions after credential replacement: %w", err)
			}
		}
	}
	return nil
}

func (store *Store) replaceAuthorizationRoles(ctx context.Context, transaction *sql.Tx, roles []AuthorizationRole) error {
	for _, role := range roles {
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_roles (id, name, description, built_in, created_at)
VALUES (`+store.placeholders(5)+`)`, role.ID, role.Name, role.Description, role.BuiltIn, role.CreatedAt.UTC()); err != nil {
			return fmt.Errorf("replace authorization role %q: %w", role.Name, err)
		}
		for _, grant := range role.Grants {
			if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_role_grants (role_id, permission, surface, resource_type, resource_id)
VALUES (`+store.placeholders(5)+`)`, role.ID, grant.Permission, grant.Surface, grant.ResourceType, grant.ResourceID); err != nil {
				return fmt.Errorf("replace grant for role %q: %w", role.Name, err)
			}
		}
	}
	return nil
}

// replaceAuthorizationLinks writes each user's role memberships, passkeys and
// identity links. Passkeys keep their local sign-in activity.
func (store *Store) replaceAuthorizationLinks(ctx context.Context, transaction *sql.Tx, users []AuthorizationUser, localPasskeys map[string]auth.Passkey) error {
	for _, user := range users {
		for _, roleID := range user.RoleIDs {
			if _, err := transaction.ExecContext(ctx, `INSERT INTO sable_user_roles (user_id, role_id) VALUES (`+store.placeholders(2)+`)`, user.ID, roleID); err != nil {
				return fmt.Errorf("replace role membership for user %q: %w", user.Username, err)
			}
		}
		for _, key := range user.Passkeys {
			key = preservePasskeyActivity(key, localPasskeys[key.ID])
			data, err := json.Marshal(key)
			if err != nil {
				return err
			}
			if _, err := transaction.ExecContext(ctx, "INSERT INTO sable_passkeys (id, user_id, data) VALUES ("+store.placeholders(3)+")", key.ID, user.ID, string(data)); err != nil {
				return err
			}
		}
		for _, identity := range user.Identities {
			if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_user_identities (provider, subject, user_id, issuer, linked_at)
VALUES (`+store.placeholders(5)+`)`, identity.Provider, identity.Subject, user.ID, identity.Issuer, identity.LinkedAt.UTC()); err != nil {
				return fmt.Errorf("replace identity link for user %q: %w", user.Username, err)
			}
		}
	}
	return nil
}

func (store *Store) replaceAPITokens(ctx context.Context, transaction *sql.Tx, tokens []AuthorizationToken, activity map[int64]apiTokenActivity) error {
	for _, token := range tokens {
		var expiration any
		if token.ExpiresAt != nil {
			expiration = token.ExpiresAt.UTC()
		}
		var lastUsed any
		if existing, found := activity[token.ID]; found && existing.hash == token.TokenHash && existing.at.Valid {
			lastUsed = existing.at.Time.UTC()
		}
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_api_tokens (id, token_hash, user_id, name, created_at, expires_at, last_used_at)
VALUES (`+store.placeholders(7)+`)`, token.ID, token.TokenHash, token.UserID, token.Name, token.CreatedAt.UTC(), expiration, lastUsed); err != nil {
			return fmt.Errorf("replace API token %q: %w", token.Name, err)
		}
		for _, roleID := range token.RoleIDs {
			if _, err := transaction.ExecContext(ctx, `INSERT INTO sable_api_token_roles (token_id, role_id) VALUES (`+store.placeholders(2)+`)`, token.ID, roleID); err != nil {
				return fmt.Errorf("replace API token group for %q: %w", token.Name, err)
			}
		}
	}
	return nil
}

// finishAuthorizationReplacement records whether setup is done and, on
// Postgres, moves the identity sequences past the IDs just written.
func (store *Store) finishAuthorizationReplacement(ctx context.Context, transaction *sql.Tx, initialized bool) error {
	if initialized {
		if err := store.setMeta(ctx, transaction, "security_initialized", "true"); err != nil {
			return fmt.Errorf("replace authorization setup state: %w", err)
		}
	} else if err := store.deleteMeta(ctx, transaction, "security_initialized"); err != nil {
		return fmt.Errorf("replace authorization setup state: %w", err)
	}
	if store.driver == "postgres" {
		for _, table := range []string{"sable_users", "sable_roles", "sable_api_tokens"} {
			if _, err := transaction.ExecContext(ctx, `SELECT setval(pg_get_serial_sequence('`+table+`', 'id'), COALESCE(MAX(id), 1), COUNT(*) > 0) FROM `+table); err != nil {
				return fmt.Errorf("advance %s identity sequence: %w", table, err)
			}
		}
	}
	return nil
}

func validateAuthorizationState(state AuthorizationState) error {
	userIDs, err := validateAuthorizationUsers(state.Users)
	if err != nil {
		return err
	}
	roleIDs, err := validateAuthorizationRoles(state.Roles)
	if err != nil {
		return err
	}
	if err := validateAuthorizationMemberships(state.Users, roleIDs); err != nil {
		return err
	}
	if err := validateAuthorizationTokens(state.Tokens, userIDs, roleIDs); err != nil {
		return err
	}
	if state.Initialized && len(state.Users) == 0 {
		return errors.New("initialized replicated authorization state has no users")
	}
	return nil
}

// validateAuthorizationUsers checks each user and their sign-in methods, and
// returns the user IDs for the checks that reference them.
func validateAuthorizationUsers(users []AuthorizationUser) (map[int64]struct{}, error) {
	userIDs := make(map[int64]struct{}, len(users))
	usernames := make(map[string]struct{}, len(users))
	subjects := make(map[string]struct{}, len(users))
	passkeyIDs := make(map[string]bool)
	for _, user := range users {
		if user.ID <= 0 || strings.TrimSpace(user.Username) == "" {
			return nil, errors.New("replicated authorization state contains an invalid user")
		}
		// An account needs at least one way in. A password hash was the only
		// possibility before single sign-on; now a federated account has an
		// empty hash and is reached through its linked provider instead.
		if strings.TrimSpace(user.PasswordHash) == "" && len(user.Identities) == 0 && len(user.Passkeys) == 0 {
			return nil, fmt.Errorf("replicated authorization user %q has neither a password nor a linked identity", user.Username)
		}
		if _, found := userIDs[user.ID]; found {
			return nil, fmt.Errorf("replicated authorization state contains duplicate user ID %d", user.ID)
		}
		if _, found := usernames[user.Username]; found {
			return nil, fmt.Errorf("replicated authorization state contains duplicate username %q", user.Username)
		}
		if err := validateAuthorizationSignIns(user, passkeyIDs, subjects); err != nil {
			return nil, err
		}
		userIDs[user.ID] = struct{}{}
		usernames[user.Username] = struct{}{}
	}
	return userIDs, nil
}

// validateAuthorizationSignIns checks one user's passkeys and identity links,
// recording each in the sets shared across users so duplicates are caught.
func validateAuthorizationSignIns(user AuthorizationUser, passkeyIDs map[string]bool, subjects map[string]struct{}) error {
	for _, key := range user.Passkeys {
		if key.UserID != user.ID || key.ID == "" || key.ID != base64.RawURLEncoding.EncodeToString(key.Credential.ID) || len(key.Credential.PublicKey) == 0 || len(key.UserHandle) == 0 || len(key.UserHandle) > 64 || key.RPID == "" || passkeyIDs[key.ID] {
			return errors.New("replicated authorization state contains an invalid or duplicate passkey")
		}
		passkeyIDs[key.ID] = true
	}
	for _, identity := range user.Identities {
		if strings.TrimSpace(identity.Provider) == "" || strings.TrimSpace(identity.Subject) == "" {
			return fmt.Errorf("replicated authorization user %q has an incomplete identity link", user.Username)
		}
		// The table's primary key would reject this on insert, but a
		// duplicate subject across two accounts means the snapshot itself
		// disagrees about who owns it, and that is worth naming.
		key := identity.Provider + "\x00" + identity.Subject
		if _, found := subjects[key]; found {
			return fmt.Errorf("replicated authorization state links %s/%s to more than one account",
				identity.Provider, identity.Subject)
		}
		subjects[key] = struct{}{}
	}
	return nil
}

func validateAuthorizationRoles(roles []AuthorizationRole) (map[int64]struct{}, error) {
	roleIDs := make(map[int64]struct{}, len(roles))
	roleNames := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		if role.ID <= 0 || strings.TrimSpace(role.Name) == "" {
			return nil, errors.New("replicated authorization state contains an invalid role")
		}
		if _, found := roleIDs[role.ID]; found {
			return nil, fmt.Errorf("replicated authorization state contains duplicate role ID %d", role.ID)
		}
		if _, found := roleNames[role.Name]; found {
			return nil, fmt.Errorf("replicated authorization state contains duplicate role name %q", role.Name)
		}
		roleIDs[role.ID] = struct{}{}
		roleNames[role.Name] = struct{}{}
		for _, grant := range role.Grants {
			if grant.Permission == "" || (grant.Surface != auth.SurfaceWeb && grant.Surface != auth.SurfaceAPI) {
				return nil, fmt.Errorf("replicated authorization role %q contains an invalid grant", role.Name)
			}
		}
	}
	return roleIDs, nil
}

func validateAuthorizationMemberships(users []AuthorizationUser, roleIDs map[int64]struct{}) error {
	for _, user := range users {
		if len(user.RoleIDs) == 0 {
			return fmt.Errorf("replicated authorization user %q has no roles", user.Username)
		}
		for _, roleID := range user.RoleIDs {
			if _, found := roleIDs[roleID]; !found {
				return fmt.Errorf("replicated authorization user %q references missing role %d", user.Username, roleID)
			}
		}
		if !slices.IsSorted(user.RoleIDs) {
			return fmt.Errorf("replicated authorization user %q has unsorted roles", user.Username)
		}
	}
	return nil
}

func validateAuthorizationTokens(tokens []AuthorizationToken, userIDs, roleIDs map[int64]struct{}) error {
	tokenIDs := make(map[int64]struct{}, len(tokens))
	tokenHashes := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		if token.ID <= 0 || token.TokenHash == "" || token.Name == "" {
			return errors.New("replicated authorization state contains an invalid API token")
		}
		if _, found := tokenIDs[token.ID]; found {
			return fmt.Errorf("replicated authorization state contains duplicate API token ID %d", token.ID)
		}
		if _, found := tokenHashes[token.TokenHash]; found {
			return errors.New("replicated authorization state contains duplicate API token hash")
		}
		if _, found := userIDs[token.UserID]; !found {
			return fmt.Errorf("replicated API token %q references missing user %d", token.Name, token.UserID)
		}
		for _, roleID := range token.RoleIDs {
			if _, found := roleIDs[roleID]; !found {
				return fmt.Errorf("replicated API token %q references missing role %d", token.Name, roleID)
			}
		}
		if !slices.IsSorted(token.RoleIDs) {
			return fmt.Errorf("replicated API token %q has unsorted roles", token.Name)
		}
		tokenIDs[token.ID] = struct{}{}
		tokenHashes[token.TokenHash] = struct{}{}
	}
	return nil
}
