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
	rows, err := store.database.QueryContext(ctx, `
SELECT users.id, users.username, users.password_hash, users.created_at,
       profiles.display_name, profiles.email, profiles.disabled, profiles.password_login, profiles.updated_at
FROM sable_users AS users
JOIN sable_user_profiles AS profiles ON profiles.user_id = users.id
ORDER BY users.id`)
	if err != nil {
		return AuthorizationState{}, fmt.Errorf("export authorization users: %w", err)
	}
	for rows.Next() {
		var user AuthorizationUser
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt, &user.DisplayName,
			&user.Email, &user.Disabled, &user.PasswordLogin, &user.UpdatedAt); err != nil {
			rows.Close()
			return AuthorizationState{}, fmt.Errorf("scan authorization user: %w", err)
		}
		user.CreatedAt = user.CreatedAt.UTC()
		user.UpdatedAt = user.UpdatedAt.UTC()
		user.RoleIDs = []int64{}
		user.Identities = []AuthorizationIdentity{}
		state.Users = append(state.Users, user)
	}
	if err := rows.Close(); err != nil {
		return AuthorizationState{}, fmt.Errorf("close authorization users: %w", err)
	}
	if err := rows.Err(); err != nil {
		return AuthorizationState{}, fmt.Errorf("iterate authorization users: %w", err)
	}

	rows, err = store.database.QueryContext(ctx, `
SELECT id, name, description, built_in, created_at
FROM sable_roles ORDER BY id`)
	if err != nil {
		return AuthorizationState{}, fmt.Errorf("export authorization roles: %w", err)
	}
	for rows.Next() {
		var role AuthorizationRole
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.BuiltIn, &role.CreatedAt); err != nil {
			rows.Close()
			return AuthorizationState{}, fmt.Errorf("scan authorization role: %w", err)
		}
		role.CreatedAt = role.CreatedAt.UTC()
		role.Grants = []auth.Grant{}
		state.Roles = append(state.Roles, role)
	}
	if err := rows.Close(); err != nil {
		return AuthorizationState{}, fmt.Errorf("close authorization roles: %w", err)
	}
	if err := rows.Err(); err != nil {
		return AuthorizationState{}, fmt.Errorf("iterate authorization roles: %w", err)
	}

	roleIndex := make(map[int64]int, len(state.Roles))
	for index := range state.Roles {
		roleIndex[state.Roles[index].ID] = index
	}
	rows, err = store.database.QueryContext(ctx, `
SELECT role_id, permission, surface, resource_type, resource_id
FROM sable_role_grants
ORDER BY role_id, permission, surface, resource_type, resource_id`)
	if err != nil {
		return AuthorizationState{}, fmt.Errorf("export authorization grants: %w", err)
	}
	for rows.Next() {
		var roleID int64
		var grant auth.Grant
		if err := rows.Scan(&roleID, &grant.Permission, &grant.Surface, &grant.ResourceType, &grant.ResourceID); err != nil {
			rows.Close()
			return AuthorizationState{}, fmt.Errorf("scan authorization grant: %w", err)
		}
		index, found := roleIndex[roleID]
		if !found {
			rows.Close()
			return AuthorizationState{}, fmt.Errorf("authorization grant references missing role %d", roleID)
		}
		state.Roles[index].Grants = append(state.Roles[index].Grants, grant)
	}
	if err := rows.Close(); err != nil {
		return AuthorizationState{}, fmt.Errorf("close authorization grants: %w", err)
	}
	if err := rows.Err(); err != nil {
		return AuthorizationState{}, fmt.Errorf("iterate authorization grants: %w", err)
	}

	userIndex := make(map[int64]int, len(state.Users))
	for index := range state.Users {
		userIndex[state.Users[index].ID] = index
	}
	rows, err = store.database.QueryContext(ctx, `SELECT user_id, role_id FROM sable_user_roles ORDER BY user_id, role_id`)
	if err != nil {
		return AuthorizationState{}, fmt.Errorf("export authorization memberships: %w", err)
	}
	for rows.Next() {
		var userID, roleID int64
		if err := rows.Scan(&userID, &roleID); err != nil {
			rows.Close()
			return AuthorizationState{}, fmt.Errorf("scan authorization membership: %w", err)
		}
		index, found := userIndex[userID]
		if !found {
			rows.Close()
			return AuthorizationState{}, fmt.Errorf("authorization membership references missing user %d", userID)
		}
		state.Users[index].RoleIDs = append(state.Users[index].RoleIDs, roleID)
	}
	if err := rows.Close(); err != nil {
		return AuthorizationState{}, fmt.Errorf("close authorization memberships: %w", err)
	}

	rows, err = store.database.QueryContext(ctx, `
SELECT user_id, provider, subject, issuer, linked_at
FROM sable_user_identities ORDER BY user_id, provider`)
	if err != nil {
		return AuthorizationState{}, fmt.Errorf("export authorization identities: %w", err)
	}
	for rows.Next() {
		var userID int64
		var identity AuthorizationIdentity
		if err := rows.Scan(&userID, &identity.Provider, &identity.Subject, &identity.Issuer, &identity.LinkedAt); err != nil {
			rows.Close()
			return AuthorizationState{}, fmt.Errorf("scan authorization identity: %w", err)
		}
		index, found := userIndex[userID]
		if !found {
			rows.Close()
			return AuthorizationState{}, fmt.Errorf("authorization identity references missing user %d", userID)
		}
		identity.LinkedAt = identity.LinkedAt.UTC()
		state.Users[index].Identities = append(state.Users[index].Identities, identity)
	}
	if err := rows.Close(); err != nil {
		return AuthorizationState{}, fmt.Errorf("close authorization identities: %w", err)
	}
	if err := rows.Err(); err != nil {
		return AuthorizationState{}, fmt.Errorf("iterate authorization memberships: %w", err)
	}

	rows, err = store.database.QueryContext(ctx, `
SELECT id, token_hash, user_id, name, created_at, expires_at
FROM sable_api_tokens ORDER BY id`)
	if err != nil {
		return AuthorizationState{}, fmt.Errorf("export API tokens: %w", err)
	}
	for rows.Next() {
		var token AuthorizationToken
		var expiresAt sql.NullTime
		if err := rows.Scan(&token.ID, &token.TokenHash, &token.UserID, &token.Name, &token.CreatedAt, &expiresAt); err != nil {
			rows.Close()
			return AuthorizationState{}, fmt.Errorf("scan API token: %w", err)
		}
		token.CreatedAt = token.CreatedAt.UTC()
		if expiresAt.Valid {
			expires := expiresAt.Time.UTC()
			token.ExpiresAt = &expires
		}
		token.RoleIDs = []int64{}
		state.Tokens = append(state.Tokens, token)
	}
	if err := rows.Close(); err != nil {
		return AuthorizationState{}, fmt.Errorf("close API tokens: %w", err)
	}
	if err := rows.Err(); err != nil {
		return AuthorizationState{}, fmt.Errorf("iterate API tokens: %w", err)
	}

	tokenIndex := make(map[int64]int, len(state.Tokens))
	for index := range state.Tokens {
		tokenIndex[state.Tokens[index].ID] = index
	}
	rows, err = store.database.QueryContext(ctx, `SELECT token_id, role_id FROM sable_api_token_roles ORDER BY token_id, role_id`)
	if err != nil {
		return AuthorizationState{}, fmt.Errorf("export API token groups: %w", err)
	}
	for rows.Next() {
		var tokenID, roleID int64
		if err := rows.Scan(&tokenID, &roleID); err != nil {
			rows.Close()
			return AuthorizationState{}, fmt.Errorf("scan API token group: %w", err)
		}
		index, found := tokenIndex[tokenID]
		if !found {
			rows.Close()
			return AuthorizationState{}, fmt.Errorf("API token group references missing token %d", tokenID)
		}
		state.Tokens[index].RoleIDs = append(state.Tokens[index].RoleIDs, roleID)
	}
	if err := rows.Close(); err != nil {
		return AuthorizationState{}, fmt.Errorf("close API token groups: %w", err)
	}
	if err := rows.Err(); err != nil {
		return AuthorizationState{}, fmt.Errorf("iterate API token groups: %w", err)
	}
	return state, nil
}

// ReplaceAuthorizationState atomically reconciles durable authorization data
// with the primary. Existing local browser sessions remain valid unless their
// user was removed or their password hash changed.
func (store *Store) ReplaceAuthorizationState(ctx context.Context, state AuthorizationState) error {
	if err := validateAuthorizationState(state); err != nil {
		return err
	}
	transaction, err := store.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin authorization state replacement: %w", err)
	}
	defer transaction.Rollback()

	passwords := map[int64]string{}
	rows, err := transaction.QueryContext(ctx, `SELECT id, password_hash FROM sable_users`)
	if err != nil {
		return fmt.Errorf("read existing authorization users: %w", err)
	}
	for rows.Next() {
		var id int64
		var passwordHash string
		if err := rows.Scan(&id, &passwordHash); err != nil {
			rows.Close()
			return err
		}
		passwords[id] = passwordHash
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}

	lastUsed := map[int64]struct {
		hash string
		at   sql.NullTime
	}{}
	rows, err = transaction.QueryContext(ctx, `SELECT id, token_hash, last_used_at FROM sable_api_tokens`)
	if err != nil {
		return fmt.Errorf("read existing API token activity: %w", err)
	}
	for rows.Next() {
		var id int64
		var hash string
		var at sql.NullTime
		if err := rows.Scan(&id, &hash, &at); err != nil {
			rows.Close()
			return err
		}
		lastUsed[id] = struct {
			hash string
			at   sql.NullTime
		}{hash: hash, at: at}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, statement := range []string{
		"DELETE FROM sable_api_token_roles",
		"DELETE FROM sable_api_tokens",
		"DELETE FROM sable_user_identities",
		"DELETE FROM sable_user_roles",
		"DELETE FROM sable_role_grants",
		"DELETE FROM sable_roles",
	} {
		if _, err := transaction.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("clear replicated authorization state: %w", err)
		}
	}

	incomingUsers := make(map[int64]AuthorizationUser, len(state.Users))
	for _, user := range state.Users {
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
	for _, user := range state.Users {
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

	for _, role := range state.Roles {
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
	for _, user := range state.Users {
		for _, roleID := range user.RoleIDs {
			if _, err := transaction.ExecContext(ctx, `INSERT INTO sable_user_roles (user_id, role_id) VALUES (`+store.placeholders(2)+`)`, user.ID, roleID); err != nil {
				return fmt.Errorf("replace role membership for user %q: %w", user.Username, err)
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
	for _, token := range state.Tokens {
		var expiration any
		if token.ExpiresAt != nil {
			expiration = token.ExpiresAt.UTC()
		}
		var activity any
		if existing, found := lastUsed[token.ID]; found && existing.hash == token.TokenHash && existing.at.Valid {
			activity = existing.at.Time.UTC()
		}
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_api_tokens (id, token_hash, user_id, name, created_at, expires_at, last_used_at)
VALUES (`+store.placeholders(7)+`)`, token.ID, token.TokenHash, token.UserID, token.Name, token.CreatedAt.UTC(), expiration, activity); err != nil {
			return fmt.Errorf("replace API token %q: %w", token.Name, err)
		}
		for _, roleID := range token.RoleIDs {
			if _, err := transaction.ExecContext(ctx, `INSERT INTO sable_api_token_roles (token_id, role_id) VALUES (`+store.placeholders(2)+`)`, token.ID, roleID); err != nil {
				return fmt.Errorf("replace API token group for %q: %w", token.Name, err)
			}
		}
	}
	if state.Initialized {
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_metadata (key, value) VALUES (`+store.placeholders(2)+`)
ON CONFLICT(key) DO UPDATE SET value = excluded.value`, "security_initialized", "true"); err != nil {
			return fmt.Errorf("replace authorization setup state: %w", err)
		}
	} else if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_metadata WHERE key = "+store.placeholder(1), "security_initialized"); err != nil {
		return fmt.Errorf("replace authorization setup state: %w", err)
	}
	if store.driver == "postgres" {
		for _, table := range []string{"sable_users", "sable_roles", "sable_api_tokens"} {
			if _, err := transaction.ExecContext(ctx, `SELECT setval(pg_get_serial_sequence('`+table+`', 'id'), COALESCE(MAX(id), 1), COUNT(*) > 0) FROM `+table); err != nil {
				return fmt.Errorf("advance %s identity sequence: %w", table, err)
			}
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit authorization state replacement: %w", err)
	}
	return nil
}

func validateAuthorizationState(state AuthorizationState) error {
	userIDs := make(map[int64]struct{}, len(state.Users))
	usernames := make(map[string]struct{}, len(state.Users))
	subjects := make(map[string]struct{}, len(state.Users))
	for _, user := range state.Users {
		if user.ID <= 0 || strings.TrimSpace(user.Username) == "" {
			return errors.New("replicated authorization state contains an invalid user")
		}
		// An account needs at least one way in. A password hash was the only
		// possibility before single sign-on; now a federated account has an
		// empty hash and is reached through its linked provider instead.
		if strings.TrimSpace(user.PasswordHash) == "" && len(user.Identities) == 0 {
			return fmt.Errorf("replicated authorization user %q has neither a password nor a linked identity", user.Username)
		}
		if _, found := userIDs[user.ID]; found {
			return fmt.Errorf("replicated authorization state contains duplicate user ID %d", user.ID)
		}
		if _, found := usernames[user.Username]; found {
			return fmt.Errorf("replicated authorization state contains duplicate username %q", user.Username)
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
		userIDs[user.ID] = struct{}{}
		usernames[user.Username] = struct{}{}
	}
	roleIDs := make(map[int64]struct{}, len(state.Roles))
	roleNames := make(map[string]struct{}, len(state.Roles))
	for _, role := range state.Roles {
		if role.ID <= 0 || strings.TrimSpace(role.Name) == "" {
			return errors.New("replicated authorization state contains an invalid role")
		}
		if _, found := roleIDs[role.ID]; found {
			return fmt.Errorf("replicated authorization state contains duplicate role ID %d", role.ID)
		}
		if _, found := roleNames[role.Name]; found {
			return fmt.Errorf("replicated authorization state contains duplicate role name %q", role.Name)
		}
		roleIDs[role.ID] = struct{}{}
		roleNames[role.Name] = struct{}{}
		for _, grant := range role.Grants {
			if grant.Permission == "" || (grant.Surface != auth.SurfaceWeb && grant.Surface != auth.SurfaceAPI) {
				return fmt.Errorf("replicated authorization role %q contains an invalid grant", role.Name)
			}
		}
	}
	for _, user := range state.Users {
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
	tokenIDs := make(map[int64]struct{}, len(state.Tokens))
	tokenHashes := make(map[string]struct{}, len(state.Tokens))
	for _, token := range state.Tokens {
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
	if state.Initialized && len(state.Users) == 0 {
		return errors.New("initialized replicated authorization state has no users")
	}
	return nil
}
