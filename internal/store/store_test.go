package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/trustanchor"
)

func TestOpenSQLiteCreatesDatabaseAndRunsMigrations(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "sable.db")
	opened, err := Open(context.Background(), "sqlite", path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer opened.Close()
	if opened.Driver() != "sqlite" {
		t.Fatalf("Driver() = %q, want sqlite", opened.Driver())
	}
}

func TestOpenMigratesExistingQueryLogForDecisions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sable.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`CREATE TABLE sable_query_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		occurred_at TIMESTAMP NOT NULL,
		client_ip TEXT NOT NULL,
		name TEXT NOT NULL,
		record_type INTEGER NOT NULL,
		class INTEGER NOT NULL,
		response_code INTEGER NOT NULL,
		source TEXT NOT NULL,
		protocol TEXT NOT NULL DEFAULT '',
		answer TEXT NOT NULL DEFAULT '',
		duration_us BIGINT NOT NULL
	)`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	opened, err := Open(context.Background(), "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	hasDecision, err := opened.tableHasColumn(context.Background(), "sable_query_log", "decision")
	if err != nil || !hasDecision {
		t.Fatalf("decision column = %v, %v", hasDecision, err)
	}
	_, err = opened.database.Exec(`INSERT INTO sable_query_log
		(occurred_at, client_ip, name, record_type, class, response_code, source, protocol, answer, duration_us)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, time.Now(), "192.0.2.10", "legacy.example", 1, 1, 0, "cache", "UDP", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	page, err := opened.QueryEvents(context.Background(), querylog.Filter{Page: 1, PageSize: 25})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].Decision != (querylog.Decision{}) {
		t.Fatalf("legacy query decision = %+v, %v", page.Entries, err)
	}
}

func TestBuiltInAPIAdministratorIsAPISurfaceOnly(t *testing.T) {
	t.Parallel()

	opened, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	roles, err := opened.ListRoles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var apiAdministrator *auth.Role
	for index := range roles {
		if roles[index].Name == "API Administrator" {
			apiAdministrator = &roles[index]
			break
		}
	}
	if apiAdministrator == nil || !apiAdministrator.BuiltIn {
		t.Fatalf("API Administrator role = %+v, want built-in role", apiAdministrator)
	}
	if len(apiAdministrator.Grants) != 1 || apiAdministrator.Grants[0].Permission != auth.PermissionAll || apiAdministrator.Grants[0].Surface != auth.SurfaceAPI {
		t.Fatalf("API Administrator grants = %+v, want API-only administrator grant", apiAdministrator.Grants)
	}
}

func TestOpenSQLiteAddsUserProfileEmailColumn(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "legacy-auth.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE sable_users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TIMESTAMP NOT NULL);
CREATE TABLE sable_user_profiles (user_id BIGINT PRIMARY KEY, display_name TEXT NOT NULL, disabled BOOLEAN NOT NULL, updated_at TIMESTAMP NOT NULL);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(context.Background(), "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	var email string
	if err := opened.database.QueryRow("SELECT email FROM sable_user_profiles LIMIT 1").Scan(&email); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("email column query error = %v", err)
	}
}

func TestOpenSQLiteReplacesScopedAPITokenSchema(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "legacy-tokens.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE sable_api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP
);`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(context.Background(), "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	hasScopes, err := opened.tableHasColumn(context.Background(), "sable_api_tokens", "scopes")
	if err != nil {
		t.Fatal(err)
	}
	if hasScopes {
		t.Fatal("legacy API token scopes column remains after migration")
	}
	var tokenRoleTable string
	if err := opened.database.QueryRow(`
SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'sable_api_token_roles'`).Scan(&tokenRoleTable); err != nil {
		t.Fatalf("API token group table was not created: %v", err)
	}
}

func TestOpenSQLiteMigratesTokenExpirationToNullable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "token-expiration.db")
	opened, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	service, err := auth.NewService(opened, auth.Options{SessionTTL: time.Hour, TokenTTL: 24 * time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := service.Setup(ctx, "admin", "correct horse battery staple", "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	administrator, err := service.AuthenticateSession(ctx, credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.CreateAPIToken(ctx, administrator, administrator.UserID, "existing", []string{"Administrator"}, auth.APITokenExpiration{}, "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
PRAGMA foreign_keys=OFF;
DROP TABLE sable_api_token_roles;
ALTER TABLE sable_api_tokens RENAME TO sable_api_tokens_nullable;
CREATE TABLE sable_api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES sable_users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP
);
INSERT INTO sable_api_tokens SELECT * FROM sable_api_tokens_nullable;
DROP TABLE sable_api_tokens_nullable;`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	nullable, err := reopened.apiTokenExpirationNullable(ctx)
	if err != nil || !nullable {
		t.Fatalf("API token expiration nullable = %t, error = %v", nullable, err)
	}
	var tokenCount int
	if err := reopened.database.QueryRow(`SELECT COUNT(*) FROM sable_api_tokens WHERE name = 'existing'`).Scan(&tokenCount); err != nil {
		t.Fatal(err)
	}
	if tokenCount != 1 {
		t.Fatalf("preserved token count = %d, want 1", tokenCount)
	}
}

func TestTrustAnchorSnapshotPersistsAcrossOpen(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sable.db")
	opened, err := Open(context.Background(), "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	snapshot := trustanchor.Snapshot{
		Status: trustanchor.Status{
			Owner: ".", Initialized: true, LastSuccess: now,
			NextRefresh: now.Add(time.Hour), OriginalTTLSeconds: 7200,
			SignatureValiditySeconds: 14400,
		},
		Anchors: []trustanchor.Anchor{{
			Owner: ".", KeyID: "key-1", DNSKEY: ". DNSKEY 257 3 13 public", State: trustanchor.StateAddPending,
			FirstSeen: now, HoldDownUntil: now.Add(30 * 24 * time.Hour), LastSeen: now,
			SourceKeyIDs: []string{"key-0"},
		}},
	}
	if err := opened.SaveTrustAnchorSnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, err := reopened.LoadTrustAnchorSnapshot(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Status.Initialized || loaded.Status.Pending != 1 || len(loaded.Anchors) != 1 || len(loaded.Anchors[0].SourceKeyIDs) != 1 {
		t.Fatalf("loaded snapshot = %+v", loaded)
	}
}

func TestAuthenticationLifecyclePersistsHashedCredentials(t *testing.T) {
	t.Parallel()

	opened, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer opened.Close()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	service, err := auth.NewService(opened, auth.Options{
		SessionTTL: time.Hour, TokenTTL: 24 * time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	required, err := service.SetupRequired(context.Background())
	if err != nil || !required {
		t.Fatalf("SetupRequired() = %v, %v", required, err)
	}
	credentials, err := service.Setup(
		context.Background(), "Admin", "correct horse battery staple", "192.0.2.1", "test",
	)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	principal, err := service.AuthenticateSession(context.Background(), credentials.SessionToken)
	if err != nil {
		t.Fatalf("AuthenticateSession() error = %v", err)
	}
	if principal.Username != "admin" || !service.ValidateCSRF(principal, credentials.CSRFToken) {
		t.Fatalf("principal = %+v, want admin with valid CSRF", principal)
	}
	if !auth.HasPermission(principal, auth.PermissionAll) {
		t.Fatalf("initial administrator permissions = %v, want full access", principal.Permissions)
	}
	if err := service.CreateRole(context.Background(), principal, "Metrics API", "Prometheus access", []auth.Grant{{
		Permission: auth.PermissionMetricsRead, Surface: auth.SurfaceAPI,
	}}, "192.0.2.1", "test"); err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	if err := service.SetUserRoles(context.Background(), principal, principal.UserID, []string{"Administrator", "Metrics API"}, "192.0.2.1", "test"); err != nil {
		t.Fatalf("SetUserRoles() error = %v", err)
	}
	token, tokenExpires, err := service.CreateAPIToken(
		context.Background(), principal, principal.UserID, "prometheus", []string{"Metrics API"}, auth.APITokenExpiration{}, "192.0.2.1", "test",
	)
	if err != nil {
		t.Fatalf("CreateAPIToken() error = %v", err)
	}
	if want := now.Add(24 * time.Hour); !tokenExpires.Equal(want) {
		t.Fatalf("default token expiration = %s, want %s", tokenExpires, want)
	}
	tokenPrincipal, err := service.AuthenticateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("AuthenticateToken(metrics) error = %v", err)
	}
	if !auth.HasPermission(tokenPrincipal, auth.PermissionMetricsRead) || auth.HasPermission(tokenPrincipal, auth.PermissionSettingsWrite) {
		t.Fatalf("token permissions = %v, want metrics only", tokenPrincipal.Permissions)
	}
	if err := service.SetUserRoles(context.Background(), principal, principal.UserID, []string{"Administrator"}, "192.0.2.1", "test"); err != nil {
		t.Fatalf("remove token group membership: %v", err)
	}
	if _, err := service.AuthenticateToken(context.Background(), token); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("token remained active after owner left its group: %v", err)
	}
	if err := service.Logout(context.Background(), principal, "192.0.2.1", "test"); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if _, err := service.AuthenticateSession(context.Background(), credentials.SessionToken); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("AuthenticateSession(after logout) error = %v", err)
	}
	var auditEvents int
	if err := opened.database.QueryRow("SELECT COUNT(*) FROM sable_audit_log").Scan(&auditEvents); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if auditEvents < 3 {
		t.Fatalf("audit events = %d, want setup, token, and logout", auditEvents)
	}
}

func TestNonExpiringAPITokenPersistsAndAuthenticates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	opened, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	service, err := auth.NewService(opened, auth.Options{
		SessionTTL: time.Hour, TokenTTL: 24 * time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := service.Setup(ctx, "admin", "correct horse battery staple", "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	administrator, err := service.AuthenticateSession(ctx, credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	secret, expires, err := service.CreateAPIToken(
		ctx, administrator, administrator.UserID, "permanent automation", []string{"Administrator"},
		auth.APITokenExpiration{Never: true}, "192.0.2.1", "test",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !expires.IsZero() {
		t.Fatalf("non-expiring token expires at %s", expires)
	}
	var nullExpiration int
	if err := opened.database.QueryRow(`SELECT expires_at IS NULL FROM sable_api_tokens WHERE name = 'permanent automation'`).Scan(&nullExpiration); err != nil {
		t.Fatal(err)
	}
	if nullExpiration != 1 {
		t.Fatal("non-expiring token was not stored with a NULL expiration")
	}
	now = now.AddDate(100, 0, 0)
	principal, err := service.AuthenticateToken(ctx, secret)
	if err != nil {
		t.Fatalf("authenticate non-expiring token after 100 years: %v", err)
	}
	if principal.Username != "admin" || !auth.HasPermission(principal, auth.PermissionAll) {
		t.Fatalf("non-expiring token principal = %+v", principal)
	}
	snapshot, err := service.Administration(ctx, administrator)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Tokens) != 1 || !snapshot.Tokens[0].ExpiresAt.IsZero() {
		t.Fatalf("administration tokens = %+v, want one non-expiring token", snapshot.Tokens)
	}
}

func TestAdministrationRolesEnforceLeastPrivilegeAndLastAdministrator(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	opened, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	service, err := auth.NewService(opened, auth.Options{SessionTTL: time.Hour, TokenTTL: 24 * time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := service.Setup(ctx, "admin", "correct horse battery staple", "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	administrator, err := service.AuthenticateSession(ctx, credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CreateUser(ctx, administrator, "operator", "DNS Operator", "operator@example.test", "another correct horse battery staple", []string{"Operator"}, "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	operatorCredentials, err := service.Login(ctx, "operator", "another correct horse battery staple", "192.0.2.2", "test")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := service.AuthenticateSession(ctx, operatorCredentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if !auth.HasPermission(operator, auth.PermissionZonesRecords) || auth.HasPermission(operator, auth.PermissionUsersRead) {
		t.Fatalf("operator permissions = %v", operator.Permissions)
	}
	if _, err := service.Administration(ctx, operator); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("operator Administration() error = %v, want forbidden", err)
	}
	if err := service.SetUserRoles(ctx, administrator, operator.UserID, []string{"API Administrator"}, "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticateSession(ctx, operatorCredentials.SessionToken); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("removing all Web grants left session active: %v", err)
	}
	if _, err := service.Login(ctx, "operator", "another correct horse battery staple", "192.0.2.2", "test"); !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("API-only operator login error = %v, want invalid credential", err)
	}
	if err := service.SetUserRoles(ctx, administrator, operator.UserID, []string{"Operator"}, "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	operatorCredentials, err = service.Login(ctx, "operator", "another correct horse battery staple", "192.0.2.3", "test")
	if err != nil {
		t.Fatalf("restored Web grant login error = %v", err)
	}
	snapshot, err := service.Administration(ctx, administrator)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Users) != 2 || len(snapshot.Roles) < len(auth.BuiltInRoles) || len(snapshot.Sessions) != 2 {
		t.Fatalf("administration snapshot = %+v", snapshot)
	}
	if snapshot.Users[1].Email != "operator@example.test" {
		t.Fatalf("operator email = %q", snapshot.Users[1].Email)
	}
	if err := service.UpdateUserProfile(ctx, administrator, operator.UserID, "operator", "DNS Operations", "operations@example.test", "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	snapshot, err = service.Administration(ctx, administrator)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Users[1].DisplayName != "DNS Operations" || snapshot.Users[1].Email != "operations@example.test" {
		t.Fatalf("updated operator = %+v", snapshot.Users[1])
	}
	if err := service.SetUserRoles(ctx, administrator, administrator.UserID, []string{"Auditor"}, "192.0.2.1", "test"); err == nil || !strings.Contains(err.Error(), "active administrator") {
		t.Fatalf("remove final administrator error = %v", err)
	}
	if err := service.SetUserDisabled(ctx, administrator, administrator.UserID, true, "192.0.2.1", "test"); err == nil {
		t.Fatal("administrator disabled own account")
	}
	if err := service.SetUserPassword(ctx, administrator, operator.UserID, "replacement correct horse battery staple", "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticateSession(ctx, operatorCredentials.SessionToken); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("password reset left old session active: %v", err)
	}
	if _, err := service.Login(ctx, "operator", "another correct horse battery staple", "192.0.2.2", "test"); !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("old password login error = %v", err)
	}
	if _, err := service.Login(ctx, "operator", "replacement correct horse battery staple", "192.0.2.2", "test"); err != nil {
		t.Fatalf("replacement password login error = %v", err)
	}
	if err := service.DeleteUser(ctx, administrator, operator.UserID, "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(ctx, "operator", "replacement correct horse battery staple", "192.0.2.2", "test"); !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("deleted user login error = %v", err)
	}
}

func TestAdministratorCreatesAPITokenForAnotherUser(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	opened, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	service, err := auth.NewService(opened, auth.Options{SessionTTL: time.Hour, TokenTTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := service.Setup(ctx, "admin", "correct horse battery staple", "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	administrator, err := service.AuthenticateSession(ctx, credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CreateUser(ctx, administrator, "automation", "Automation", "", "", []string{"API Administrator"}, "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Administration(ctx, administrator)
	if err != nil {
		t.Fatal(err)
	}
	var ownerID int64
	for _, user := range snapshot.Users {
		if user.Username == "automation" {
			ownerID = user.ID
			break
		}
	}
	if ownerID == 0 {
		t.Fatal("automation user was not created")
	}
	if _, err := service.Login(ctx, "automation", "any password is still unusable", "192.0.2.1", "test"); !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("API-only user login error = %v, want invalid credential", err)
	}
	if err := service.CreateUser(ctx, administrator, "missing-password", "Missing Password", "", "", []string{"Operator"}, "192.0.2.1", "test"); err == nil || !strings.Contains(err.Error(), "password is required") {
		t.Fatalf("Web-capable user without password error = %v", err)
	}
	secret, _, err := service.CreateAPIToken(ctx, administrator, ownerID, "deployment", []string{"API Administrator"}, auth.APITokenExpiration{}, "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	tokenPrincipal, err := service.AuthenticateToken(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if tokenPrincipal.UserID != ownerID || tokenPrincipal.Username != "automation" || tokenPrincipal.Surface != auth.SurfaceAPI || !auth.HasPermission(tokenPrincipal, auth.PermissionAll) {
		t.Fatalf("token principal = %+v, want API administrator owned by automation", tokenPrincipal)
	}
	readOnly := auth.Principal{UserID: 999, Permissions: []string{auth.PermissionUsersRead}}
	if _, _, err := service.CreateAPIToken(ctx, readOnly, ownerID, "forbidden", []string{"API Administrator"}, auth.APITokenExpiration{}, "192.0.2.1", "test"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("read-only cross-user token creation error = %v, want forbidden", err)
	}
}

func TestUserSelfServiceProfilePasswordAndTokens(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	opened, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	service, err := auth.NewService(opened, auth.Options{SessionTTL: time.Hour, TokenTTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := service.Setup(ctx, "admin", "correct horse battery staple", "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := service.AuthenticateSession(ctx, credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateOwnProfile(ctx, principal, "Sable Administrator", "admin@example.test", "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	profile, err := service.Profile(ctx, principal)
	if err != nil {
		t.Fatal(err)
	}
	if profile.User.DisplayName != "Sable Administrator" || profile.User.Email != "admin@example.test" {
		t.Fatalf("self profile = %+v", profile.User)
	}
	if _, _, err := service.CreateAPIToken(ctx, principal, 0, "invalid", []string{"Operator"}, auth.APITokenExpiration{}, "192.0.2.1", "test"); err == nil {
		t.Fatal("created token using a group not assigned to the owner")
	}
	if _, _, err := service.CreateAPIToken(ctx, principal, 0, "automation", []string{"Administrator"}, auth.APITokenExpiration{}, "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	profile, err = service.Profile(ctx, principal)
	if err != nil || len(profile.Tokens) != 1 {
		t.Fatalf("profile tokens = %+v error=%v", profile.Tokens, err)
	}
	if err := service.RevokeOwnAPIToken(ctx, principal, profile.Tokens[0].ID, "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	if err := service.ChangeOwnPassword(ctx, principal, "wrong password", "replacement correct horse battery staple", "192.0.2.1", "test"); !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("wrong current password error = %v", err)
	}
	if err := service.ChangeOwnPassword(ctx, principal, "correct horse battery staple", "replacement correct horse battery staple", "192.0.2.1", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticateSession(ctx, credentials.SessionToken); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("password change left old session active: %v", err)
	}
	if _, err := service.Login(ctx, "admin", "replacement correct horse battery staple", "192.0.2.1", "test"); err != nil {
		t.Fatalf("new password login error = %v", err)
	}
}

func TestWriteQueryEventsPersistsBatch(t *testing.T) {
	t.Parallel()

	opened, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer opened.Close()
	events := []querylog.Event{
		{
			OccurredAt: time.Now(), ClientIP: "192.0.2.10", Name: "example.com",
			RecordType: 1, Class: 1, ResponseCode: 0, Source: querylog.SourceCache,
			Protocol: "UDP", Answer: "A 192.0.2.20", Duration: 50 * time.Microsecond,
			Decision: querylog.Decision{Policy: querylog.PolicyNoMatch, Cache: querylog.CacheHit, Resolver: querylog.ResolverCache},
		},
		{
			OccurredAt: time.Now(), ClientIP: "192.0.2.11", Name: "blocked.example",
			RecordType: 28, Class: 1, ResponseCode: 3, Source: querylog.SourceBlocked,
			Duration: 20 * time.Microsecond,
		},
	}
	if err := opened.WriteQueryEvents(context.Background(), events); err != nil {
		t.Fatalf("WriteQueryEvents() error = %v", err)
	}
	var count int
	if err := opened.database.QueryRow("SELECT COUNT(*) FROM sable_query_log").Scan(&count); err != nil {
		t.Fatalf("count query log rows: %v", err)
	}
	if count != len(events) {
		t.Fatalf("query log rows = %d, want %d", count, len(events))
	}
	recent, err := opened.RecentQueryEvents(context.Background(), 1)
	if err != nil {
		t.Fatalf("RecentQueryEvents() error = %v", err)
	}
	if len(recent) != 1 || recent[0].Name != "blocked.example" {
		t.Fatalf("RecentQueryEvents() = %+v, want newest event", recent)
	}
	filtered, err := opened.QueryEvents(context.Background(), querylog.Filter{
		Page: 1, PageSize: 25, Name: "example.com", Protocol: "udp", RecordTypes: []uint16{1},
	})
	if err != nil {
		t.Fatalf("QueryEvents() error = %v", err)
	}
	if filtered.TotalEntries != 1 || len(filtered.Entries) != 1 || filtered.Entries[0].Protocol != "UDP" || filtered.Entries[0].Answer != "A 192.0.2.20" || filtered.Entries[0].Decision.Cache != querylog.CacheHit {
		t.Fatalf("QueryEvents() = %+v, want filtered UDP answer", filtered)
	}
	if err := opened.PruneQueryEvents(context.Background(), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("PruneQueryEvents() error = %v", err)
	}
	if err := opened.database.QueryRow("SELECT COUNT(*) FROM sable_query_log").Scan(&count); err != nil {
		t.Fatalf("count pruned query log rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("query log rows after prune = %d, want 0", count)
	}
}

func TestReplaceCachedResponsesRoundTripAndClear(t *testing.T) {
	t.Parallel()

	opened, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	now := time.Date(2026, time.August, 8, 0, 0, 0, 0, time.UTC)
	want := []CachedResponse{{
		RequestWire: []byte{1, 2, 3}, ResponseWire: []byte{4, 5, 6},
		StoredAt: now, ExpiresAt: now.Add(time.Minute), StaleUntil: now.Add(time.Hour),
	}}
	if err := opened.ReplaceCachedResponses(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := opened.CachedResponses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].RequestWire) != string(want[0].RequestWire) ||
		!got[0].ExpiresAt.Equal(want[0].ExpiresAt) || !got[0].StaleUntil.Equal(want[0].StaleUntil) {
		t.Fatalf("CachedResponses() = %+v, want %+v", got, want)
	}
	if err := opened.ReplaceCachedResponses(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	got, err = opened.CachedResponses(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("CachedResponses() after clear = %+v, %v", got, err)
	}
}

func TestSQLitePragmasReachEveryPooledConnection(t *testing.T) {
	t.Parallel()

	opened, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	// Connections are held open together so the pool has to make new ones
	// rather than handing back the connection that ran the migrations.
	ctx := context.Background()
	connections := make([]*sql.Conn, 0, 4)
	defer func() {
		for _, connection := range connections {
			connection.Close()
		}
	}()
	for range cap(connections) {
		connection, err := opened.database.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	for index, connection := range connections {
		var timeout, foreignKeys int
		var journal string
		if err := connection.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&timeout); err != nil {
			t.Fatal(err)
		}
		if err := connection.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			t.Fatal(err)
		}
		if err := connection.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
			t.Fatal(err)
		}
		if timeout != 5000 || foreignKeys != 1 || !strings.EqualFold(journal, "wal") {
			t.Fatalf("connection %d: busy_timeout = %d, foreign_keys = %d, journal_mode = %q", index, timeout, foreignKeys, journal)
		}
	}
}

func TestSQLiteDSNLeavesOperatorPragmasAlone(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		dsn  string
		want []string
	}{
		"plain path": {
			dsn:  "data/sable.db",
			want: []string{"_pragma=journal_mode%28WAL%29", "_pragma=busy_timeout%285000%29", "_pragma=foreign_keys%281%29"},
		},
		"pragma form": {
			dsn:  "data/sable.db?_pragma=busy_timeout(20000)",
			want: []string{"_pragma=journal_mode%28WAL%29", "_pragma=foreign_keys%281%29"},
		},
		"shorthand form": {
			dsn:  "data/sable.db?_busy_timeout=20000&_fk=0",
			want: []string{"_pragma=journal_mode%28WAL%29"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := sqliteDSN(test.dsn)
			if !strings.HasPrefix(got, test.dsn) {
				t.Fatalf("sqliteDSN(%q) = %q, want it to keep the configured DSN", test.dsn, got)
			}
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Fatalf("sqliteDSN(%q) = %q, want it to carry %s", test.dsn, got, want)
				}
			}
			if strings.Count(got, "_pragma=busy_timeout") > 1 || strings.Count(got, "_pragma=foreign_keys") > 1 {
				t.Fatalf("sqliteDSN(%q) = %q, want no repeated pragma", test.dsn, got)
			}
			if strings.Count(got, "?") != 1 {
				t.Fatalf("sqliteDSN(%q) = %q, want the settings appended to one query", test.dsn, got)
			}
		})
	}
}
