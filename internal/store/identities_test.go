package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
)

func openIdentityStore(t *testing.T) *Store {
	t.Helper()
	opened, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { opened.Close() })
	return opened
}

// seedAdministrator creates the local administrator every deployment starts
// with, which most of these tests need as the account that keeps a password.
func seedAdministrator(t *testing.T, store *Store) auth.ManagedUser {
	t.Helper()
	admin, err := store.CreateUser(context.Background(), "nick", "Nick", "nick@example.com", "argon2id$hash",
		[]string{"Administrator"}, time.Now())
	if err != nil {
		t.Fatalf("create administrator: %v", err)
	}
	return admin
}

func TestFederatedUserIsProvisionedWithoutAPassword(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	seedAdministrator(t, store)

	created, err := store.CreateFederatedUser(ctx, "casey", "Casey Jones", "casey@example.com",
		[]string{"Auditor"}, "pocket-id", "subject-1", "https://id.example.com", time.Now())
	if err != nil {
		t.Fatalf("provision federated user: %v", err)
	}

	found, err := store.UserByIdentity(ctx, "pocket-id", "subject-1")
	if err != nil {
		t.Fatalf("look up by identity: %v", err)
	}
	if found.ID != created.ID {
		t.Errorf("identity resolved to user %d, want %d", found.ID, created.ID)
	}
	if found.PasswordHash != "" {
		t.Error("a provisioned account was given a password hash")
	}
	if found.PasswordLogin {
		t.Error("a provisioned account may sign in with a password")
	}
}

func TestUserByIdentityReportsNotFoundForAnUnknownSubject(t *testing.T) {
	store := openIdentityStore(t)
	if _, err := store.UserByIdentity(context.Background(), "pocket-id", "nobody"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("error = %v, want %v", err, auth.ErrNotFound)
	}
}

// Repointing a subject at a second account would hand that account's sessions,
// tokens, and grants to whoever the provider says holds the subject now.
func TestLinkIdentityRefusesToMoveASubjectBetweenAccounts(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	first := seedAdministrator(t, store)
	second, err := store.CreateUser(ctx, "casey", "Casey", "casey@example.com", "hash", []string{"Auditor"}, time.Now())
	if err != nil {
		t.Fatalf("create second user: %v", err)
	}
	if err := store.LinkIdentity(ctx, "pocket-id", "subject-1", "https://id.example.com", first.ID, time.Now()); err != nil {
		t.Fatalf("link identity: %v", err)
	}
	err = store.LinkIdentity(ctx, "pocket-id", "subject-1", "https://id.example.com", second.ID, time.Now())
	if err == nil {
		t.Fatal("the subject was moved to another account, want a rejection")
	}
	if !strings.Contains(err.Error(), "already linked") {
		t.Fatalf("error = %q, want it to mention the existing link", err)
	}
}

// Relinking the same subject to the same account is what every repeat sign-in
// does, so it has to be accepted.
func TestLinkIdentityIsRepeatable(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	admin := seedAdministrator(t, store)
	for range 3 {
		if err := store.LinkIdentity(ctx, "pocket-id", "subject-1", "https://id.example.com", admin.ID, time.Now()); err != nil {
			t.Fatalf("relink identity: %v", err)
		}
	}
	identities, err := store.IdentitiesForUser(ctx, admin.ID)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("identities = %d, want 1", len(identities))
	}
}

func TestSetPasswordLoginKeepsOneAdministratorAbleToSignIn(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	admin := seedAdministrator(t, store)
	if err := store.LinkIdentity(ctx, "pocket-id", "subject-1", "https://id.example.com", admin.ID, time.Now()); err != nil {
		t.Fatalf("link identity: %v", err)
	}

	err := store.SetPasswordLogin(ctx, admin.ID, false, time.Now())
	if err == nil {
		t.Fatal("the last password administrator was switched to SSO only, want a rejection")
	}
	if !strings.Contains(err.Error(), "lock everyone out") {
		t.Fatalf("error = %q, want it to explain the lockout risk", err)
	}

	// With a second password administrator present, the switch is allowed.
	if _, err := store.CreateUser(ctx, "backup-admin", "Backup", "backup@example.com", "hash",
		[]string{"Administrator"}, time.Now()); err != nil {
		t.Fatalf("create second administrator: %v", err)
	}
	if err := store.SetPasswordLogin(ctx, admin.ID, false, time.Now()); err != nil {
		t.Fatalf("switch to SSO only: %v", err)
	}
}

// Turning off password sign-in for an account with nothing else to sign in
// with would strand it entirely.
func TestSetPasswordLoginRequiresALinkedIdentity(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	seedAdministrator(t, store)
	casey, err := store.CreateUser(ctx, "casey", "Casey", "casey@example.com", "hash", []string{"Auditor"}, time.Now())
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	err = store.SetPasswordLogin(ctx, casey.ID, false, time.Now())
	if err == nil {
		t.Fatal("an account with no identity was switched to SSO only, want a rejection")
	}
	if !strings.Contains(err.Error(), "link an identity provider") {
		t.Fatalf("error = %q, want it to ask for a linked provider", err)
	}
}

func TestUnlinkIdentityRefusesToStripTheLastWayIn(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	seedAdministrator(t, store)
	casey, err := store.CreateFederatedUser(ctx, "casey", "Casey", "casey@example.com",
		[]string{"Auditor"}, "pocket-id", "subject-1", "https://id.example.com", time.Now())
	if err != nil {
		t.Fatalf("provision federated user: %v", err)
	}
	err = store.UnlinkIdentity(ctx, casey.ID, "pocket-id")
	if err == nil {
		t.Fatal("the only sign-in method was removed, want a rejection")
	}
	if !strings.Contains(err.Error(), "password sign-in") {
		t.Fatalf("error = %q, want it to point at password sign-in", err)
	}

	if err := store.SetPasswordLogin(ctx, casey.ID, true, time.Now()); err != nil {
		t.Fatalf("restore password sign-in: %v", err)
	}
	if err := store.UnlinkIdentity(ctx, casey.ID, "pocket-id"); err != nil {
		t.Fatalf("unlink identity: %v", err)
	}
}

// The provider owns the roles it maps and nothing else. A role assigned by
// hand in the console has to survive a sign-in that no longer grants it.
func TestReconcileManagedRolesLeavesHandAssignedRolesAlone(t *testing.T) {
	store := openIdentityStore(t)
	ctx := context.Background()
	seedAdministrator(t, store)
	casey, err := store.CreateFederatedUser(ctx, "casey", "Casey", "casey@example.com",
		[]string{"Auditor", "Operator"}, "pocket-id", "subject-1", "https://id.example.com", time.Now())
	if err != nil {
		t.Fatalf("provision federated user: %v", err)
	}

	// The provider manages Operator only. Viewer was assigned by hand.
	roles, err := store.ReconcileManagedRoles(ctx, casey.ID, []string{"Operator"}, nil, time.Now())
	if err != nil {
		t.Fatalf("reconcile roles: %v", err)
	}
	if strings.Join(roles, ",") != "Auditor" {
		t.Fatalf("roles = %v, want Auditor to survive and Operator to be dropped", roles)
	}

	// Granting it back restores it without disturbing Viewer.
	roles, err = store.ReconcileManagedRoles(ctx, casey.ID, []string{"Operator"}, []string{"Operator"}, time.Now())
	if err != nil {
		t.Fatalf("reconcile roles: %v", err)
	}
	if strings.Join(roles, ",") != "Auditor,Operator" {
		t.Fatalf("roles = %v, want Auditor and Operator", roles)
	}
}

// A promoted replica has to know which provider subject owns which account, or
// every federated user provisions a duplicate on their next sign-in.
func TestAuthorizationStateCarriesIdentitiesAndSignInMethods(t *testing.T) {
	source := openIdentityStore(t)
	ctx := context.Background()
	seedAdministrator(t, source)
	if _, err := source.CreateFederatedUser(ctx, "casey", "Casey", "casey@example.com",
		[]string{"Auditor"}, "pocket-id", "subject-1", "https://id.example.com", time.Now()); err != nil {
		t.Fatalf("provision federated user: %v", err)
	}

	state, err := source.ExportAuthorizationState(ctx)
	if err != nil {
		t.Fatalf("export state: %v", err)
	}

	replica := openIdentityStore(t)
	if err := replica.ReplaceAuthorizationState(ctx, state); err != nil {
		t.Fatalf("replace state on the replica: %v", err)
	}

	restored, err := replica.UserByIdentity(ctx, "pocket-id", "subject-1")
	if err != nil {
		t.Fatalf("look up the replicated identity: %v", err)
	}
	if restored.Username != "casey" {
		t.Errorf("identity resolved to %q, want casey", restored.Username)
	}
	if restored.PasswordLogin {
		t.Error("the replicated account regained password sign-in")
	}
	admin, err := replica.UserByUsername(ctx, "nick")
	if err != nil {
		t.Fatalf("look up the replicated administrator: %v", err)
	}
	if !admin.PasswordLogin {
		t.Error("the replicated administrator lost password sign-in")
	}
}
