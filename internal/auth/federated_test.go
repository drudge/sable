package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeStore is an in-memory stand-in for the SQL store. The federated sign-in
// path branches on what storage reports rather than on anything it computes
// itself, so the branches are what these tests drive.
type fakeStore struct {
	usersByID       map[int64]User
	usersByName     map[string]int64
	usersByEmail    map[string]int64
	identities      map[string]int64
	roles           map[int64][]string
	grants          map[int64][]Grant
	nextID          int64
	reconcileErr    error
	audit           []AuditEvent
	linked          []string
	touched         []string
	profileUpdates  int
	reconcileCalled int
	avatars         map[int64]Avatar
	avatarDeletes   int
	avatarSaves     int
	avatarErr       error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		usersByID:    map[int64]User{},
		usersByName:  map[string]int64{},
		usersByEmail: map[string]int64{},
		identities:   map[string]int64{},
		roles:        map[int64][]string{},
		grants:       map[int64][]Grant{},
		avatars:      map[int64]Avatar{},
		nextID:       1,
	}
}

// addUser seeds an account that already exists, with console access.
func (store *fakeStore) addUser(username, email string, roles ...string) User {
	id := store.nextID
	store.nextID++
	user := User{ID: id, Username: username, DisplayName: username, Email: email, LoginAllowed: true, PasswordLogin: true}
	store.usersByID[id] = user
	store.usersByName[username] = id
	if email != "" {
		store.usersByEmail[strings.ToLower(email)] = id
	}
	store.roles[id] = roles
	store.grants[id] = []Grant{{Permission: PermissionZonesRead, Surface: SurfaceWeb}}
	return user
}

func (store *fakeStore) AdminExists(context.Context) (bool, error) { return true, nil }

func (store *fakeStore) CreateInitialAdmin(context.Context, string, string, time.Time) (User, error) {
	return User{}, errors.New("not used")
}

func (store *fakeStore) UserByUsername(_ context.Context, username string) (User, error) {
	id, found := store.usersByName[username]
	if !found {
		return User{}, ErrNotFound
	}
	return store.usersByID[id], nil
}

func (store *fakeStore) CreateSession(context.Context, string, int64, string, time.Time, time.Time) error {
	return nil
}

func (store *fakeStore) SessionByHash(context.Context, string, time.Time) (StoredSession, error) {
	return StoredSession{}, ErrNotFound
}

func (store *fakeStore) DeleteSession(context.Context, string) error { return nil }

func (store *fakeStore) CreateAPIToken(context.Context, string, int64, string, []string, time.Time, time.Time) error {
	return nil
}

func (store *fakeStore) APITokenByHash(context.Context, string, time.Time) (StoredAPIToken, error) {
	return StoredAPIToken{}, ErrNotFound
}

func (store *fakeStore) GrantsForUser(_ context.Context, userID int64, _ Surface) ([]Grant, error) {
	return store.grants[userID], nil
}

func (store *fakeStore) GrantsForToken(context.Context, int64, int64, Surface) ([]Grant, error) {
	return nil, nil
}

func (store *fakeStore) RecordAuditEvent(_ context.Context, event AuditEvent) error {
	store.audit = append(store.audit, event)
	return nil
}

func (store *fakeStore) RolesHaveSurface(_ context.Context, roles []string, _ Surface) (bool, error) {
	for _, role := range roles {
		if role == "Nonexistent" {
			return false, errors.New("role not found")
		}
	}
	return true, nil
}

func (store *fakeStore) UserByIdentity(_ context.Context, provider, subject string) (User, error) {
	id, found := store.identities[provider+"\x00"+subject]
	if !found {
		return User{}, ErrNotFound
	}
	return store.usersByID[id], nil
}

func (store *fakeStore) UserByEmail(_ context.Context, email string) (User, error) {
	id, found := store.usersByEmail[strings.ToLower(strings.TrimSpace(email))]
	if !found {
		return User{}, ErrNotFound
	}
	return store.usersByID[id], nil
}

func (store *fakeStore) LinkIdentity(_ context.Context, provider, subject, _ string, userID int64, _ time.Time) error {
	key := provider + "\x00" + subject
	if existing, found := store.identities[key]; found && existing != userID {
		return errors.New("identity is already linked to another account")
	}
	store.identities[key] = userID
	store.linked = append(store.linked, key)
	return nil
}

func (store *fakeStore) TouchIdentity(_ context.Context, provider, subject string, _ time.Time) error {
	store.touched = append(store.touched, provider+"\x00"+subject)
	return nil
}

func (store *fakeStore) CreateFederatedUser(
	_ context.Context, username, displayName, email string, roles []string,
	provider, subject, _ string, _ time.Time,
) (ManagedUser, error) {
	if _, taken := store.usersByName[username]; taken {
		return ManagedUser{}, errors.New("username is taken")
	}
	id := store.nextID
	store.nextID++
	store.usersByID[id] = User{ID: id, Username: username, DisplayName: displayName, Email: email, LoginAllowed: true}
	store.usersByName[username] = id
	if email != "" {
		store.usersByEmail[strings.ToLower(email)] = id
	}
	store.roles[id] = roles
	store.grants[id] = []Grant{{Permission: PermissionZonesRead, Surface: SurfaceWeb}}
	store.identities[provider+"\x00"+subject] = id
	return ManagedUser{ID: id, Username: username, DisplayName: displayName, Email: email, Roles: roles}, nil
}

func (store *fakeStore) ReconcileManagedRoles(
	_ context.Context, userID int64, managed, granted []string, _ time.Time,
) ([]string, error) {
	store.reconcileCalled++
	if store.reconcileErr != nil {
		return nil, store.reconcileErr
	}
	kept := make([]string, 0)
	for _, role := range store.roles[userID] {
		if !contains(managed, role) || contains(granted, role) {
			kept = append(kept, role)
		}
	}
	for _, role := range granted {
		if !contains(kept, role) {
			kept = append(kept, role)
		}
	}
	store.roles[userID] = kept
	return kept, nil
}

func (store *fakeStore) UpdateFederatedProfile(_ context.Context, _ int64, _, _ string, _ time.Time) error {
	store.profileUpdates++
	return nil
}

func (store *fakeStore) SaveAvatar(_ context.Context, userID int64, avatar Avatar, _ time.Time) error {
	if store.avatarErr != nil {
		return store.avatarErr
	}
	store.avatarSaves++
	store.avatars[userID] = avatar
	if user, found := store.usersByID[userID]; found {
		user.AvatarETag = avatar.ETag
		store.usersByID[userID] = user
	}
	return nil
}

func (store *fakeStore) DeleteAvatar(_ context.Context, userID int64, _ time.Time) error {
	if store.avatarErr != nil {
		return store.avatarErr
	}
	store.avatarDeletes++
	delete(store.avatars, userID)
	if user, found := store.usersByID[userID]; found {
		user.AvatarETag = ""
		store.usersByID[userID] = user
	}
	return nil
}

func (store *fakeStore) Avatar(_ context.Context, userID int64) (Avatar, error) {
	avatar, found := store.avatars[userID]
	if !found {
		return Avatar{}, ErrNotFound
	}
	return avatar, nil
}

func contains(list []string, value string) bool {
	for _, entry := range list {
		if entry == value {
			return true
		}
	}
	return false
}

func newFederatedService(t *testing.T, store *fakeStore) *Service {
	t.Helper()
	service, err := NewService(store, Options{})
	if err != nil {
		t.Fatalf("build auth service: %v", err)
	}
	return service
}

func defaultPolicy() FederatedPolicy {
	return FederatedPolicy{
		Provider:            "pocket-id",
		Issuer:              "https://id.example.com",
		Provision:           true,
		LinkByVerifiedEmail: true,
		SyncRoles:           true,
		ManagedRoles:        []string{"Operator", "Auditor"},
		GrantedRoles:        []string{"Operator"},
	}
}

func TestFederatedLoginProvisionsAnUnknownIdentity(t *testing.T) {
	store := newFakeStore()
	service := newFederatedService(t, store)

	identity := FederatedIdentity{Subject: "subject-1", Username: "casey", DisplayName: "Casey Jones", Email: "casey@example.com"}
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("federated sign-in: %v", err)
	}
	id, found := store.identities["pocket-id\x00subject-1"]
	if !found {
		t.Fatal("the new identity was not linked")
	}
	created := store.usersByID[id]
	if created.Username != "casey" {
		t.Errorf("username = %q, want casey", created.Username)
	}
	if strings.Join(store.roles[id], ",") != "Operator" {
		t.Errorf("roles = %v, want Operator", store.roles[id])
	}
}

// The subject is what identifies a returning person. A second sign-in must
// find the same account rather than creating another one.
func TestFederatedLoginReusesTheLinkedAccount(t *testing.T) {
	store := newFakeStore()
	service := newFederatedService(t, store)
	identity := FederatedIdentity{Subject: "subject-1", Username: "casey", Email: "casey@example.com"}

	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	countAfterFirst := len(store.usersByID)

	// The provider renamed them and changed their address; the subject did not.
	identity.Username = "casey-renamed"
	identity.Email = "casey.jones@example.com"
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	if len(store.usersByID) != countAfterFirst {
		t.Fatalf("users = %d, want %d; the rename created a second account", len(store.usersByID), countAfterFirst)
	}
}

func TestFederatedLoginLinksByVerifiedEmailOnce(t *testing.T) {
	store := newFakeStore()
	existing := store.addUser("nick", "nick@example.com", "Administrator")
	service := newFederatedService(t, store)

	identity := FederatedIdentity{Subject: "subject-1", Username: "nick", Email: "nick@example.com", EmailVerified: true}
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("federated sign-in: %v", err)
	}
	if store.identities["pocket-id\x00subject-1"] != existing.ID {
		t.Fatal("the identity did not attach to the existing account")
	}
	if len(store.usersByID) != 1 {
		t.Fatalf("users = %d, want the existing account to be reused", len(store.usersByID))
	}
}

// Anyone who can set their own email address at the provider could otherwise
// claim any account by naming its address.
func TestFederatedLoginRefusesToLinkAnUnverifiedEmail(t *testing.T) {
	store := newFakeStore()
	store.addUser("nick", "nick@example.com", "Administrator")
	service := newFederatedService(t, store)

	identity := FederatedIdentity{Subject: "attacker", Username: "nick", Email: "nick@example.com", EmailVerified: false}
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("federated sign-in: %v", err)
	}
	if store.identities["pocket-id\x00attacker"] == 1 {
		t.Fatal("an unverified email claimed the existing administrator account")
	}
	if len(store.usersByID) != 2 {
		t.Fatalf("users = %d, want a separate account to have been provisioned", len(store.usersByID))
	}
}

func TestFederatedLoginRejectsAnUnknownIdentityWhenProvisioningIsOff(t *testing.T) {
	store := newFakeStore()
	service := newFederatedService(t, store)
	policy := defaultPolicy()
	policy.Provision = false
	policy.LinkByVerifiedEmail = false

	identity := FederatedIdentity{Subject: "subject-1", Username: "casey"}
	_, err := service.FederatedLogin(context.Background(), identity, policy, "10.0.0.1", "test")
	if !errors.Is(err, ErrNoFederatedAccount) {
		t.Fatalf("error = %v, want %v", err, ErrNoFederatedAccount)
	}
	if len(store.usersByID) != 0 {
		t.Fatal("an account was created while provisioning was off")
	}
}

// An account with no mapped role would be created unable to sign in, which
// looks identical to a broken group mapping.
func TestFederatedLoginRejectsAnIdentityThatMapsToNoRole(t *testing.T) {
	store := newFakeStore()
	service := newFederatedService(t, store)
	policy := defaultPolicy()
	policy.GrantedRoles = nil

	identity := FederatedIdentity{Subject: "subject-1", Username: "casey"}
	if _, err := service.FederatedLogin(context.Background(), identity, policy, "10.0.0.1", "test"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("error = %v, want %v", err, ErrForbidden)
	}
}

// Losing every administrator to a group-claim change is worse than one stale
// role, so a refused reconcile lets the sign-in through and records why.
func TestFederatedLoginSurvivesARefusedRoleReconcile(t *testing.T) {
	store := newFakeStore()
	existing := store.addUser("nick", "nick@example.com", "Administrator")
	store.identities["pocket-id\x00subject-1"] = existing.ID
	store.reconcileErr = errors.New("at least one active administrator is required")
	service := newFederatedService(t, store)

	identity := FederatedIdentity{Subject: "subject-1", Username: "nick"}
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("federated sign-in: %v", err)
	}
	if strings.Join(store.roles[existing.ID], ",") != "Administrator" {
		t.Errorf("roles = %v, want the existing Administrator role to survive", store.roles[existing.ID])
	}
	if !auditContains(store.audit, "auth.federated.roles.failed") {
		t.Error("the refused reconcile was not recorded in the audit log")
	}
}

func TestFederatedLoginRejectsAnAccountWithNoConsoleAccess(t *testing.T) {
	store := newFakeStore()
	existing := store.addUser("api-only", "api@example.com", "API Administrator")
	store.grants[existing.ID] = nil
	store.identities["pocket-id\x00subject-1"] = existing.ID
	service := newFederatedService(t, store)
	policy := defaultPolicy()
	policy.SyncRoles = false

	identity := FederatedIdentity{Subject: "subject-1", Username: "api-only"}
	if _, err := service.FederatedLogin(context.Background(), identity, policy, "10.0.0.1", "test"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("error = %v, want %v", err, ErrForbidden)
	}
}

func TestFederatedLoginRejectsAnEmptySubject(t *testing.T) {
	store := newFakeStore()
	service := newFederatedService(t, store)
	if _, err := service.FederatedLogin(context.Background(), FederatedIdentity{}, defaultPolicy(), "10.0.0.1", "test"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidCredential)
	}
}

func TestFederatedUsernameFallsBackThroughTheClaims(t *testing.T) {
	tests := []struct {
		name     string
		identity FederatedIdentity
		want     string
	}{
		{"preferred username wins", FederatedIdentity{Subject: "s", Username: "casey", Email: "other@example.com"}, "casey"},
		{"email local part is next", FederatedIdentity{Subject: "s", Email: "casey.jones@example.com"}, "casey.jones"},
		{"display name after that", FederatedIdentity{Subject: "s", DisplayName: "Casey Jones"}, "casey-jones"},
		{"subject is the last resort", FederatedIdentity{Subject: "abc123"}, "sso-abc123"},
		{"unusable characters are dropped", FederatedIdentity{Subject: "s", Username: "Ca$ey!"}, "caey"},
		{"a too-short result falls through", FederatedIdentity{Subject: "abc123", Username: "x"}, "sso-abc123"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := federatedUsernameBase(test.identity); got != test.want {
				t.Fatalf("username base = %q, want %q", got, test.want)
			}
		})
	}
}

// Two providers, or a provider and a local account, can easily agree on a
// name while describing different people.
func TestFederatedLoginPicksAFreeUsernameOnCollision(t *testing.T) {
	store := newFakeStore()
	store.addUser("casey", "someone.else@example.com", "Auditor")
	service := newFederatedService(t, store)

	identity := FederatedIdentity{Subject: "subject-1", Username: "casey", Email: "casey@example.com"}
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("federated sign-in: %v", err)
	}
	id := store.identities["pocket-id\x00subject-1"]
	if got := store.usersByID[id].Username; got != "casey2" {
		t.Fatalf("username = %q, want casey2", got)
	}
}

func auditContains(events []AuditEvent, action string) bool {
	for _, event := range events {
		if event.Action == action {
			return true
		}
	}
	return false
}

// An account that moved to single sign-on keeps whatever password hash it had.
// The flag is what must stop it being used, not the hash being blank.
func TestLoginRefusesAnAccountThatMovedToSingleSignOn(t *testing.T) {
	store := newFakeStore()
	user := store.addUser("casey", "casey@example.com", "Operator")
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	stored := store.usersByID[user.ID]
	stored.PasswordHash = hash
	stored.PasswordLogin = false
	store.usersByID[user.ID] = stored
	service := newFederatedService(t, store)

	_, err = service.Login(context.Background(), "casey", "correct horse battery staple", "10.0.0.1", "test")
	if !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidCredential)
	}

	// Turning password sign-in back on restores it, proving the hash was
	// still valid and the flag alone did the refusing.
	stored.PasswordLogin = true
	store.usersByID[user.ID] = stored
	if _, err := service.Login(context.Background(), "casey", "correct horse battery staple", "10.0.0.2", "test"); err != nil {
		t.Fatalf("sign-in after restoring password login: %v", err)
	}
}

func TestFederatedLoginStoresTheProfilePicture(t *testing.T) {
	store := newFakeStore()
	service := newFederatedService(t, store)
	identity := FederatedIdentity{
		Subject: "subject-1", Username: "casey", Email: "casey@example.com",
		Avatar: &Avatar{
			ContentType: "image/png", Data: []byte{0x89, 'P', 'N', 'G'},
			ETag: `"abc"`, SourceURL: "https://id.example.com/avatar.png",
		},
	}
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("federated sign-in: %v", err)
	}
	id := store.identities["pocket-id\x00subject-1"]
	stored, err := store.Avatar(context.Background(), id)
	if err != nil {
		t.Fatalf("read stored avatar: %v", err)
	}
	if stored.ETag != `"abc"` || stored.ContentType != "image/png" {
		t.Errorf("stored avatar = %+v, want the one the provider served", stored)
	}
}

// Rewriting an unchanged picture would churn the row and hand every browser a
// fresh tag for bytes it already has.
func TestFederatedLoginLeavesAnUnchangedPictureAlone(t *testing.T) {
	store := newFakeStore()
	service := newFederatedService(t, store)
	avatar := &Avatar{ContentType: "image/png", Data: []byte{0x89, 'P', 'N', 'G'}, ETag: `"abc"`}
	identity := FederatedIdentity{Subject: "subject-1", Username: "casey", Avatar: avatar}

	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	if store.avatarSaves != 1 {
		t.Errorf("avatar writes = %d, want 1", store.avatarSaves)
	}
}

// A download that failed arrives as a nil avatar. Erasing the stored picture
// then would turn a provider's flaky image host into a lost avatar.
func TestFederatedLoginKeepsThePictureWhenTheDownloadFailed(t *testing.T) {
	store := newFakeStore()
	service := newFederatedService(t, store)
	identity := FederatedIdentity{
		Subject: "subject-1", Username: "casey",
		Avatar: &Avatar{ContentType: "image/png", Data: []byte{0x89, 'P'}, ETag: `"abc"`},
	}
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	id := store.identities["pocket-id\x00subject-1"]

	identity.Avatar = nil
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	if _, err := store.Avatar(context.Background(), id); err != nil {
		t.Fatalf("the stored picture was dropped after a failed download: %v", err)
	}
	if store.avatarDeletes != 0 {
		t.Errorf("avatar deletions = %d, want 0", store.avatarDeletes)
	}
}

func TestFederatedLoginRemovesAPictureTheProviderNoLongerAdvertises(t *testing.T) {
	store := newFakeStore()
	service := newFederatedService(t, store)
	identity := FederatedIdentity{
		Subject: "subject-1", Username: "casey",
		Avatar: &Avatar{ContentType: "image/png", Data: []byte{0x89, 'P'}, ETag: `"abc"`},
	}
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	id := store.identities["pocket-id\x00subject-1"]

	identity.Avatar, identity.AvatarCleared = nil, true
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	if _, err := store.Avatar(context.Background(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound; the picture was not removed", err)
	}
}

// A picture is decoration. A store that cannot hold one must not cost somebody
// the console.
func TestFederatedLoginSurvivesAnAvatarStoreFailure(t *testing.T) {
	store := newFakeStore()
	service := newFederatedService(t, store)
	store.avatarErr = errors.New("disk is full")
	identity := FederatedIdentity{
		Subject: "subject-1", Username: "casey",
		Avatar: &Avatar{ContentType: "image/png", Data: []byte{0x89, 'P'}, ETag: `"abc"`},
	}
	if _, err := service.FederatedLogin(context.Background(), identity, defaultPolicy(), "10.0.0.1", "test"); err != nil {
		t.Fatalf("federated sign-in: %v", err)
	}
}
