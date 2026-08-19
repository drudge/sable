package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"time"
)

const (
	defaultSessionTTL    = 12 * time.Hour
	defaultTokenTTL      = 90 * 24 * time.Hour
	defaultLoginAttempts = 5
	defaultLoginWindow   = 15 * time.Minute
	randomTokenBytes     = 32
	minimumUsername      = 3
	maximumUsername      = 64
)

var (
	ErrNotFound          = errors.New("not found")
	ErrSetupComplete     = errors.New("initial administrator setup is already complete")
	ErrInvalidCredential = errors.New("invalid username or password")
	ErrRateLimited       = errors.New("too many login attempts; try again later")
	ErrUnauthorized      = errors.New("authentication required")
	ErrForbidden         = errors.New("permission denied")
)

type User struct {
	ID           int64
	Username     string
	DisplayName  string
	Email        string
	PasswordHash string
	LoginAllowed bool
	// PasswordLogin reports whether a password may be used to sign in as this
	// account. A federated account that never had a password has it cleared,
	// and so does anyone who deliberately moved to single sign-on only.
	PasswordLogin bool
}

type StoredSession struct {
	User      User
	CSRFToken string
	Expires   time.Time
}

type StoredAPIToken struct {
	ID      int64
	User    User
	Groups  []string
	Expires time.Time
}

// APITokenExpiration selects the lifetime of a newly issued API token. The
// zero value uses the configured default; Never creates a non-expiring token.
type APITokenExpiration struct {
	Lifetime time.Duration
	Never    bool
}

type AuditEvent struct {
	OccurredAt time.Time
	UserID     *int64
	Action     string
	ClientIP   string
	UserAgent  string
	Details    string
}

type Store interface {
	AdminExists(context.Context) (bool, error)
	CreateInitialAdmin(context.Context, string, string, time.Time) (User, error)
	UserByUsername(context.Context, string) (User, error)
	CreateSession(context.Context, string, int64, string, time.Time, time.Time) error
	SessionByHash(context.Context, string, time.Time) (StoredSession, error)
	DeleteSession(context.Context, string) error
	CreateAPIToken(context.Context, string, int64, string, []string, time.Time, time.Time) error
	APITokenByHash(context.Context, string, time.Time) (StoredAPIToken, error)
	GrantsForUser(context.Context, int64, Surface) ([]Grant, error)
	GrantsForToken(context.Context, int64, int64, Surface) ([]Grant, error)
	RecordAuditEvent(context.Context, AuditEvent) error
	RolesHaveSurface(context.Context, []string, Surface) (bool, error)

	// Single sign-on storage. An identity is looked up by its provider subject
	// on every repeat sign-in; the rest is only reached the first time someone
	// arrives from a provider.
	UserByIdentity(context.Context, string, string) (User, error)
	UserByEmail(context.Context, string) (User, error)
	LinkIdentity(context.Context, string, string, string, int64, time.Time) error
	TouchIdentity(context.Context, string, string, time.Time) error
	CreateFederatedUser(context.Context, string, string, string, []string, string, string, string, time.Time) (ManagedUser, error)
	ReconcileManagedRoles(context.Context, int64, []string, []string, time.Time) ([]string, error)
	UpdateFederatedProfile(context.Context, int64, string, string, time.Time) error
}

type Options struct {
	SessionTTL    time.Duration
	TokenTTL      time.Duration
	LoginAttempts int
	LoginWindow   time.Duration
	Now           func() time.Time
}

type Service struct {
	store       Store
	sessionTTL  time.Duration
	tokenTTL    time.Duration
	now         func() time.Time
	limiter     *loginLimiter
	passwordOps chan struct{}
}

type Credentials struct {
	SessionToken string
	CSRFToken    string
	Expires      time.Time
}

type Principal struct {
	UserID               int64
	Username             string
	DisplayName          string
	Email                string
	CSRFToken            string
	Groups               []string
	Permissions          []string
	Grants               []Grant
	grantIndex           map[string]struct{}
	Surface              Surface
	SessionHash          string
	AuthenticatedByToken bool
}

func NewService(store Store, options Options) (*Service, error) {
	if store == nil {
		return nil, errors.New("authentication store is required")
	}
	if options.SessionTTL <= 0 {
		options.SessionTTL = defaultSessionTTL
	}
	if options.TokenTTL <= 0 {
		options.TokenTTL = defaultTokenTTL
	}
	if options.LoginAttempts <= 0 {
		options.LoginAttempts = defaultLoginAttempts
	}
	if options.LoginWindow <= 0 {
		options.LoginWindow = defaultLoginWindow
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	maximumPasswordOperations := max(1, runtime.GOMAXPROCS(0)/2)
	return &Service{
		store: store, sessionTTL: options.SessionTTL, tokenTTL: options.TokenTTL, now: options.Now,
		limiter:     newLoginLimiter(options.LoginAttempts, options.LoginWindow),
		passwordOps: make(chan struct{}, maximumPasswordOperations),
	}, nil
}

func (service *Service) SetupRequired(ctx context.Context) (bool, error) {
	exists, err := service.store.AdminExists(ctx)
	return !exists, err
}

func (service *Service) Setup(
	ctx context.Context,
	username, password, clientIP, userAgent string,
) (Credentials, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return Credentials{}, err
	}
	if err := validatePassword(password); err != nil {
		return Credentials{}, err
	}
	if !service.acquirePasswordOperation() {
		return Credentials{}, ErrRateLimited
	}
	passwordHash, err := HashPassword(password)
	service.releasePasswordOperation()
	if err != nil {
		return Credentials{}, err
	}
	now := service.now()
	user, err := service.store.CreateInitialAdmin(ctx, username, passwordHash, now)
	if err != nil {
		return Credentials{}, err
	}
	credentials, err := service.newSession(ctx, user.ID, now)
	service.audit(ctx, &user.ID, "admin.setup", clientIP, userAgent, "initial administrator created")
	return credentials, err
}

func (service *Service) Login(
	ctx context.Context,
	username, password, clientIP, userAgent string,
) (Credentials, error) {
	normalized, normalizeErr := normalizeUsername(username)
	key := strings.ToLower(strings.TrimSpace(username)) + "\x00" + clientIP
	now := service.now()
	if !service.limiter.allow(key, now) || !service.acquirePasswordOperation() {
		return Credentials{}, ErrRateLimited
	}
	defer service.releasePasswordOperation()
	user, err := service.store.UserByUsername(ctx, normalized)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Credentials{}, err
	}
	// An account that moved to single sign-on keeps whatever password hash it
	// had, so the check is on the flag rather than on the hash being empty.
	usable := normalizeErr == nil && err == nil && user.LoginAllowed && user.PasswordLogin
	valid := usable && VerifyPassword(user.PasswordHash, password)
	if !usable {
		// The hashing work happens even when there is nothing to compare
		// against, so an unknown username, a disabled account, and an
		// SSO-only account cannot be told apart by how long the reply takes.
		consumePasswordWork(password)
	}
	if !valid {
		service.limiter.failure(key, now)
		service.audit(ctx, nil, "auth.login.failed", clientIP, userAgent, "invalid credentials")
		return Credentials{}, ErrInvalidCredential
	}
	service.limiter.success(key)
	credentials, err := service.newSession(ctx, user.ID, now)
	service.audit(ctx, &user.ID, "auth.login", clientIP, userAgent, "session created")
	return credentials, err
}

func (service *Service) AuthenticateSession(ctx context.Context, token string) (Principal, error) {
	if token == "" {
		return Principal{}, ErrUnauthorized
	}
	sessionHash := tokenHash(token)
	session, err := service.store.SessionByHash(ctx, sessionHash, service.now())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Principal{}, ErrUnauthorized
		}
		return Principal{}, err
	}
	grants, err := service.store.GrantsForUser(ctx, session.User.ID, SurfaceWeb)
	if err != nil {
		return Principal{}, err
	}
	return Principal{
		UserID: session.User.ID, Username: session.User.Username, DisplayName: session.User.DisplayName, Email: session.User.Email,
		CSRFToken: session.CSRFToken, SessionHash: sessionHash, Permissions: grantPermissions(grants), Grants: grants,
		grantIndex: indexGrants(grants, SurfaceWeb), Surface: SurfaceWeb,
	}, nil
}

func (service *Service) AuthenticateToken(ctx context.Context, token string) (Principal, error) {
	if !strings.HasPrefix(token, "sable_pat_") {
		return Principal{}, ErrUnauthorized
	}
	stored, err := service.store.APITokenByHash(ctx, tokenHash(token), service.now())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Principal{}, ErrUnauthorized
		}
		return Principal{}, err
	}
	grants, err := service.store.GrantsForToken(ctx, stored.ID, stored.User.ID, SurfaceAPI)
	if err != nil {
		return Principal{}, err
	}
	permissions := grantPermissions(grants)
	return Principal{
		UserID: stored.User.ID, Username: stored.User.Username,
		Groups: stored.Groups, Permissions: permissions, Grants: grants,
		grantIndex: indexGrants(grants, SurfaceAPI), Surface: SurfaceAPI, AuthenticatedByToken: true,
	}, nil
}

func (service *Service) ValidateCSRF(principal Principal, token string) bool {
	if principal.AuthenticatedByToken || principal.CSRFToken == "" || token == "" {
		return principal.AuthenticatedByToken
	}
	expected := sha256.Sum256([]byte(principal.CSRFToken))
	actual := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(actual[:], expected[:]) == 1
}

func (service *Service) Logout(ctx context.Context, principal Principal, clientIP, userAgent string) error {
	if principal.SessionHash == "" {
		return nil
	}
	err := service.store.DeleteSession(ctx, principal.SessionHash)
	service.audit(ctx, &principal.UserID, "auth.logout", clientIP, userAgent, "session deleted")
	return err
}

func (service *Service) CreateAPIToken(
	ctx context.Context,
	principal Principal,
	ownerID int64,
	name string,
	groups []string,
	expiration APITokenExpiration,
	clientIP, userAgent string,
) (string, time.Time, error) {
	if ownerID == 0 {
		ownerID = principal.UserID
	}
	if ownerID != principal.UserID {
		if err := requirePermission(principal, PermissionUsersWrite); err != nil {
			return "", time.Time{}, err
		}
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return "", time.Time{}, errors.New("token name must contain 1 to 100 characters")
	}
	groups = uniqueStrings(groups)
	if len(groups) == 0 {
		return "", time.Time{}, errors.New("at least one group is required")
	}
	if store, ok := service.store.(AdministrationStore); ok {
		users, err := store.ListUsers(ctx)
		if err != nil {
			return "", time.Time{}, err
		}
		var ownerGroups []string
		for _, user := range users {
			if user.ID == ownerID {
				ownerGroups = user.Roles
				break
			}
		}
		if ownerGroups == nil {
			return "", time.Time{}, ErrNotFound
		}
		for _, group := range groups {
			if !slices.Contains(ownerGroups, group) {
				return "", time.Time{}, errors.New("token groups must belong to the token owner")
			}
		}
	}
	if expiration.Lifetime < 0 || (expiration.Never && expiration.Lifetime != 0) {
		return "", time.Time{}, errors.New("token expiration must be positive or never")
	}
	secret, err := randomToken("sable_pat_")
	if err != nil {
		return "", time.Time{}, err
	}
	now := service.now()
	var expires time.Time
	if !expiration.Never {
		lifetime := expiration.Lifetime
		if lifetime == 0 {
			lifetime = service.tokenTTL
		}
		expires = now.Add(lifetime)
	}
	if err := service.store.CreateAPIToken(
		ctx, tokenHash(secret), ownerID, name, groups, now, expires,
	); err != nil {
		return "", time.Time{}, err
	}
	expirationLabel := "never"
	if !expires.IsZero() {
		expirationLabel = expires.UTC().Format(time.RFC3339)
	}
	service.audit(ctx, &principal.UserID, "api_token.create", clientIP, userAgent,
		fmt.Sprintf("owner_id=%d groups=%s expires=%s", ownerID, strings.Join(groups, ","), expirationLabel))
	return secret, expires, nil
}

func (service *Service) newSession(ctx context.Context, userID int64, now time.Time) (Credentials, error) {
	sessionToken, err := randomToken("")
	if err != nil {
		return Credentials{}, err
	}
	csrfToken, err := randomToken("")
	if err != nil {
		return Credentials{}, err
	}
	expires := now.Add(service.sessionTTL)
	if err := service.store.CreateSession(
		ctx, tokenHash(sessionToken), userID, csrfToken, now, expires,
	); err != nil {
		return Credentials{}, err
	}
	return Credentials{SessionToken: sessionToken, CSRFToken: csrfToken, Expires: expires}, nil
}

func (service *Service) acquirePasswordOperation() bool {
	select {
	case service.passwordOps <- struct{}{}:
		return true
	default:
		return false
	}
}

func (service *Service) releasePasswordOperation() { <-service.passwordOps }

func (service *Service) audit(
	ctx context.Context,
	userID *int64,
	action, clientIP, userAgent, details string,
) {
	_ = service.store.RecordAuditEvent(ctx, AuditEvent{
		OccurredAt: service.now(), UserID: userID, Action: action,
		ClientIP: clientIP, UserAgent: userAgent, Details: details,
	})
}

func normalizeUsername(username string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if len(username) < minimumUsername || len(username) > maximumUsername {
		return "", fmt.Errorf("username must contain %d to %d characters", minimumUsername, maximumUsername)
	}
	for _, character := range username {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return "", errors.New("username may contain lowercase letters, numbers, dots, underscores, and hyphens")
	}
	return username, nil
}

func grantPermissions(grants []Grant) []string {
	result := make([]string, 0, len(grants))
	for _, grant := range grants {
		if !slices.Contains(result, grant.Permission) {
			result = append(result, grant.Permission)
		}
	}
	return result
}

func indexGrants(grants []Grant, surface Surface) map[string]struct{} {
	index := make(map[string]struct{}, len(grants))
	for _, grant := range grants {
		if grant.Surface == surface {
			index[grantKey(grant.Permission, grant.ResourceType, grant.ResourceID)] = struct{}{}
		}
	}
	return index
}

func randomToken(prefix string) (string, error) {
	buffer := make([]byte, randomTokenBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate authentication token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func tokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
