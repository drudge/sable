package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ErrNoFederatedAccount is returned when a verified identity has no Sable
// account and the provider is not permitted to create one.
var ErrNoFederatedAccount = errors.New("no Sable account is linked to that identity")

// FederatedIdentity is a sign-in the identity provider has already vouched
// for. The oidc package proves it; nothing here re-checks a signature.
//
// Subject is the only field treated as identifying. Username and Email are
// display material and a one-time linking hint, because a provider is free to
// change either one and matching on them later would hand one person another
// person's account.
type FederatedIdentity struct {
	Subject       string
	Username      string
	DisplayName   string
	Email         string
	EmailVerified bool
}

// FederatedPolicy is what the operator's configuration decided about this
// sign-in. Resolving groups into roles happens before this point, so the auth
// package stays free of any knowledge about claim shapes.
type FederatedPolicy struct {
	// Provider is the stable key an identity is stored under. It does not
	// change when the issuer URL does, so moving a provider to a new hostname
	// keeps every existing link intact.
	Provider string
	Issuer   string

	Provision           bool
	LinkByVerifiedEmail bool
	SyncRoles           bool

	// ManagedRoles is every role the provider is allowed to grant or revoke.
	// Anything outside it was assigned by hand and is left alone.
	ManagedRoles []string
	// GrantedRoles is what this particular sign-in earns.
	GrantedRoles []string
}

// FederatedLogin turns a verified external identity into a Sable session,
// creating or linking the account as the policy allows.
func (service *Service) FederatedLogin(
	ctx context.Context,
	identity FederatedIdentity,
	policy FederatedPolicy,
	clientIP, userAgent string,
) (Credentials, error) {
	if strings.TrimSpace(identity.Subject) == "" || strings.TrimSpace(policy.Provider) == "" {
		return Credentials{}, ErrInvalidCredential
	}
	// The callback is reachable without a session, so it is rate limited the
	// same way the password form is. The key is the client alone: the subject
	// is attacker-chosen and keying on it would give each attempt its own
	// budget.
	key := "federated\x00" + clientIP
	now := service.now()
	if !service.limiter.allow(key, now) {
		return Credentials{}, ErrRateLimited
	}

	user, err := service.resolveFederatedUser(ctx, identity, policy, clientIP, userAgent, now)
	if err != nil {
		service.limiter.failure(key, now)
		return Credentials{}, err
	}
	service.limiter.success(key)

	if policy.SyncRoles {
		roles, err := service.store.ReconcileManagedRoles(ctx, user.ID, policy.ManagedRoles, policy.GrantedRoles, now)
		if err != nil {
			// A refused reconcile means applying it would have left the
			// deployment with no administrator. The sign-in still proceeds
			// with the roles already on the account, because locking the
			// operator out is worse than one stale role.
			service.audit(ctx, &user.ID, "auth.federated.roles.failed", clientIP, userAgent, err.Error())
		} else {
			service.audit(ctx, &user.ID, "auth.federated.roles", clientIP, userAgent,
				fmt.Sprintf("roles now %s", strings.Join(roles, ", ")))
		}
	}
	if err := service.store.UpdateFederatedProfile(ctx, user.ID, identity.DisplayName, identity.Email, now); err != nil {
		service.audit(ctx, &user.ID, "auth.federated.profile.failed", clientIP, userAgent, err.Error())
	}
	if err := service.store.TouchIdentity(ctx, policy.Provider, identity.Subject, now); err != nil {
		service.audit(ctx, &user.ID, "auth.federated.touch.failed", clientIP, userAgent, err.Error())
	}

	// Web access is checked after reconciliation, because the roles this
	// sign-in just granted are what may have provided it.
	grants, err := service.store.GrantsForUser(ctx, user.ID, SurfaceWeb)
	if err != nil {
		return Credentials{}, err
	}
	if len(grants) == 0 {
		service.audit(ctx, &user.ID, "auth.federated.denied", clientIP, userAgent,
			"account has no role granting console access")
		return Credentials{}, ErrForbidden
	}

	credentials, err := service.newSession(ctx, user.ID, now)
	service.audit(ctx, &user.ID, "auth.federated.login", clientIP, userAgent,
		fmt.Sprintf("session created through %s", policy.Provider))
	return credentials, err
}

// resolveFederatedUser finds, links, or creates the account behind a verified
// identity, in that order of preference.
func (service *Service) resolveFederatedUser(
	ctx context.Context,
	identity FederatedIdentity,
	policy FederatedPolicy,
	clientIP, userAgent string,
	now time.Time,
) (User, error) {
	user, err := service.store.UserByIdentity(ctx, policy.Provider, identity.Subject)
	switch {
	case err == nil:
		if !user.LoginAllowed {
			// LoginAllowed is false for a disabled account as well as one with
			// no console role. Either way it is not a sign-in.
			service.audit(ctx, &user.ID, "auth.federated.denied", clientIP, userAgent, "account cannot sign in")
			return User{}, ErrForbidden
		}
		return user, nil
	case !errors.Is(err, ErrNotFound):
		return User{}, err
	}

	// A first sign-in may attach to an account that already exists, but only
	// on an address the provider says it verified. Without that check anyone
	// who can set their own email at the provider could claim any account.
	if policy.LinkByVerifiedEmail && identity.EmailVerified && strings.TrimSpace(identity.Email) != "" {
		existing, lookupErr := service.store.UserByEmail(ctx, identity.Email)
		switch {
		case lookupErr == nil:
			if err := service.store.LinkIdentity(ctx, policy.Provider, identity.Subject, policy.Issuer, existing.ID, now); err != nil {
				service.audit(ctx, &existing.ID, "auth.federated.link.failed", clientIP, userAgent, err.Error())
				return User{}, ErrInvalidCredential
			}
			service.audit(ctx, &existing.ID, "auth.federated.link", clientIP, userAgent,
				fmt.Sprintf("linked to %s subject %s by verified email", policy.Provider, identity.Subject))
			return existing, nil
		case !errors.Is(lookupErr, ErrNotFound):
			return User{}, lookupErr
		}
	}

	if !policy.Provision {
		service.audit(ctx, nil, "auth.federated.denied", clientIP, userAgent,
			fmt.Sprintf("%s subject %s has no linked account and provisioning is off", policy.Provider, identity.Subject))
		return User{}, ErrNoFederatedAccount
	}
	if len(policy.GrantedRoles) == 0 {
		// Creating an account with no roles produces something that cannot
		// sign in and cannot be told apart from a mapping mistake.
		service.audit(ctx, nil, "auth.federated.denied", clientIP, userAgent,
			fmt.Sprintf("%s subject %s maps to no role", policy.Provider, identity.Subject))
		return User{}, ErrForbidden
	}
	username, err := service.availableFederatedUsername(ctx, identity)
	if err != nil {
		service.audit(ctx, nil, "auth.federated.denied", clientIP, userAgent, err.Error())
		return User{}, err
	}
	created, err := service.store.CreateFederatedUser(
		ctx, username, identity.DisplayName, strings.ToLower(strings.TrimSpace(identity.Email)),
		policy.GrantedRoles, policy.Provider, identity.Subject, policy.Issuer, now,
	)
	if err != nil {
		return User{}, err
	}
	service.audit(ctx, &created.ID, "auth.federated.provision", clientIP, userAgent,
		fmt.Sprintf("created %q from %s subject %s with roles %s",
			username, policy.Provider, identity.Subject, strings.Join(policy.GrantedRoles, ", ")))
	return User{
		ID: created.ID, Username: created.Username, DisplayName: created.DisplayName,
		Email: created.Email, LoginAllowed: true,
	}, nil
}

// availableFederatedUsername picks a username that is free. A collision is
// ordinary rather than suspicious: two providers, or a provider and a local
// account, can easily agree on "admin" while describing different people.
func (service *Service) availableFederatedUsername(ctx context.Context, identity FederatedIdentity) (string, error) {
	base := federatedUsernameBase(identity)
	if base == "" {
		return "", errors.New("the identity provider sent nothing usable as a username")
	}
	for attempt := range 50 {
		candidate := base
		if attempt > 0 {
			suffix := strconv.Itoa(attempt + 1)
			// Keep room for the suffix rather than overrunning the limit.
			trimmed := candidate
			if len(trimmed)+len(suffix) > maximumUsername {
				trimmed = trimmed[:maximumUsername-len(suffix)]
			}
			candidate = trimmed + suffix
		}
		_, err := service.store.UserByUsername(ctx, candidate)
		if errors.Is(err, ErrNotFound) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("could not find a free username for the new account")
}

// federatedUsernameBase reduces what the provider sent to something that
// satisfies Sable's username rules, preferring the claim an operator would
// recognise. The subject is the last resort because it is usually a UUID.
func federatedUsernameBase(identity FederatedIdentity) string {
	candidates := []string{identity.Username}
	if local, _, found := strings.Cut(identity.Email, "@"); found {
		candidates = append(candidates, local)
	}
	candidates = append(candidates, identity.DisplayName, "sso-"+identity.Subject)
	for _, candidate := range candidates {
		if sanitized := sanitizeUsername(candidate); len(sanitized) >= minimumUsername {
			return sanitized
		}
	}
	return ""
}

// sanitizeUsername maps a provider's value onto the characters Sable allows,
// dropping anything else rather than substituting, so two different inputs do
// not collapse into the same name through a shared replacement character.
func sanitizeUsername(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			character == '.' || character == '_' || character == '-':
			builder.WriteRune(character)
		case unicode.IsSpace(character):
			builder.WriteRune('-')
		}
	}
	sanitized := strings.Trim(builder.String(), ".-_")
	if len(sanitized) > maximumUsername {
		sanitized = sanitized[:maximumUsername]
	}
	return sanitized
}

// FederatedProviderRoles reports whether every role a mapping names actually
// exists, so the console can refuse a mapping that would silently grant
// nothing. The caller passes the roles it intends to configure.
func (service *Service) FederatedProviderRoles(ctx context.Context, roles []string) error {
	missing := make([]string, 0)
	for _, role := range roles {
		if strings.TrimSpace(role) == "" {
			continue
		}
		exists, err := service.store.RolesHaveSurface(ctx, []string{role}, SurfaceWeb)
		if err != nil {
			// RolesHaveSurface reports a missing role as an error rather than
			// as a false result, so the message is surfaced as-is.
			missing = append(missing, role)
			continue
		}
		if !exists {
			missing = append(missing, role)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	slices.Sort(missing)
	return fmt.Errorf("these roles do not exist or grant no console access: %s", strings.Join(missing, ", "))
}
