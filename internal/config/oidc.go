package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	defaultOIDCDisplayName       = "Single sign-on"
	defaultOIDCDiscoveryInterval = time.Hour
	defaultOIDCClockSkew         = time.Minute
	minimumOIDCDiscoveryInterval = time.Minute
	// maximumOIDCClockSkew bounds how long an expired token stays usable. A
	// generous skew papers over a broken clock at the cost of widening the
	// replay window, so the loader refuses anything past five minutes.
	maximumOIDCClockSkew = 5 * time.Minute
)

// OIDC configures single sign-on against an external identity provider.
//
// The client secret is deliberately absent. It is credential material, so it
// lives in the encrypted vault alongside TSIG secrets and ACME credentials
// rather than in sable.toml, its backups, and every replica's copy of the
// runtime configuration.
type OIDC struct {
	Enabled     bool   `toml:"enabled"`
	DisplayName string `toml:"display_name"`
	Issuer      string `toml:"issuer"`
	ClientID    string `toml:"client_id"`
	RedirectURL string `toml:"redirect_url"`

	Scopes        []string `toml:"scopes"`
	UsernameClaim string   `toml:"username_claim"`
	EmailClaim    string   `toml:"email_claim"`
	GroupsClaim   string   `toml:"groups_claim"`
	FetchUserInfo bool     `toml:"fetch_userinfo"`

	// Provision creates a Sable user the first time an unknown person signs in
	// successfully. With it off, only accounts that already exist can use SSO.
	Provision bool `toml:"provision"`
	// LinkByVerifiedEmail attaches a first-time sign-in to an existing local
	// account whose email matches, but only when the provider asserts the
	// address is verified. After the first sign-in the subject is what
	// identifies the person, so this is a one-time bridge.
	LinkByVerifiedEmail bool `toml:"link_by_verified_email"`

	SyncRoles    bool              `toml:"sync_roles"`
	DefaultRoles []string          `toml:"default_roles"`
	RoleMappings []OIDCRoleMapping `toml:"role_mappings"`

	RPInitiatedLogout bool     `toml:"rp_initiated_logout"`
	DiscoveryInterval Duration `toml:"discovery_interval"`
	ClockSkew         Duration `toml:"clock_skew"`
}

// OIDCRoleMapping grants a Sable role to everyone carrying one group from the
// provider. Group is whatever the groups claim contains: a name for Pocket ID,
// Authentik, and Keycloak, an object identifier for Entra ID unless the app
// registration is configured to emit names.
type OIDCRoleMapping struct {
	Group string `toml:"group"`
	Role  string `toml:"role"`
}

// DefaultOIDC is the shape a freshly configured provider starts from. The
// claim names match what Pocket ID, Authentik, and Keycloak send for a request
// asking for the openid, profile, email, and groups scopes.
func DefaultOIDC() OIDC {
	return OIDC{
		DisplayName:         defaultOIDCDisplayName,
		Scopes:              []string{"openid", "profile", "email", "groups"},
		UsernameClaim:       "preferred_username",
		EmailClaim:          "email",
		GroupsClaim:         "groups",
		Provision:           true,
		LinkByVerifiedEmail: true,
		SyncRoles:           true,
		DiscoveryInterval:   Duration{Duration: defaultOIDCDiscoveryInterval},
		ClockSkew:           Duration{Duration: defaultOIDCClockSkew},
	}
}

// Label names the provider on the sign-in button and in the console.
func (settings OIDC) Label() string {
	if trimmed := strings.TrimSpace(settings.DisplayName); trimmed != "" {
		return trimmed
	}
	return defaultOIDCDisplayName
}

// RoleFor reports the Sable role a provider group maps to. Group comparison is
// exact: these are opaque identifiers at the provider and case-folding them
// would silently merge two groups an operator meant to keep apart.
func (settings OIDC) RoleFor(group string) (string, bool) {
	for _, mapping := range settings.RoleMappings {
		if mapping.Group == group {
			return mapping.Role, true
		}
	}
	return "", false
}

// MappedRoles reduces a person's provider groups to the Sable roles they earn,
// including the roles every federated user receives. The result is ordered and
// free of duplicates so two sign-ins with the same groups reconcile to the
// same set.
func (settings OIDC) MappedRoles(groups []string) []string {
	roles := make([]string, 0, len(groups)+len(settings.DefaultRoles))
	for _, role := range settings.DefaultRoles {
		if trimmed := strings.TrimSpace(role); trimmed != "" && !slices.Contains(roles, trimmed) {
			roles = append(roles, trimmed)
		}
	}
	for _, group := range groups {
		if role, mapped := settings.RoleFor(group); mapped && !slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}
	slices.Sort(roles)
	return roles
}

// ManagedRoles lists every role the provider is allowed to grant or take away.
// A role outside this set was assigned by hand in the console and survives
// reconciliation, so an unrelated change at the identity provider cannot
// silently revoke a per-zone grant somebody set up deliberately.
func (settings OIDC) ManagedRoles() []string {
	managed := make([]string, 0, len(settings.RoleMappings)+len(settings.DefaultRoles))
	for _, role := range settings.DefaultRoles {
		if trimmed := strings.TrimSpace(role); trimmed != "" && !slices.Contains(managed, trimmed) {
			managed = append(managed, trimmed)
		}
	}
	for _, mapping := range settings.RoleMappings {
		if mapping.Role != "" && !slices.Contains(managed, mapping.Role) {
			managed = append(managed, mapping.Role)
		}
	}
	slices.Sort(managed)
	return managed
}

// Validate reports every problem with the single sign-on settings. The setup
// wizard calls it before persisting so the operator sees the same rules the
// loader enforces.
func (settings OIDC) Validate() error {
	return errors.Join(settings.validate()...)
}

func (settings OIDC) validate() []error {
	var validationErrors []error
	if settings.DiscoveryInterval.Duration != 0 && settings.DiscoveryInterval.Duration < minimumOIDCDiscoveryInterval {
		validationErrors = append(validationErrors, fmt.Errorf("oidc.discovery_interval must be at least %s", minimumOIDCDiscoveryInterval))
	}
	if settings.ClockSkew.Duration < 0 {
		validationErrors = append(validationErrors, errors.New("oidc.clock_skew must not be negative"))
	}
	if settings.ClockSkew.Duration > maximumOIDCClockSkew {
		validationErrors = append(validationErrors, fmt.Errorf("oidc.clock_skew must be at most %s", maximumOIDCClockSkew))
	}
	seenGroups := make(map[string]struct{}, len(settings.RoleMappings))
	for index, mapping := range settings.RoleMappings {
		field := fmt.Sprintf("oidc.role_mappings[%d]", index)
		if strings.TrimSpace(mapping.Group) == "" {
			validationErrors = append(validationErrors, fmt.Errorf("%s.group is required", field))
		}
		if strings.TrimSpace(mapping.Role) == "" {
			validationErrors = append(validationErrors, fmt.Errorf("%s.role is required", field))
		}
		if _, duplicate := seenGroups[mapping.Group]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("duplicate oidc role mapping for group %q", mapping.Group))
		}
		seenGroups[mapping.Group] = struct{}{}
	}
	if !settings.Enabled {
		return validationErrors
	}
	if strings.TrimSpace(settings.Issuer) == "" {
		validationErrors = append(validationErrors, errors.New("oidc.issuer is required when oidc.enabled is true"))
	} else if err := validateProviderURL("oidc.issuer", settings.Issuer, false); err != nil {
		validationErrors = append(validationErrors, err)
	}
	if strings.TrimSpace(settings.ClientID) == "" {
		validationErrors = append(validationErrors, errors.New("oidc.client_id is required when oidc.enabled is true"))
	}
	if strings.TrimSpace(settings.RedirectURL) == "" {
		validationErrors = append(validationErrors, errors.New("oidc.redirect_url is required when oidc.enabled is true"))
	} else if err := validateProviderURL("oidc.redirect_url", settings.RedirectURL, true); err != nil {
		validationErrors = append(validationErrors, err)
	}
	// Without the openid scope the provider is free to answer with no ID token
	// at all, which leaves nothing to verify an identity against.
	if len(settings.Scopes) > 0 && !slices.Contains(settings.Scopes, "openid") {
		validationErrors = append(validationErrors, errors.New("oidc.scopes must contain openid"))
	}
	// A provider that can neither create accounts nor attach to existing ones
	// and grants no roles is configured to let nobody in.
	if !settings.Provision && !settings.LinkByVerifiedEmail {
		validationErrors = append(validationErrors, errors.New(
			"oidc.provision or oidc.link_by_verified_email must be true, or no one can ever sign in"))
	}
	return validationErrors
}

// validateProviderURL enforces the transport rules the oidc package applies at
// runtime, so a bad value is refused when it is typed rather than at the first
// attempted sign-in. Plain HTTP is tolerated only against a loopback host,
// which is where a developer runs a throwaway provider.
func validateProviderURL(field, value string, isRedirect bool) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return fmt.Errorf("%s must be an absolute URL", field)
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		host := parsed.Hostname()
		address := net.ParseIP(host)
		if host != "localhost" && (address == nil || !address.IsLoopback()) {
			return fmt.Errorf("%s must use https", field)
		}
	default:
		return fmt.Errorf("%s must use https", field)
	}
	if isRedirect && (parsed.RawQuery != "" || parsed.Fragment != "") {
		return fmt.Errorf("%s must not carry a query or fragment", field)
	}
	return nil
}
