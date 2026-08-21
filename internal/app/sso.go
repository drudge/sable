package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/oidc"
	"github.com/drudge/sable/internal/version"
	"github.com/drudge/sable/internal/web"
)

// ssoProviderKey is the stable name an identity is stored under. It is not the
// issuer URL on purpose: moving a provider to a new hostname, or putting it
// behind a different path, would otherwise orphan every existing link.
const ssoProviderKey = "oidc"

// federatedAuthenticator is the part of the authentication service single
// sign-on needs.
type federatedAuthenticator interface {
	FederatedLogin(context.Context, auth.FederatedIdentity, auth.FederatedPolicy, string, string) (auth.Credentials, error)
}

// ssoService turns the [oidc] configuration section plus the client secret in
// the vault into a working relying party, and rebuilds it whenever either one
// changes.
//
// The provider is rebuilt rather than mutated so an in-flight sign-in keeps
// talking to the configuration it started with.
type ssoService struct {
	config  *config.Manager
	secrets *oidcSecretStore
	auth    federatedAuthenticator
	logger  *slog.Logger
	client  *http.Client

	mutex         sync.Mutex
	provider      *oidc.Provider
	builtFor      config.OIDC
	builtKey      string
	builtRedirect string
	buildErr      error
}

func newSSOService(
	manager *config.Manager,
	secrets *oidcSecretStore,
	authentication federatedAuthenticator,
	logger *slog.Logger,
) *ssoService {
	return &ssoService{
		config: manager, secrets: secrets, auth: authentication, logger: logger,
		// A sign-in that hangs holds a browser tab and a request goroutine, so
		// the provider gets a bounded window rather than the default of none.
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// settings reads the current [oidc] section.
func (service *ssoService) settings() config.OIDC {
	if service == nil || service.config == nil {
		return config.OIDC{}
	}
	return service.config.Current().Config.OIDC
}

// redirectURLFor resolves the callback for a block of settings. An empty
// override is the normal case in a cluster: the section is identical on every
// node and each one fills in its own host.
func (service *ssoService) redirectURLFor(settings config.OIDC) string {
	if override := strings.TrimSpace(settings.RedirectURL); override != "" {
		return override
	}
	if service == nil || service.config == nil {
		return ""
	}
	return strings.TrimRight(service.config.Current().Config.AdvertisedBaseURL(), "/") + config.OIDCCallbackPath
}

// Enabled reports whether a provider is configured and switched on. The
// sign-in page calls it on every render, so it only reads configuration.
func (service *ssoService) Enabled() bool {
	settings := service.settings()
	return settings.Enabled && strings.TrimSpace(settings.Issuer) != "" && strings.TrimSpace(settings.ClientID) != ""
}

// Label names the provider on the sign-in button.
func (service *ssoService) Label() string { return service.settings().Label() }

// provider returns a relying party built for the current configuration,
// rebuilding it when the settings or the stored secret have changed.
func (service *ssoService) resolveProvider(ctx context.Context) (*oidc.Provider, error) {
	settings := service.settings()
	if !settings.Enabled {
		return nil, errors.New("single sign-on is not enabled")
	}
	secret, err := service.secrets.Get(ctx)
	if err != nil {
		return nil, err
	}

	redirectURL := service.redirectURLFor(settings)

	service.mutex.Lock()
	defer service.mutex.Unlock()
	if service.provider != nil && service.builtKey == secret &&
		service.builtRedirect == redirectURL && reflect.DeepEqual(service.builtFor, settings) {
		return service.provider, service.buildErr
	}
	built, buildErr := oidc.New(oidc.Config{
		Issuer:       settings.Issuer,
		ClientID:     settings.ClientID,
		ClientSecret: secret,
		RedirectURL:  redirectURL,
		Scopes:       settings.Scopes,
		Claims: oidc.ClaimNames{
			Username: settings.UsernameClaim,
			Email:    settings.EmailClaim,
			Groups:   settings.GroupsClaim,
		},
		FetchUserInfo:     settings.FetchUserInfo,
		ClockSkew:         settings.ClockSkew.Duration,
		DiscoveryInterval: settings.DiscoveryInterval.Duration,
		HTTPClient:        service.client,
		UserAgent:         "sable/" + version.Release,
	})
	service.provider, service.builtFor, service.builtKey, service.buildErr = built, settings, secret, buildErr
	service.builtRedirect = redirectURL
	if buildErr != nil {
		service.provider = nil
	}
	return built, buildErr
}

// Begin starts a sign-in against the configured provider.
func (service *ssoService) Begin(ctx context.Context, returnTo string) (oidc.Request, error) {
	provider, err := service.resolveProvider(ctx)
	if err != nil {
		return oidc.Request{}, err
	}
	return provider.Begin(ctx, returnTo)
}

// Complete redeems the authorization code and turns the verified identity into
// a Sable session.
func (service *ssoService) Complete(
	ctx context.Context,
	code string,
	request oidc.Request,
	clientIP, userAgent string,
) (auth.Credentials, error) {
	provider, err := service.resolveProvider(ctx)
	if err != nil {
		return auth.Credentials{}, err
	}
	identity, err := provider.Complete(ctx, code, request)
	if err != nil {
		return auth.Credentials{}, err
	}
	settings := service.settings()
	return service.auth.FederatedLogin(ctx, auth.FederatedIdentity{
		Subject:       identity.Subject,
		Username:      identity.Username,
		DisplayName:   identity.DisplayName,
		Email:         identity.Email,
		EmailVerified: identity.EmailVerified,
	}, auth.FederatedPolicy{
		Provider:            ssoProviderKey,
		Issuer:              identity.Issuer,
		Provision:           settings.Provision,
		LinkByVerifiedEmail: settings.LinkByVerifiedEmail,
		SyncRoles:           settings.SyncRoles,
		ManagedRoles:        settings.ManagedRoles(),
		GrantedRoles:        settings.MappedRoles(identity.Groups),
	}, clientIP, userAgent)
}

// LogoutURL reports where to send a browser to end the session at the provider
// as well as here, when the operator asked for that and the provider supports
// it.
func (service *ssoService) LogoutURL(ctx context.Context, postLogoutRedirect string) (string, bool) {
	if !service.settings().RPInitiatedLogout {
		return "", false
	}
	provider, err := service.resolveProvider(ctx)
	if err != nil {
		return "", false
	}
	return provider.LogoutURL(ctx, postLogoutRedirect)
}

// Status describes the configured provider without contacting it.
func (service *ssoService) Status(ctx context.Context) web.SSOStatusView {
	settings := service.settings()
	secret, _ := service.secrets.Get(ctx)
	return web.SSOStatusView{
		Configured:       strings.TrimSpace(settings.Issuer) != "" && strings.TrimSpace(settings.ClientID) != "",
		Enabled:          settings.Enabled,
		Label:            settings.Label(),
		Issuer:           settings.Issuer,
		ClientID:         settings.ClientID,
		RedirectURL:      service.redirectURLFor(settings),
		RedirectOverride: settings.RedirectURL,
		Scopes:           settings.Scopes,
		UsernameClaim:    settings.UsernameClaim,
		GroupsClaim:      settings.GroupsClaim,
		Provision:        settings.Provision,
		LinkByEmail:      settings.LinkByVerifiedEmail,
		SyncRoles:        settings.SyncRoles,
		DefaultRoles:     settings.DefaultRoles,
		Mappings:         settings.RoleMappings,
		SecretStored:     secret != "",
	}
}

// Check contacts the provider and reports what it found. The console's test
// action uses it so an operator can confirm a setup without opening a browser
// flow and without waiting for somebody to try signing in.
func (service *ssoService) Check(ctx context.Context) web.SSOStatusView {
	status := service.Status(ctx)
	status.Checked = true
	provider, err := service.resolveProvider(ctx)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	metadata, err := provider.Check(ctx)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.Reachable = true
	status.SupportsPKCE = metadata.SupportsPKCE()
	status.EndSession = metadata.EndSessionEndpoint != ""
	return status
}

// Probe contacts a provider that has not been saved yet, so the setup wizard
// can refuse a bad issuer, an unreachable host, or a document that answers for
// somebody else before the operator fills in the rest of the form.
func (service *ssoService) Probe(ctx context.Context, settings config.OIDC, secret string) (web.SSOProbeResult, error) {
	if strings.TrimSpace(secret) == "" {
		// A returning operator leaves the field blank to keep the stored
		// secret. Discovery itself is unauthenticated, so this only matters
		// for what the wizard reports back.
		stored, err := service.secrets.Get(ctx)
		if err != nil {
			return web.SSOProbeResult{}, err
		}
		secret = stored
	}
	candidate, err := oidc.New(oidc.Config{
		Issuer:       settings.Issuer,
		ClientID:     settings.ClientID,
		ClientSecret: secret,
		RedirectURL:  service.redirectURLFor(settings),
		Scopes:       settings.Scopes,
		Claims: oidc.ClaimNames{
			Username: settings.UsernameClaim,
			Email:    settings.EmailClaim,
			Groups:   settings.GroupsClaim,
		},
		ClockSkew:  settings.ClockSkew.Duration,
		HTTPClient: service.client,
		UserAgent:  "sable/" + version.Release,
	})
	if err != nil {
		return web.SSOProbeResult{}, err
	}
	metadata, err := candidate.Check(ctx)
	if err != nil {
		return web.SSOProbeResult{}, err
	}
	return web.SSOProbeResult{
		Issuer:       metadata.Issuer,
		Scopes:       metadata.ScopesSupported,
		Claims:       metadata.ClaimsSupported,
		SupportsPKCE: metadata.SupportsPKCE(),
		EndSession:   metadata.EndSessionEndpoint != "",
	}, nil
}

// PutSecret stores the client secret on its own, which the wizard does as soon
// as the provider answers so the later steps need not carry it.
func (service *ssoService) PutSecret(ctx context.Context, secret string) error {
	return service.secrets.Put(ctx, secret)
}

// Save writes a provider configuration and its secret together. The secret
// goes in first: a configuration pointing at a provider Sable has no secret
// for cannot complete a sign-in, and failing before the config is written
// leaves the previous working setup in place.
func (service *ssoService) Save(ctx context.Context, settings config.OIDC, secret string) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	if settings.Enabled {
		if err := service.secrets.Put(ctx, secret); err != nil {
			return err
		}
	} else if strings.TrimSpace(secret) != "" {
		if err := service.secrets.Put(ctx, secret); err != nil {
			return err
		}
	}
	if err := service.config.Update(ctx, func(current *config.Config) error {
		current.OIDC = settings
		return nil
	}); err != nil {
		return fmt.Errorf("save single sign-on settings: %w", err)
	}
	return nil
}

// Remove forgets the provider entirely, including its secret. Existing links
// are left in the database: an operator who reconnects the same provider gets
// their users back rather than a pile of duplicates, and an operator who does
// not can delete the accounts from the administration page.
func (service *ssoService) Remove(ctx context.Context) error {
	if err := service.config.Update(ctx, func(current *config.Config) error {
		current.OIDC = config.DefaultOIDC()
		return nil
	}); err != nil {
		return fmt.Errorf("remove single sign-on settings: %w", err)
	}
	if err := service.secrets.Forget(ctx); err != nil {
		service.logger.Warn("clear stored OIDC client secret", "error", err)
	}
	service.mutex.Lock()
	service.provider, service.builtFor, service.builtKey, service.buildErr = nil, config.OIDC{}, "", nil
	service.mutex.Unlock()
	return nil
}

// SignInOrigins reports where the sign-in button sends the browser, so the
// console can name the provider in that page's form-action policy. It reads
// configuration plus whatever discovery has already cached and never contacts
// the provider, because the sign-in page renders it on every request.
func (service *ssoService) SignInOrigins() []string {
	service.mutex.Lock()
	provider := service.provider
	service.mutex.Unlock()
	if provider != nil {
		return provider.SignInOrigins()
	}
	// No provider has been built yet, which is the ordinary state until
	// somebody signs in. The issuer is where every provider Sable has seen
	// authorizes, so it is enough to get the first sign-in moving.
	if origin, ok := oidc.OriginOf(service.settings().Issuer); ok {
		return []string{origin}
	}
	return nil
}
