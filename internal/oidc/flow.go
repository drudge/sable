package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Config describes one identity provider. Everything except the client secret
// comes from the [oidc] section of sable.toml; the secret is read from the
// encrypted vault by the caller and handed in here.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Claims       ClaimNames

	// FetchUserInfo asks the UserInfo endpoint for the claims the ID token did
	// not carry. Some providers only put group membership there.
	FetchUserInfo bool

	ClockSkew         time.Duration
	DiscoveryInterval time.Duration

	HTTPClient *http.Client
	UserAgent  string
	Now        func() time.Time
}

// Provider is a configured relying party. It is safe for concurrent use and is
// rebuilt, not mutated, when the [oidc] section is reloaded.
type Provider struct {
	config    Config
	fetcher   *fetcher
	discovery *discoveryCache
	keys      *keyCache
	now       func() time.Time
}

// Request is the per-sign-in state that has to survive the round trip to the
// provider. The caller seals it into a short-lived cookie; none of it may be
// stored where another browser could read it, because holding the verifier is
// what proves the callback belongs to the browser that started.
type Request struct {
	URL          string
	State        string
	Nonce        string
	CodeVerifier string
	ReturnTo     string
}

// New validates a provider configuration and prepares it for use. It performs
// no network calls, so a provider whose issuer is temporarily unreachable
// still lets Sable start.
func New(config Config) (*Provider, error) {
	config.Issuer = normalizeIssuer(config.Issuer)
	if config.Issuer == "" {
		return nil, fmt.Errorf("oidc: issuer is required")
	}
	if err := requireSecureURL(config.Issuer); err != nil {
		return nil, fmt.Errorf("oidc: issuer %w", err)
	}
	if strings.TrimSpace(config.ClientID) == "" {
		return nil, fmt.Errorf("oidc: client id is required")
	}
	if err := validateRedirectURL(config.RedirectURL); err != nil {
		return nil, err
	}
	if config.ClockSkew <= 0 {
		config.ClockSkew = defaultClockSkew
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if len(config.Scopes) == 0 {
		config.Scopes = []string{"openid", "profile", "email", "groups"}
	}
	// "openid" is what makes this an OpenID Connect request rather than a bare
	// OAuth one, and without it the provider need not return an ID token.
	if !slices.Contains(config.Scopes, "openid") {
		config.Scopes = append([]string{"openid"}, config.Scopes...)
	}
	config.Claims = config.Claims.withDefaults()
	fetch := newFetcher(config.HTTPClient, config.UserAgent)
	return &Provider{
		config:    config,
		fetcher:   fetch,
		discovery: newDiscoveryCache(fetch, config.Issuer, config.DiscoveryInterval, config.Now),
		keys:      newKeyCache(fetch, config.Now),
		now:       config.Now,
	}, nil
}

// validateRedirectURL insists on an absolute URL the provider can be told to
// send the browser back to. A relative or wildcard value would let the
// authorization code land somewhere this server does not control.
func validateRedirectURL(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return fmt.Errorf("oidc: redirect url must be an absolute URL")
	}
	if parsed.Scheme != "https" && !isLoopback(parsed.Hostname()) {
		return fmt.Errorf("oidc: redirect url must use https")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("oidc: redirect url must not carry a query or fragment")
	}
	return nil
}

// Metadata returns the provider's discovery document, fetching it if the cache
// is cold or stale.
func (provider *Provider) Metadata(ctx context.Context) (Metadata, error) {
	return provider.discovery.metadataNow(ctx)
}

// Check forces a fresh read of the discovery document and the signing keys.
// The console's test action calls it so an operator sees the provider's real
// current state rather than what Sable cached earlier.
func (provider *Provider) Check(ctx context.Context) (Metadata, error) {
	metadata, err := provider.discovery.refresh(ctx)
	if err != nil {
		return Metadata{}, err
	}
	if err := provider.keys.refresh(ctx, metadata.JWKSURI); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

// Begin starts a sign-in. The returned Request carries the URL to send the
// browser to and the secrets the callback will need to prove the round trip
// was not forged.
func (provider *Provider) Begin(ctx context.Context, returnTo string) (Request, error) {
	metadata, err := provider.Metadata(ctx)
	if err != nil {
		return Request{}, err
	}
	state, err := randomToken()
	if err != nil {
		return Request{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return Request{}, err
	}
	verifier, err := randomToken()
	if err != nil {
		return Request{}, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", provider.config.ClientID)
	query.Set("redirect_uri", provider.config.RedirectURL)
	query.Set("scope", strings.Join(provider.config.Scopes, " "))
	query.Set("state", state)
	query.Set("nonce", nonce)
	// PKCE is sent unconditionally. A provider that ignores it is no worse off
	// than one never asked, and one that honours it stops a leaked
	// authorization code from being redeemed by anybody but this server.
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	separator := "?"
	if strings.Contains(metadata.AuthorizationEndpoint, "?") {
		separator = "&"
	}
	return Request{
		URL:          metadata.AuthorizationEndpoint + separator + query.Encode(),
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		ReturnTo:     returnTo,
	}, nil
}

// tokenResponse is the token endpoint's answer. Sable uses the ID token for
// identity and keeps the access token only long enough to call UserInfo.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

// Complete redeems an authorization code and returns the verified identity it
// stands for. The request argument must be the one Begin produced for this
// browser: its verifier proves possession and its nonce ties the returned
// token to this sign-in.
func (provider *Provider) Complete(ctx context.Context, code string, request Request) (Identity, error) {
	metadata, err := provider.Metadata(ctx)
	if err != nil {
		return Identity{}, err
	}
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("code", code)
	values.Set("redirect_uri", provider.config.RedirectURL)
	values.Set("code_verifier", request.CodeVerifier)
	header := http.Header{}
	// Basic is only chosen when the provider says it takes basic and does not
	// take post, because post is the form every provider in practice accepts.
	if slices.Contains(metadata.TokenAuthMethods, "client_secret_basic") &&
		!slices.Contains(metadata.TokenAuthMethods, "client_secret_post") {
		header.Set("Authorization", "Basic "+basicCredential(provider.config.ClientID, provider.config.ClientSecret))
	} else {
		values.Set("client_id", provider.config.ClientID)
		values.Set("client_secret", provider.config.ClientSecret)
	}
	var tokens tokenResponse
	if err := provider.fetcher.postForm(ctx, metadata.TokenEndpoint, values, header, &tokens); err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrExchange, err)
	}
	if tokens.IDToken == "" {
		return Identity{}, fmt.Errorf("%w: provider returned no id token", ErrExchange)
	}
	identity, err := provider.verify(ctx, metadata, tokens.IDToken, request.Nonce)
	if err != nil {
		return Identity{}, err
	}
	if provider.config.FetchUserInfo && len(identity.Groups) == 0 && metadata.UserInfoEndpoint != "" && tokens.AccessToken != "" {
		provider.fillFromUserInfo(ctx, metadata, tokens.AccessToken, &identity)
	}
	return identity, nil
}

// verify checks a raw ID token end to end: signature against a key the issuer
// publishes, then every claim OpenID Connect fixes.
func (provider *Provider) verify(ctx context.Context, metadata Metadata, token, nonce string) (Identity, error) {
	header, payload, signature, signed, err := parseJWS(token)
	if err != nil {
		return Identity{}, err
	}
	// The algorithm is settled before any key is fetched. Deciding it inside
	// the loop below would collapse "this provider signs with something Sable
	// refuses" into the same generic failure as "the signature is wrong", and
	// those two need different fixes from whoever reads the log.
	if _, accepted := acceptedAlgorithms[header.Algorithm]; !accepted {
		return Identity{}, fmt.Errorf("%w: %q", ErrUnsupported, header.Algorithm)
	}
	candidates, err := provider.keys.keyFor(ctx, metadata.JWKSURI, header.KeyID)
	if err != nil {
		return Identity{}, err
	}
	verified := false
	lastErr := fmt.Errorf("%w: no published key verified this token", ErrInvalidToken)
	for _, key := range candidates {
		if err := verifySignature(header, key, signed, signature); err == nil {
			verified = true
			break
		} else if len(candidates) == 1 {
			lastErr = err
		}
	}
	if !verified {
		return Identity{}, lastErr
	}
	return validateClaims(payload, verification{
		issuer:    provider.config.Issuer,
		clientID:  provider.config.ClientID,
		nonce:     nonce,
		skew:      provider.config.ClockSkew,
		claims:    provider.config.Claims,
		now:       provider.now(),
		requireAt: true,
	})
}

// fillFromUserInfo tops up claims the ID token left out. A failure here is not
// fatal: the identity is already proven, and losing group membership means the
// user signs in with fewer roles rather than none, which is the safe direction.
func (provider *Provider) fillFromUserInfo(ctx context.Context, metadata Metadata, accessToken string, identity *Identity) {
	if err := requireSecureURL(metadata.UserInfoEndpoint); err != nil {
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadata.UserInfoEndpoint, nil)
	if err != nil {
		return
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", provider.fetcher.agent)
	var raw map[string]any
	if err := provider.fetcher.do(request, &raw); err != nil {
		return
	}
	// UserInfo answers for whoever the access token names. If that is not the
	// same subject the ID token named, the two responses are about different
	// people and merging them would attach one person's groups to another.
	if subject, _ := raw["sub"].(string); subject != identity.Subject {
		return
	}
	names := provider.config.Claims
	if len(identity.Groups) == 0 {
		identity.Groups = stringsClaim(raw, names.Groups)
	}
	if identity.Email == "" {
		identity.Email = strings.ToLower(stringClaim(raw, names.Email))
		identity.EmailVerified = boolClaim(raw, "email_verified")
	}
	if identity.Username == "" {
		identity.Username = stringClaim(raw, names.Username)
	}
	if identity.DisplayName == "" {
		identity.DisplayName = stringClaim(raw, "name")
	}
}

// LogoutURL returns the provider's RP-initiated logout URL when it publishes
// one. The second result reports whether the provider supports it at all.
func (provider *Provider) LogoutURL(ctx context.Context, postLogoutRedirect string) (string, bool) {
	metadata, err := provider.Metadata(ctx)
	if err != nil || metadata.EndSessionEndpoint == "" {
		return "", false
	}
	query := url.Values{}
	query.Set("client_id", provider.config.ClientID)
	if postLogoutRedirect != "" {
		query.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	separator := "?"
	if strings.Contains(metadata.EndSessionEndpoint, "?") {
		separator = "&"
	}
	return metadata.EndSessionEndpoint + separator + query.Encode(), true
}

// Issuer reports the normalized issuer this provider was configured with, which
// is the value stored alongside a linked identity.
func (provider *Provider) Issuer() string { return provider.config.Issuer }

func basicCredential(id, secret string) string {
	// The spec form-encodes both halves before base64, which matters for a
	// secret containing a character that is reserved in a URL.
	return base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id) + ":" + url.QueryEscape(secret)))
}

// randomToken produces the 256 bits of entropy behind a state value, a nonce,
// and a PKCE verifier. The encoded length also satisfies the 43 character
// minimum the PKCE spec sets for a verifier.
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// SignInOrigins lists the origins a browser is sent to when a sign-in starts.
//
// The console names them in the sign-in page's form-action policy. That is not
// a relaxation for its own sake: the sign-in button is a form post whose reply
// is a redirect to the provider, and browsers apply form-action to the whole
// redirect chain, so a policy of 'self' alone makes the browser drop the
// redirect and the sign-in silently never leaves the page.
//
// It never contacts the provider, because the sign-in page renders on every
// unauthenticated request. The configured issuer is always reported, and the
// discovered authorization endpoint is added only once discovery has cached
// it, which covers the rare provider that authorizes on another host.
func (provider *Provider) SignInOrigins() []string {
	origins := make([]string, 0, 2)
	if origin, ok := OriginOf(provider.config.Issuer); ok {
		origins = append(origins, origin)
	}
	if metadata, cached := provider.discovery.cachedMetadata(); cached {
		if origin, ok := OriginOf(metadata.AuthorizationEndpoint); ok && !slices.Contains(origins, origin) {
			origins = append(origins, origin)
		}
	}
	return origins
}

// OriginOf reduces an absolute URL to the "scheme://host[:port]" form a
// Content-Security-Policy source expects.
//
// It is deliberately stricter than url.Parse. One of its inputs is an endpoint
// read from the provider's discovery document, which is remote data on its way
// into a response header, so anything carrying a character that could end the
// directive early is rejected rather than escaped.
func OriginOf(value string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" {
		return "", false
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", false
	}
	host := parsed.Hostname()
	if host == "" {
		return "", false
	}
	if strings.Contains(host, ":") {
		// An IPv6 literal loses its brackets to Hostname and needs them back
		// before it can be written as an origin.
		if !isHostSafe(host, true) {
			return "", false
		}
		host = "[" + host + "]"
	} else if !isHostSafe(host, false) {
		return "", false
	}
	origin := parsed.Scheme + "://" + host
	port := parsed.Port()
	if port == "" {
		return origin, true
	}
	for _, char := range port {
		if char < '0' || char > '9' {
			return "", false
		}
	}
	return origin + ":" + port, true
}

// isHostSafe reports whether a host is made only of the characters a hostname
// or an IPv6 literal is allowed to use.
func isHostSafe(host string, allowColon bool) bool {
	for _, char := range host {
		switch {
		case char >= 'a' && char <= 'z',
			char >= 'A' && char <= 'Z',
			char >= '0' && char <= '9',
			char == '.', char == '-':
		case char == ':' && allowColon:
		default:
			return false
		}
	}
	return true
}
