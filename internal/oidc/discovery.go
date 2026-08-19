package oidc

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Metadata is the subset of an OpenID Connect discovery document Sable uses.
// The issuer is security relevant: it is compared against the configured
// issuer and against every token's iss claim.
type Metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
	ClaimsSupported       []string `json:"claims_supported"`
	SigningAlgorithms     []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

// discoveryPath is appended to the issuer to find the metadata document. The
// spec fixes this path, so an issuer that already carries a path keeps it and
// the well-known segment is appended rather than replacing it.
const discoveryPath = "/.well-known/openid-configuration"

// discoveryCache holds the provider's metadata and refreshes it on an interval
// so an endpoint move is picked up without a Sable restart.
type discoveryCache struct {
	fetcher  *fetcher
	issuer   string
	interval time.Duration
	now      func() time.Time

	mutex     sync.Mutex
	metadata  Metadata
	fetchedAt time.Time
}

func newDiscoveryCache(fetcher *fetcher, issuer string, interval time.Duration, now func() time.Time) *discoveryCache {
	if interval <= 0 {
		interval = defaultDiscoveryInterval
	}
	if now == nil {
		now = time.Now
	}
	return &discoveryCache{fetcher: fetcher, issuer: normalizeIssuer(issuer), interval: interval, now: now}
}

// metadataNow returns cached metadata, fetching it when the cache is empty or
// stale. A refresh that fails while a usable document is already cached keeps
// serving the cached one: a provider that is briefly unreachable should not
// take sign-in down when Sable already knows where its endpoints are.
func (cache *discoveryCache) metadataNow(ctx context.Context) (Metadata, error) {
	cache.mutex.Lock()
	cached, fetchedAt := cache.metadata, cache.fetchedAt
	cache.mutex.Unlock()
	if cached.Issuer != "" && cache.now().Sub(fetchedAt) < cache.interval {
		return cached, nil
	}
	fetched, err := cache.fetch(ctx)
	if err != nil {
		if cached.Issuer != "" {
			return cached, nil
		}
		return Metadata{}, err
	}
	cache.mutex.Lock()
	cache.metadata, cache.fetchedAt = fetched, cache.now()
	cache.mutex.Unlock()
	return fetched, nil
}

// refresh forces a fetch regardless of the interval. The console's "test
// connection" action uses it so an operator who just fixed something at the
// provider sees the result immediately.
func (cache *discoveryCache) refresh(ctx context.Context) (Metadata, error) {
	fetched, err := cache.fetch(ctx)
	if err != nil {
		return Metadata{}, err
	}
	cache.mutex.Lock()
	cache.metadata, cache.fetchedAt = fetched, cache.now()
	cache.mutex.Unlock()
	return fetched, nil
}

func (cache *discoveryCache) fetch(ctx context.Context) (Metadata, error) {
	var metadata Metadata
	endpoint := cache.issuer + discoveryPath
	if err := cache.fetcher.getJSON(ctx, endpoint, &metadata); err != nil {
		return Metadata{}, fmt.Errorf("%w from %s: %w", ErrDiscovery, endpoint, err)
	}
	// An issuer that does not name itself is either misconfigured or is
	// answering for somebody else. Either way its endpoints cannot be trusted,
	// because the whole chain of trust downstream is anchored on this match.
	if normalizeIssuer(metadata.Issuer) != cache.issuer {
		return Metadata{}, fmt.Errorf("%w: document at %s claims issuer %q", ErrDiscovery, endpoint, metadata.Issuer)
	}
	if metadata.AuthorizationEndpoint == "" || metadata.TokenEndpoint == "" || metadata.JWKSURI == "" {
		return Metadata{}, fmt.Errorf("%w: document at %s is missing a required endpoint", ErrDiscovery, endpoint)
	}
	for _, endpoint := range []string{metadata.AuthorizationEndpoint, metadata.TokenEndpoint, metadata.JWKSURI} {
		if err := requireSecureURL(endpoint); err != nil {
			return Metadata{}, err
		}
	}
	return metadata, nil
}

// SupportsPKCE reports whether the provider advertises the S256 challenge
// method. Sable sends the challenge either way, because a provider that does
// not advertise the method usually still honours it and one that ignores it is
// no worse off, but the console shows the answer during setup.
func (metadata Metadata) SupportsPKCE() bool {
	for _, method := range metadata.CodeChallengeMethods {
		if strings.EqualFold(method, "S256") {
			return true
		}
	}
	return false
}
