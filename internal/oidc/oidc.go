// Package oidc speaks OpenID Connect to an external identity provider.
//
// Sable ships as one static executable with a deliberately small dependency
// list, and the verification surface an OpenID Connect relying party needs is
// small enough to own outright: fetch a discovery document, cache the signing
// keys it points at, check a compact JWS, and read a handful of claims. Doing
// it here keeps the trust decision in code this project tests directly rather
// than in a transitive dependency tree.
//
// The package is transport and storage free. It knows how to talk to a
// provider and how to decide whether a token is trustworthy. Deciding which
// Sable user a verified token belongs to is the auth package's job.
package oidc

import (
	"errors"
	"strings"
	"time"
)

// Errors callers distinguish. Everything else arrives wrapped with enough
// context for the server log while the browser only ever sees a generic
// failure, because a precise sign-in error is a gift to someone probing.
var (
	ErrDiscovery    = errors.New("read provider metadata")
	ErrKeyNotFound  = errors.New("no signing key matched the token")
	ErrUnsupported  = errors.New("unsupported signing algorithm")
	ErrInvalidToken = errors.New("token failed verification")
	ErrExchange     = errors.New("exchange authorization code")
	ErrStateMissing = errors.New("sign-in did not start on this server")
)

// defaultClockSkew forgives the small clock differences between a provider and
// a DNS server that may not share an NTP source. Sixty seconds is the usual
// relying-party allowance; anything larger meaningfully widens the window an
// expired token stays usable.
const defaultClockSkew = 60 * time.Second

// defaultDiscoveryInterval is how long a fetched discovery document is trusted
// before it is read again. Providers rotate endpoints rarely; an hour keeps a
// rename from stranding sign-in for a whole day without hammering the issuer.
const defaultDiscoveryInterval = time.Hour

// Identity is what a completed sign-in tells Sable about the person who signed
// in. Subject is the only field the caller may treat as stable: everything
// else is display material or a claim the provider is free to change.
type Identity struct {
	Issuer        string
	Subject       string
	Username      string
	DisplayName   string
	Email         string
	EmailVerified bool
	Groups        []string
}

// normalizeIssuer trims the trailing slash so a configured issuer and the one
// a provider states in its metadata and tokens compare equal. Providers differ
// on whether they include it and OpenID Connect requires an exact match, so a
// stray slash would otherwise reject every token from a correct setup.
func normalizeIssuer(issuer string) string {
	return strings.TrimRight(strings.TrimSpace(issuer), "/")
}
