package oidc

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// registeredClaims are the claims OpenID Connect fixes the meaning of. Every
// one of them is checked; the provider-specific claims are read separately
// because their names are configurable.
type registeredClaims struct {
	Issuer          string      `json:"iss"`
	Subject         string      `json:"sub"`
	Audience        audience    `json:"aud"`
	AuthorizedParty string      `json:"azp"`
	Expires         numericDate `json:"exp"`
	IssuedAt        numericDate `json:"iat"`
	NotBefore       numericDate `json:"nbf"`
	Nonce           string      `json:"nonce"`
}

// audience is a claim OpenID Connect allows to be either one string or an
// array of them, so it needs a decoder that accepts both shapes.
type audience []string

func (list *audience) UnmarshalJSON(raw []byte) error {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		*list = audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return fmt.Errorf("aud is neither a string nor an array of strings")
	}
	*list = many
	return nil
}

func (list audience) contains(value string) bool {
	for _, entry := range list {
		// Constant time is not strictly required for a public identifier, but
		// the comparison is cheap and keeps the habit consistent with the rest
		// of the token checks.
		if subtle.ConstantTimeCompare([]byte(entry), []byte(value)) == 1 {
			return true
		}
	}
	return false
}

// numericDate is the seconds-since-epoch encoding OpenID Connect uses. Some
// providers emit it as a JSON string, so both are accepted.
type numericDate time.Time

func (stamp *numericDate) UnmarshalJSON(raw []byte) error {
	text := strings.Trim(string(raw), `"`)
	if text == "" || text == "null" {
		return nil
	}
	seconds, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return fmt.Errorf("timestamp %q is not a number", text)
	}
	*stamp = numericDate(time.Unix(int64(seconds), 0).UTC())
	return nil
}

func (stamp numericDate) time() time.Time { return time.Time(stamp) }

// ClaimNames tells the verifier which provider claims carry the fields Sable
// cares about. The defaults match what Pocket ID, Authentik, and Keycloak send
// for a request that asks for the openid, profile, email, and groups scopes.
type ClaimNames struct {
	Username string
	Email    string
	Groups   string
	Picture  string
}

func (names ClaimNames) withDefaults() ClaimNames {
	if names.Username == "" {
		names.Username = "preferred_username"
	}
	if names.Email == "" {
		names.Email = "email"
	}
	if names.Groups == "" {
		names.Groups = "groups"
	}
	if names.Picture == "" {
		names.Picture = "picture"
	}
	return names
}

// verification is everything the caller must prove about a token beyond its
// signature.
type verification struct {
	issuer    string
	clientID  string
	nonce     string
	skew      time.Duration
	claims    ClaimNames
	now       time.Time
	requireAt bool
}

// validateClaims runs every check OpenID Connect requires of an ID token. The
// order does not matter to correctness, but each failure names one reason so a
// misconfiguration is diagnosable from the server log.
func validateClaims(payload []byte, check verification) (Identity, error) {
	var registered registeredClaims
	if err := json.Unmarshal(payload, &registered); err != nil {
		return Identity{}, fmt.Errorf("%w: payload is not a claim set: %v", ErrInvalidToken, err)
	}
	if normalizeIssuer(registered.Issuer) != normalizeIssuer(check.issuer) {
		return Identity{}, fmt.Errorf("%w: issued by %q, expected %q", ErrInvalidToken, registered.Issuer, check.issuer)
	}
	if registered.Subject == "" {
		return Identity{}, fmt.Errorf("%w: no subject", ErrInvalidToken)
	}
	if !registered.Audience.contains(check.clientID) {
		return Identity{}, fmt.Errorf("%w: audience %v does not include this client", ErrInvalidToken, []string(registered.Audience))
	}
	// With more than one audience the spec requires azp, and requires it to be
	// this client. Without the check a token minted for a different client at
	// the same provider would be accepted here.
	if len(registered.Audience) > 1 && registered.AuthorizedParty != check.clientID {
		return Identity{}, fmt.Errorf("%w: authorized party is %q", ErrInvalidToken, registered.AuthorizedParty)
	}
	if registered.AuthorizedParty != "" && registered.AuthorizedParty != check.clientID {
		return Identity{}, fmt.Errorf("%w: authorized party is %q", ErrInvalidToken, registered.AuthorizedParty)
	}
	expires := registered.Expires.time()
	if expires.IsZero() {
		return Identity{}, fmt.Errorf("%w: no expiry", ErrInvalidToken)
	}
	if !check.now.Add(-check.skew).Before(expires) {
		return Identity{}, fmt.Errorf("%w: expired at %s", ErrInvalidToken, expires.Format(time.RFC3339))
	}
	if notBefore := registered.NotBefore.time(); !notBefore.IsZero() && check.now.Add(check.skew).Before(notBefore) {
		return Identity{}, fmt.Errorf("%w: not valid until %s", ErrInvalidToken, notBefore.Format(time.RFC3339))
	}
	issuedAt := registered.IssuedAt.time()
	if check.requireAt && issuedAt.IsZero() {
		return Identity{}, fmt.Errorf("%w: no issued-at", ErrInvalidToken)
	}
	// A token stamped in the future is a clock problem at best and a replay of
	// something minted elsewhere at worst.
	if !issuedAt.IsZero() && issuedAt.After(check.now.Add(check.skew)) {
		return Identity{}, fmt.Errorf("%w: issued at %s, which is ahead of this server", ErrInvalidToken, issuedAt.Format(time.RFC3339))
	}
	// The nonce ties this token to the browser that started the sign-in. Its
	// absence is what turns a stolen token into a working replay.
	if check.nonce != "" && subtle.ConstantTimeCompare([]byte(registered.Nonce), []byte(check.nonce)) != 1 {
		return Identity{}, fmt.Errorf("%w: nonce does not match the sign-in that started here", ErrInvalidToken)
	}

	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Identity{}, fmt.Errorf("%w: payload is not an object", ErrInvalidToken)
	}
	names := check.claims.withDefaults()
	identity := Identity{
		Issuer:        normalizeIssuer(registered.Issuer),
		Subject:       registered.Subject,
		Username:      stringClaim(raw, names.Username),
		DisplayName:   stringClaim(raw, "name"),
		Email:         strings.ToLower(stringClaim(raw, names.Email)),
		EmailVerified: boolClaim(raw, "email_verified"),
		Groups:        stringsClaim(raw, names.Groups),
		Picture:       stringClaim(raw, names.Picture),
	}
	return identity, nil
}

func stringClaim(raw map[string]any, name string) string {
	value, found := raw[name]
	if !found {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

// boolClaim accepts the string spellings too. Providers have been known to
// send email_verified as "true", and reading that as false would quietly
// disable email linking for every user.
func boolClaim(raw map[string]any, name string) bool {
	switch value := raw[name].(type) {
	case bool:
		return value
	case string:
		parsed, err := strconv.ParseBool(value)
		return err == nil && parsed
	default:
		return false
	}
}

// stringsClaim reads a claim that should be an array of strings but may arrive
// as a single string. Entra sends group object identifiers, Pocket ID and
// Authentik send names; either way they are opaque labels to Sable.
func stringsClaim(raw map[string]any, name string) []string {
	switch value := raw[name].(type) {
	case []any:
		entries := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				entries = append(entries, strings.TrimSpace(text))
			}
		}
		return entries
	case string:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		return []string{strings.TrimSpace(value)}
	default:
		return nil
	}
}
