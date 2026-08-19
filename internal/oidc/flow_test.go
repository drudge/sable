package oidc

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCompleteReturnsTheVerifiedIdentity(t *testing.T) {
	provider := newFakeProvider(t)
	party := provider.relyingParty(t, nil)

	request, err := party.Begin(context.Background(), "/zones")
	if err != nil {
		t.Fatalf("begin sign-in: %v", err)
	}
	provider.claims["nonce"] = request.Nonce

	identity, err := party.Complete(context.Background(), "code-1", request)
	if err != nil {
		t.Fatalf("complete sign-in: %v", err)
	}
	if identity.Subject != "user-1" {
		t.Errorf("subject = %q, want user-1", identity.Subject)
	}
	if identity.Username != "nick" {
		t.Errorf("username = %q, want nick", identity.Username)
	}
	if identity.Email != "nick@example.com" || !identity.EmailVerified {
		t.Errorf("email = %q verified = %v, want nick@example.com verified", identity.Email, identity.EmailVerified)
	}
	if strings.Join(identity.Groups, ",") != "dns-admins,noc" {
		t.Errorf("groups = %v, want [dns-admins noc]", identity.Groups)
	}
	if identity.Issuer != normalizeIssuer(provider.issuer()) {
		t.Errorf("issuer = %q, want %q", identity.Issuer, provider.issuer())
	}
}

func TestBeginSendsPKCEAndSingleUseValues(t *testing.T) {
	provider := newFakeProvider(t)
	party := provider.relyingParty(t, nil)

	first, err := party.Begin(context.Background(), "")
	if err != nil {
		t.Fatalf("begin sign-in: %v", err)
	}
	second, err := party.Begin(context.Background(), "")
	if err != nil {
		t.Fatalf("begin second sign-in: %v", err)
	}
	if first.State == second.State || first.Nonce == second.Nonce || first.CodeVerifier == second.CodeVerifier {
		t.Fatal("two sign-ins reused a state, nonce, or verifier")
	}
	parsed, err := url.Parse(first.URL)
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	query := parsed.Query()
	if query.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", query.Get("code_challenge_method"))
	}
	if query.Get("code_challenge") == "" || query.Get("code_challenge") == first.CodeVerifier {
		t.Error("code challenge is missing or is the bare verifier")
	}
	if query.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want code", query.Get("response_type"))
	}
	// A verifier below 43 characters is outside what the PKCE spec permits.
	if len(first.CodeVerifier) < 43 {
		t.Errorf("code verifier is %d characters, want at least 43", len(first.CodeVerifier))
	}
}

func TestCompleteSendsTheVerifierToTheTokenEndpoint(t *testing.T) {
	provider := newFakeProvider(t)
	party := provider.relyingParty(t, nil)
	request, err := party.Begin(context.Background(), "")
	if err != nil {
		t.Fatalf("begin sign-in: %v", err)
	}
	provider.claims["nonce"] = request.Nonce
	if _, err := party.Complete(context.Background(), "code-1", request); err != nil {
		t.Fatalf("complete sign-in: %v", err)
	}
	if provider.lastForm["code_verifier"] != request.CodeVerifier {
		t.Errorf("code_verifier = %q, want %q", provider.lastForm["code_verifier"], request.CodeVerifier)
	}
	if provider.lastForm["grant_type"] != "authorization_code" {
		t.Errorf("grant_type = %q, want authorization_code", provider.lastForm["grant_type"])
	}
	if provider.lastForm["client_secret"] != "secret" {
		t.Error("client secret was not posted when the provider advertises client_secret_post")
	}
}

func TestCompleteUsesBasicWhenThatIsAllTheProviderTakes(t *testing.T) {
	provider := newFakeProvider(t)
	provider.authMethods = []string{"client_secret_basic"}
	party := provider.relyingParty(t, nil)
	request, err := party.Begin(context.Background(), "")
	if err != nil {
		t.Fatalf("begin sign-in: %v", err)
	}
	provider.claims["nonce"] = request.Nonce
	if _, err := party.Complete(context.Background(), "code-1", request); err != nil {
		t.Fatalf("complete sign-in: %v", err)
	}
	if !strings.HasPrefix(provider.lastForm["_authorization"], "Basic ") {
		t.Errorf("authorization header = %q, want a Basic credential", provider.lastForm["_authorization"])
	}
	if provider.lastForm["client_secret"] != "" {
		t.Error("client secret was posted in the form as well as the header")
	}
}

func TestCompleteSignsInWithAnECKey(t *testing.T) {
	provider := newFakeProvider(t)
	provider.algorithm = "ES256"
	party := provider.relyingParty(t, nil)
	request, err := party.Begin(context.Background(), "")
	if err != nil {
		t.Fatalf("begin sign-in: %v", err)
	}
	provider.claims["nonce"] = request.Nonce
	if _, err := party.Complete(context.Background(), "code-1", request); err != nil {
		t.Fatalf("complete sign-in with ES256: %v", err)
	}
}

// TestCompleteRejectsBadTokens is the security core of this package. Each case
// changes exactly one thing about an otherwise valid sign-in and expects the
// sign-in to fail.
func TestCompleteRejectsBadTokens(t *testing.T) {
	tests := []struct {
		name    string
		arrange func(*fakeProvider, *Request)
		wantErr error
	}{
		{
			name: "signature tampered",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.tamper = func(token string) string {
					parts := strings.Split(token, ".")
					// The first character is flipped rather than the last:
					// the trailing character of a base64url segment can carry
					// unused bits, so changing it need not change any byte of
					// the decoded signature.
					signature := []byte(parts[2])
					if signature[0] == 'A' {
						signature[0] = 'B'
					} else {
						signature[0] = 'A'
					}
					return parts[0] + "." + parts[1] + "." + string(signature)
				}
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "payload swapped after signing",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.tamper = func(token string) string {
					parts := strings.Split(token, ".")
					forged := map[string]any{}
					for key, value := range provider.claims {
						forged[key] = value
					}
					forged["sub"] = "somebody-else"
					return parts[0] + "." + encodeSegment(forged) + "." + parts[2]
				}
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "unsigned token",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.algorithm = "none"
			},
			wantErr: ErrUnsupported,
		},
		{
			name: "hmac signed with the published public key",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.algorithm = "HS256"
			},
			wantErr: ErrUnsupported,
		},
		{
			name: "unknown key identifier",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.tamper = func(token string) string {
					parts := strings.Split(token, ".")
					header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "not-a-key"}
					return encodeSegment(header) + "." + parts[1] + "." + parts[2]
				}
			},
			wantErr: ErrKeyNotFound,
		},
		{
			name: "wrong audience",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.claims["aud"] = "some-other-client"
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "authorized party is another client",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.claims["aud"] = []string{"sable", "other"}
				provider.claims["azp"] = "other"
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "wrong issuer",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.claims["iss"] = "https://id.evil.example"
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "expired",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.claims["exp"] = time.Now().Add(-10 * time.Minute).Unix()
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "not yet valid",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.claims["nbf"] = time.Now().Add(10 * time.Minute).Unix()
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "issued in the future",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.claims["iat"] = time.Now().Add(10 * time.Minute).Unix()
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "no expiry at all",
			arrange: func(provider *fakeProvider, _ *Request) {
				delete(provider.claims, "exp")
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "no subject",
			arrange: func(provider *fakeProvider, _ *Request) {
				delete(provider.claims, "sub")
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "nonce from a different sign-in",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.claims["nonce"] = "a-nonce-from-somewhere-else"
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "nonce missing entirely",
			arrange: func(provider *fakeProvider, _ *Request) {
				delete(provider.claims, "nonce")
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "no id token returned",
			arrange: func(provider *fakeProvider, _ *Request) {
				provider.omitIDToken = true
			},
			wantErr: ErrExchange,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := newFakeProvider(t)
			party := provider.relyingParty(t, nil)
			request, err := party.Begin(context.Background(), "")
			if err != nil {
				t.Fatalf("begin sign-in: %v", err)
			}
			provider.claims["nonce"] = request.Nonce
			test.arrange(provider, &request)

			if _, err := party.Complete(context.Background(), "code-1", request); !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestCompleteReadsGroupsFromUserInfoWhenTheTokenOmitsThem(t *testing.T) {
	provider := newFakeProvider(t)
	delete(provider.claims, "groups")
	provider.userInfo = map[string]any{"sub": "user-1", "groups": []any{"noc"}}
	party := provider.relyingParty(t, func(config *Config) { config.FetchUserInfo = true })

	request, err := party.Begin(context.Background(), "")
	if err != nil {
		t.Fatalf("begin sign-in: %v", err)
	}
	provider.claims["nonce"] = request.Nonce
	identity, err := party.Complete(context.Background(), "code-1", request)
	if err != nil {
		t.Fatalf("complete sign-in: %v", err)
	}
	if strings.Join(identity.Groups, ",") != "noc" {
		t.Errorf("groups = %v, want [noc]", identity.Groups)
	}
}

// A UserInfo response describing a different person must not be merged in, or
// one user's group membership would be attached to another's session.
func TestCompleteIgnoresUserInfoForADifferentSubject(t *testing.T) {
	provider := newFakeProvider(t)
	delete(provider.claims, "groups")
	provider.userInfo = map[string]any{"sub": "somebody-else", "groups": []any{"dns-admins"}}
	party := provider.relyingParty(t, func(config *Config) { config.FetchUserInfo = true })

	request, err := party.Begin(context.Background(), "")
	if err != nil {
		t.Fatalf("begin sign-in: %v", err)
	}
	provider.claims["nonce"] = request.Nonce
	identity, err := party.Complete(context.Background(), "code-1", request)
	if err != nil {
		t.Fatalf("complete sign-in: %v", err)
	}
	if len(identity.Groups) != 0 {
		t.Errorf("groups = %v, want none", identity.Groups)
	}
}

func TestNewRejectsUnusableConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		adjust func(*Config)
	}{
		{"no issuer", func(config *Config) { config.Issuer = "" }},
		{"plaintext issuer over the network", func(config *Config) { config.Issuer = "http://id.example.com" }},
		{"no client id", func(config *Config) { config.ClientID = "" }},
		{"relative redirect", func(config *Config) { config.RedirectURL = "/auth/oidc/callback" }},
		{"plaintext redirect over the network", func(config *Config) { config.RedirectURL = "http://dns.example.com/callback" }},
		{"redirect carrying a query", func(config *Config) { config.RedirectURL = "https://dns.example.com/callback?next=/" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := Config{
				Issuer:      "https://id.example.com",
				ClientID:    "sable",
				RedirectURL: "https://dns.example.com/auth/oidc/callback",
			}
			test.adjust(&config)
			if _, err := New(config); err == nil {
				t.Fatal("configuration was accepted, want a rejection")
			}
		})
	}
}

func TestNewAlwaysRequestsTheOpenIDScope(t *testing.T) {
	party, err := New(Config{
		Issuer:      "https://id.example.com",
		ClientID:    "sable",
		RedirectURL: "https://dns.example.com/auth/oidc/callback",
		Scopes:      []string{"profile"},
	})
	if err != nil {
		t.Fatalf("build relying party: %v", err)
	}
	if party.config.Scopes[0] != "openid" {
		t.Errorf("scopes = %v, want openid first", party.config.Scopes)
	}
}

func TestDiscoveryRejectsADocumentClaimingAnotherIssuer(t *testing.T) {
	provider := newFakeProvider(t)
	party := provider.relyingParty(t, func(config *Config) {
		// Point the relying party at a path the fake does not answer for, so
		// the document it reads names a different issuer than was configured.
		config.Issuer = provider.issuer() + "/tenant-two"
	})
	if _, err := party.Metadata(context.Background()); !errors.Is(err, ErrDiscovery) {
		t.Fatalf("error = %v, want %v", err, ErrDiscovery)
	}
}
