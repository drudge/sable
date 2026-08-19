package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeProvider is an identity provider small enough to run inside a test. It
// serves a real discovery document, a real JWKS, and a token endpoint that
// mints signed ID tokens, so the verification path under test is exercised
// against bytes rather than against mocks of its own internals.
type fakeProvider struct {
	server *httptest.Server

	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey

	// claims is the payload the token endpoint signs. Tests mutate it to
	// produce the token they need.
	claims map[string]any
	// algorithm names how the next issued token is signed.
	algorithm string
	// tamper rewrites the issued token just before it is returned.
	tamper func(string) string
	// authMethods overrides what the discovery document advertises.
	authMethods []string
	// omitIDToken makes the token endpoint answer without an id_token.
	omitIDToken bool
	// userInfo is served from the UserInfo endpoint when non-nil.
	userInfo map[string]any

	// lastForm records what the relying party posted to the token endpoint.
	lastForm map[string]string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	provider := &fakeProvider{rsaKey: rsaKey, ecKey: ecKey, algorithm: "RS256"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", provider.serveDiscovery)
	mux.HandleFunc("/jwks", provider.serveJWKS)
	mux.HandleFunc("/token", provider.serveToken)
	mux.HandleFunc("/userinfo", provider.serveUserInfo)
	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)
	provider.claims = provider.defaultClaims()
	return provider
}

func (provider *fakeProvider) issuer() string { return provider.server.URL }

func (provider *fakeProvider) defaultClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":                provider.issuer(),
		"sub":                "user-1",
		"aud":                "sable",
		"exp":                now.Add(5 * time.Minute).Unix(),
		"iat":                now.Unix(),
		"nonce":              "",
		"preferred_username": "nick",
		"name":               "Nick Penree",
		"email":              "nick@example.com",
		"email_verified":     true,
		"groups":             []string{"dns-admins", "noc"},
	}
}

func (provider *fakeProvider) serveDiscovery(writer http.ResponseWriter, _ *http.Request) {
	methods := provider.authMethods
	if methods == nil {
		methods = []string{"client_secret_post", "client_secret_basic"}
	}
	writeJSON(writer, map[string]any{
		"issuer":                                provider.issuer(),
		"authorization_endpoint":                provider.issuer() + "/authorize",
		"token_endpoint":                        provider.issuer() + "/token",
		"userinfo_endpoint":                     provider.issuer() + "/userinfo",
		"jwks_uri":                              provider.issuer() + "/jwks",
		"end_session_endpoint":                  provider.issuer() + "/logout",
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": methods,
		"id_token_signing_alg_values_supported": []string{"RS256", "ES256"},
	})
}

func (provider *fakeProvider) serveJWKS(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, map[string]any{"keys": []any{
		map[string]any{
			"kty": "RSA",
			"use": "sig",
			"kid": "rsa-1",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(provider.rsaKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(provider.rsaKey.E)).Bytes()),
		},
		map[string]any{
			"kty": "EC",
			"use": "sig",
			"kid": "ec-1",
			"alg": "ES256",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(provider.ecKey.X.FillBytes(make([]byte, 32))),
			"y":   base64.RawURLEncoding.EncodeToString(provider.ecKey.Y.FillBytes(make([]byte, 32))),
		},
	}})
}

func (provider *fakeProvider) serveToken(writer http.ResponseWriter, request *http.Request) {
	_ = request.ParseForm()
	provider.lastForm = map[string]string{}
	for name := range request.Form {
		provider.lastForm[name] = request.Form.Get(name)
	}
	if authorization := request.Header.Get("Authorization"); authorization != "" {
		provider.lastForm["_authorization"] = authorization
	}
	body := map[string]any{"access_token": "access-1", "token_type": "Bearer"}
	if !provider.omitIDToken {
		body["id_token"] = provider.signToken()
	}
	writeJSON(writer, body)
}

func (provider *fakeProvider) serveUserInfo(writer http.ResponseWriter, _ *http.Request) {
	if provider.userInfo == nil {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSON(writer, provider.userInfo)
}

// signToken serializes the current claim set as a compact JWS using the
// configured algorithm, then applies any tamper hook.
func (provider *fakeProvider) signToken() string {
	keyID := "rsa-1"
	if provider.algorithm == "ES256" {
		keyID = "ec-1"
	}
	token := provider.signAs(provider.algorithm, keyID, provider.claims)
	if provider.tamper != nil {
		token = provider.tamper(token)
	}
	return token
}

func (provider *fakeProvider) signAs(algorithm, keyID string, claims map[string]any) string {
	header := map[string]any{"alg": algorithm, "typ": "JWT"}
	if keyID != "" {
		header["kid"] = keyID
	}
	signingInput := encodeSegment(header) + "." + encodeSegment(claims)
	var signature []byte
	switch algorithm {
	case "none":
		signature = nil
	case "HS256":
		// Signed with the provider's own public modulus, which is published in
		// the JWKS. This is the algorithm-confusion attack in concrete form.
		mac := hmac.New(sha256.New, provider.rsaKey.N.Bytes())
		mac.Write([]byte(signingInput))
		signature = mac.Sum(nil)
	case "ES256":
		digest := sha256.Sum256([]byte(signingInput))
		r, s, err := ecdsa.Sign(rand.Reader, provider.ecKey, digest[:])
		if err != nil {
			panic(err)
		}
		signature = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "RS512":
		digest := sha512.Sum512([]byte(signingInput))
		signed, err := rsa.SignPKCS1v15(rand.Reader, provider.rsaKey, crypto.SHA512, digest[:])
		if err != nil {
			panic(err)
		}
		signature = signed
	default:
		digest := sha256.Sum256([]byte(signingInput))
		signed, err := rsa.SignPKCS1v15(rand.Reader, provider.rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			panic(err)
		}
		signature = signed
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// relyingParty builds a Provider pointed at this fake, with the clock and the
// client configuration a test needs.
func (provider *fakeProvider) relyingParty(t *testing.T, adjust func(*Config)) *Provider {
	t.Helper()
	config := Config{
		Issuer:       provider.issuer(),
		ClientID:     "sable",
		ClientSecret: "secret",
		RedirectURL:  "http://127.0.0.1:8080/auth/oidc/callback",
		Scopes:       []string{"openid", "profile", "email", "groups"},
		HTTPClient:   provider.server.Client(),
	}
	if adjust != nil {
		adjust(&config)
	}
	party, err := New(config)
	if err != nil {
		t.Fatalf("build relying party: %v", err)
	}
	return party
}

func encodeSegment(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func writeJSON(writer http.ResponseWriter, body any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(body)
}
