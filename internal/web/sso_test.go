package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/oidc"
)

// fakeSSO stands in for the configured provider. The handlers under test are
// responsible for the round trip through the browser, not for anything the
// oidc package proves, so this records what it was asked and answers directly.
type fakeSSO struct {
	enabled     bool
	beginErr    error
	completeErr error
	credentials auth.Credentials
	logoutURL   string
	logoutOK    bool

	completedCode string
	completedWith oidc.Request
	completeCalls int
}

func (fake *fakeSSO) Enabled() bool { return fake.enabled }
func (fake *fakeSSO) Label() string { return "Example SSO" }

func (fake *fakeSSO) Begin(_ context.Context, returnTo string) (oidc.Request, error) {
	if fake.beginErr != nil {
		return oidc.Request{}, fake.beginErr
	}
	return oidc.Request{
		URL:          "https://id.example.com/authorize?state=state-1",
		State:        "state-1",
		Nonce:        "nonce-1",
		CodeVerifier: "verifier-1",
		ReturnTo:     returnTo,
	}, nil
}

func (fake *fakeSSO) Complete(_ context.Context, code string, request oidc.Request, _, _ string) (auth.Credentials, error) {
	fake.completeCalls++
	fake.completedCode, fake.completedWith = code, request
	if fake.completeErr != nil {
		return auth.Credentials{}, fake.completeErr
	}
	return fake.credentials, nil
}

func (fake *fakeSSO) LogoutURL(context.Context, string) (string, bool) {
	return fake.logoutURL, fake.logoutOK
}

func newSSOTestServer(t *testing.T, provider *fakeSSO) *Server {
	t.Helper()
	return &Server{
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		securityEnabled: true,
		sessionCookie:   "sable_session_test",
		preAuthTokens:   newPreAuthTokenStore(),
		ssoStateStore:   newSSOStateStore(),
		crossOrigin:     &http.CrossOriginProtection{},
		sso:             provider,
	}
}

// startSignIn drives the start handler and returns the redirect target and the
// state cookie the browser would carry.
func startSignIn(t *testing.T, server *Server, returnTo string) (*http.Response, *http.Cookie) {
	t.Helper()
	token, err := server.preAuthTokens.issue()
	if err != nil {
		t.Fatalf("issue form token: %v", err)
	}
	form := url.Values{"csrf_token": {token}, "return_to": {returnTo}}
	request := httptest.NewRequest(http.MethodPost, "http://dns.example.test/auth/oidc/start", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.startSSO(response, request)

	result := response.Result()
	for _, cookie := range result.Cookies() {
		if cookie.Name == ssoStateCookieName && cookie.Value != "" {
			return result, cookie
		}
	}
	return result, nil
}

func TestStartSignInRedirectsAndStoresState(t *testing.T) {
	server := newSSOTestServer(t, &fakeSSO{enabled: true})
	result, cookie := startSignIn(t, server, "/zones")

	if result.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusSeeOther)
	}
	if location := result.Header.Get("Location"); !strings.HasPrefix(location, "https://id.example.com/authorize") {
		t.Fatalf("location = %q, want the provider's authorize endpoint", location)
	}
	if cookie == nil {
		t.Fatal("no state cookie was set")
	}
	if !cookie.HttpOnly {
		t.Error("the state cookie is readable by scripts")
	}
	// Strict would withhold the cookie on the provider's top-level redirect
	// back, so no sign-in could ever complete.
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("state cookie SameSite = %v, want Lax", cookie.SameSite)
	}
}

// The verifier proves the callback belongs to the browser that started. It
// must never travel to that browser.
func TestStartSignInKeepsTheVerifierOffTheBrowser(t *testing.T) {
	server := newSSOTestServer(t, &fakeSSO{enabled: true})
	result, cookie := startSignIn(t, server, "/")

	if cookie == nil {
		t.Fatal("no state cookie was set")
	}
	if strings.Contains(cookie.Value, "verifier-1") || strings.Contains(cookie.Value, "nonce-1") {
		t.Fatal("the state cookie carries the PKCE verifier or the nonce")
	}
	if strings.Contains(result.Header.Get("Location"), "verifier-1") {
		t.Fatal("the redirect URL carries the PKCE verifier")
	}
}

func TestStartSignInRequiresAFormToken(t *testing.T) {
	server := newSSOTestServer(t, &fakeSSO{enabled: true})
	form := url.Values{"csrf_token": {"not-a-real-token"}}
	request := httptest.NewRequest(http.MethodPost, "http://dns.example.test/auth/oidc/start", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.startSSO(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestStartSignInIsAbsentWithoutAProvider(t *testing.T) {
	server := newSSOTestServer(t, &fakeSSO{enabled: false})
	request := httptest.NewRequest(http.MethodPost, "http://dns.example.test/auth/oidc/start", nil)
	response := httptest.NewRecorder()
	server.startSSO(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

// callback drives the callback handler with a given state cookie and query.
func callback(t *testing.T, server *Server, cookie *http.Cookie, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://dns.example.test/auth/oidc/callback?"+query.Encode(), nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	server.completeSSO(response, request)
	return response
}

func TestCallbackCompletesTheSignIn(t *testing.T) {
	provider := &fakeSSO{enabled: true, credentials: auth.Credentials{SessionToken: "session-1"}}
	server := newSSOTestServer(t, provider)
	_, cookie := startSignIn(t, server, "/zones")

	response := callback(t, server, cookie, url.Values{"code": {"code-1"}, "state": {"state-1"}})

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if location := response.Header().Get("Location"); location != "/zones" {
		t.Fatalf("location = %q, want /zones", location)
	}
	if provider.completedCode != "code-1" {
		t.Errorf("exchanged code = %q, want code-1", provider.completedCode)
	}
	if provider.completedWith.CodeVerifier != "verifier-1" {
		t.Errorf("verifier = %q, want the one stored at start", provider.completedWith.CodeVerifier)
	}
	var session *http.Cookie
	for _, candidate := range response.Result().Cookies() {
		if candidate.Name == "sable_session_test" {
			session = candidate
		}
	}
	if session == nil || session.Value != "session-1" {
		t.Fatal("the session cookie was not set")
	}
}

// Without the state comparison a callback forged by another site would be
// redeemed against this browser's stored verifier.
func TestCallbackRejectsAMismatchedState(t *testing.T) {
	provider := &fakeSSO{enabled: true}
	server := newSSOTestServer(t, provider)
	_, cookie := startSignIn(t, server, "/")

	response := callback(t, server, cookie, url.Values{"code": {"code-1"}, "state": {"some-other-state"}})

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if provider.completeCalls != 0 {
		t.Fatal("the code was exchanged despite the state mismatch")
	}
}

func TestCallbackRejectsAMissingStateCookie(t *testing.T) {
	provider := &fakeSSO{enabled: true}
	server := newSSOTestServer(t, provider)
	startSignIn(t, server, "/")

	response := callback(t, server, nil, url.Values{"code": {"code-1"}, "state": {"state-1"}})

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if provider.completeCalls != 0 {
		t.Fatal("the code was exchanged without a state cookie")
	}
}

// An intercepted callback URL is worth nothing once the browser has used it.
func TestCallbackStateIsSingleUse(t *testing.T) {
	provider := &fakeSSO{enabled: true, credentials: auth.Credentials{SessionToken: "session-1"}}
	server := newSSOTestServer(t, provider)
	_, cookie := startSignIn(t, server, "/")
	query := url.Values{"code": {"code-1"}, "state": {"state-1"}}

	if first := callback(t, server, cookie, query); first.Code != http.StatusSeeOther {
		t.Fatalf("first callback status = %d, want %d", first.Code, http.StatusSeeOther)
	}
	second := callback(t, server, cookie, query)
	if second.Code != http.StatusForbidden {
		t.Fatalf("replayed callback status = %d, want %d", second.Code, http.StatusForbidden)
	}
	if provider.completeCalls != 1 {
		t.Fatalf("complete calls = %d, want the replay to have been refused", provider.completeCalls)
	}
}

// The state cookie is cleared even when the attempt fails, so a half-finished
// sign-in cannot be retried against the same stored verifier.
func TestCallbackClearsTheStateCookieOnFailure(t *testing.T) {
	server := newSSOTestServer(t, &fakeSSO{enabled: true})
	_, cookie := startSignIn(t, server, "/")

	response := callback(t, server, cookie, url.Values{"error": {"access_denied"}})

	cleared := false
	for _, candidate := range response.Result().Cookies() {
		if candidate.Name == ssoStateCookieName && candidate.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("the state cookie was not cleared after a refused sign-in")
	}
}

// The provider's own error text is attacker-influenced and must not reach the
// rendered page.
func TestCallbackDoesNotRenderTheProvidersErrorText(t *testing.T) {
	server := newSSOTestServer(t, &fakeSSO{enabled: true})
	_, cookie := startSignIn(t, server, "/")

	query := url.Values{
		"error":             {"access_denied"},
		"error_description": {"<script>alert(1)</script> contact evil.example"},
	}
	response := callback(t, server, cookie, query)

	if strings.Contains(response.Body.String(), "evil.example") {
		t.Fatal("the provider's error description was rendered on the sign-in page")
	}
}

func TestCallbackMapsFailuresToUsefulStatuses(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantText   string
	}{
		{"no account", auth.ErrNoFederatedAccount, http.StatusForbidden, "not set up in Sable"},
		{"no console access", auth.ErrForbidden, http.StatusForbidden, "not allowed to sign in"},
		{"rate limited", auth.ErrRateLimited, http.StatusTooManyRequests, "Too many sign-in attempts"},
		{"provider unreachable", oidc.ErrDiscovery, http.StatusBadGateway, "could not reach the identity provider"},
		{"bad token", oidc.ErrInvalidToken, http.StatusUnauthorized, "Single sign-on failed"},
		{"anything else", errors.New("boom"), http.StatusUnauthorized, "Single sign-on failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newSSOTestServer(t, &fakeSSO{enabled: true, completeErr: test.err})
			_, cookie := startSignIn(t, server, "/")
			response := callback(t, server, cookie, url.Values{"code": {"code-1"}, "state": {"state-1"}})

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if !strings.Contains(response.Body.String(), test.wantText) {
				t.Fatalf("body does not mention %q", test.wantText)
			}
		})
	}
}

// A return target pointing at another host would turn the sign-in into an open
// redirect that arrives already authenticated.
func TestCallbackRefusesAnOffSiteReturnTarget(t *testing.T) {
	provider := &fakeSSO{enabled: true, credentials: auth.Credentials{SessionToken: "session-1"}}
	server := newSSOTestServer(t, provider)
	_, cookie := startSignIn(t, server, "https://evil.example/steal")

	response := callback(t, server, cookie, url.Values{"code": {"code-1"}, "state": {"state-1"}})

	if location := response.Header().Get("Location"); location != "/" {
		t.Fatalf("location = %q, want / rather than the off-site target", location)
	}
}

func TestSignInPageShowsTheProviderButton(t *testing.T) {
	server := newSSOTestServer(t, &fakeSSO{enabled: true})
	request := httptest.NewRequest(http.MethodGet, "http://dns.example.test/login", nil)
	response := httptest.NewRecorder()
	server.renderAuthPage(response, request, false, "", http.StatusOK)

	body := response.Body.String()
	if !strings.Contains(body, "Sign in with Example SSO") {
		t.Fatal("the sign-in page does not offer the provider button")
	}
	if !strings.Contains(body, `action="/auth/oidc/start"`) {
		t.Fatal("the provider button does not post to the start route")
	}
}

func TestSignInPageHidesTheButtonWithoutAProvider(t *testing.T) {
	server := newSSOTestServer(t, &fakeSSO{enabled: false})
	request := httptest.NewRequest(http.MethodGet, "http://dns.example.test/login", nil)
	response := httptest.NewRecorder()
	server.renderAuthPage(response, request, false, "", http.StatusOK)

	if strings.Contains(response.Body.String(), "/auth/oidc/start") {
		t.Fatal("the sign-in page offers a provider button with no provider configured")
	}
}

func TestSignInRoutesAreReachableWithoutASession(t *testing.T) {
	for _, path := range []string{ssoStartPath, ssoCallbackPath} {
		if !publicRequest(path) {
			t.Fatalf("%s requires a session, so no one could ever sign in through it", path)
		}
	}
}
