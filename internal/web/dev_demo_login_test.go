package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDevDemoAutoLoginRunsOncePerProcess(t *testing.T) {
	server := &Server{
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		auth:            testAuthenticator{},
		securityEnabled: true,
		preAuthTokens:   newPreAuthTokenStore(),
		sessionCookie:   "sable_session_demo",
		demoLogin:       devDemoAutoLoginState{username: "art.vandelay", password: "LatexImporter2026!"},
	}
	server.demoLogin.available.Store(true)

	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:5381/login?return_to=%2Fcluster", nil)
	request.RemoteAddr = "127.0.0.1:5381"
	response := httptest.NewRecorder()
	server.loginPage(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/cluster" {
		t.Fatalf("auto-login response = %d with location %q, want 303 /cluster", response.Code, response.Header().Get("Location"))
	}
	if cookie := namedCookie(response, server.sessionCookieName()); cookie == nil || cookie.Value != "session-token" {
		t.Fatalf("auto-login session cookie = %+v, want demo session", cookie)
	}

	second := httptest.NewRecorder()
	server.loginPage(second, request)
	if second.Code != http.StatusOK || !strings.Contains(second.Body.String(), "Sign in to your Sable DNS server") {
		t.Fatalf("second login page = %d %s, want the normal login page", second.Code, second.Body.String())
	}
}

func TestDevDemoAutoLoginRequiresLoopback(t *testing.T) {
	server := &Server{
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		auth:            testAuthenticator{},
		securityEnabled: true,
		preAuthTokens:   newPreAuthTokenStore(),
		demoLogin:       devDemoAutoLoginState{username: "art.vandelay", password: "LatexImporter2026!"},
	}
	server.demoLogin.available.Store(true)

	request := httptest.NewRequest(http.MethodGet, "http://demo.example.test/login", nil)
	request.RemoteAddr = "192.0.2.10:5381"
	response := httptest.NewRecorder()
	server.loginPage(response, request)

	if response.Code != http.StatusOK || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("non-loopback login response = %d with cookie %q, want normal login page without session", response.Code, response.Header().Get("Set-Cookie"))
	}
}
