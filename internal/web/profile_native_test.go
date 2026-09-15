package web

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/web/pages"
)

type profileUpdateAuthenticator struct {
	testAuthenticator
	updateErr error
	updated   []string
	mu        sync.Mutex
}

func (authentication *profileUpdateAuthenticator) UpdateOwnProfile(_ context.Context, _ auth.Principal, displayName, email, clientIP, userAgent string) error {
	authentication.mu.Lock()
	defer authentication.mu.Unlock()
	authentication.updated = []string{displayName, email, clientIP, userAgent}
	return authentication.updateErr
}

func (authentication *profileUpdateAuthenticator) Profile(ctx context.Context, principal auth.Principal) (auth.ProfileSnapshot, error) {
	snapshot, err := authentication.testAuthenticator.Profile(ctx, principal)
	if err != nil {
		return snapshot, err
	}
	authentication.mu.Lock()
	defer authentication.mu.Unlock()
	if authentication.updateErr == nil && len(authentication.updated) >= 2 {
		snapshot.User.DisplayName = authentication.updated[0]
		snapshot.User.Email = authentication.updated[1]
	}
	return snapshot, nil
}

func newNativeProfileTestServer(t *testing.T, authentication Authenticator) *Server {
	t.Helper()
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		testConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}},
		testZones{}, "sqlite", testQueryLog{}, testQueryLog{}, func(context.Context) error { return nil },
		authentication, true, false, false,
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return server
}

func nativeProfilePost(server *Server, target string, form url.Values) *http.Request {
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: "session-token"})
	return request
}

func TestNativeProfileFallbackAcceptsBodyCSRFAndRedirects(t *testing.T) {
	authentication := &profileUpdateAuthenticator{}
	server := newNativeProfileTestServer(t, authentication)
	request := nativeProfilePost(server, "http://example.test/ui/profile", url.Values{
		"csrf_token": {"csrf-token"}, "display_name": {"New Name"}, "email": {"new@example.test"},
	})
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/profile" {
		t.Fatalf("native profile response = %d Location=%q", response.Code, response.Header().Get("Location"))
	}
	if len(authentication.updated) < 2 || authentication.updated[0] != "New Name" || authentication.updated[1] != "new@example.test" {
		t.Fatalf("profile update values = %#v", authentication.updated)
	}
}

func TestProfilePageIncludesNativeProfileFormContract(t *testing.T) {
	var response bytes.Buffer
	err := pages.ProfilePage(pages.ProfilePageView{
		Console:   pages.DashboardView{CSRFToken: "csrf-token"},
		User:      auth.ManagedUser{Username: "admin", DisplayName: "Administrator"},
		ActiveTab: "profile",
	}).Render(context.Background(), &response)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`method="post" action="/ui/profile"`, `name="csrf_token" value="csrf-token"`} {
		if !strings.Contains(response.String(), expected) {
			t.Fatalf("profile page missing %q: %s", expected, response.String())
		}
	}
}

func TestNativeProfileFallbackValidationErrorRendersFullPageAndSubmittedValues(t *testing.T) {
	authentication := &profileUpdateAuthenticator{updateErr: errors.New("email is invalid")}
	server := newNativeProfileTestServer(t, authentication)
	request := nativeProfilePost(server, "http://example.test/ui/profile", url.Values{
		"csrf_token": {"csrf-token"}, "display_name": {"Submitted Name"}, "email": {"bad@example"},
	})
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)

	body := response.Body.String()
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(body, "email is invalid") {
		t.Fatalf("native validation response = %d %s", response.Code, body)
	}
	if !strings.Contains(body, `value="Submitted Name"`) || !strings.Contains(body, `value="bad@example"`) || !strings.Contains(body, "<html") {
		t.Fatalf("native validation response lost full-page form values: %s", body)
	}
}

func TestNativeProfileFallbackRejectsUnsafeBodyVariants(t *testing.T) {
	tests := []struct {
		name    string
		request func(*Server) *http.Request
	}{
		{name: "missing token", request: func(server *Server) *http.Request {
			return nativeProfilePost(server, "http://example.test/ui/profile", url.Values{"display_name": {"Name"}})
		}},
		{name: "invalid token", request: func(server *Server) *http.Request {
			return nativeProfilePost(server, "http://example.test/ui/profile", url.Values{"csrf_token": {"wrong-token"}, "display_name": {"Name"}})
		}},
		{name: "query token", request: func(server *Server) *http.Request {
			return nativeProfilePost(server, "http://example.test/ui/profile?csrf_token=csrf-token", url.Values{"display_name": {"Name"}})
		}},
		{name: "unsupported content type", request: func(server *Server) *http.Request {
			request := nativeProfilePost(server, "http://example.test/ui/profile", url.Values{"csrf_token": {"csrf-token"}})
			request.Header.Set("Content-Type", "application/json")
			return request
		}},
		{name: "cross origin", request: func(server *Server) *http.Request {
			request := nativeProfilePost(server, "http://example.test/ui/profile", url.Values{"csrf_token": {"csrf-token"}})
			request.Header.Set("Origin", "https://attacker.example")
			return request
		}},
		{name: "oversized body", request: func(server *Server) *http.Request {
			request := httptest.NewRequest(http.MethodPost, "http://example.test/ui/profile", strings.NewReader("csrf_token=csrf-token&display_name="+strings.Repeat("a", authFormLimit)))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: "session-token"})
			return request
		}},
		{name: "wrong path", request: func(server *Server) *http.Request {
			return nativeProfilePost(server, "http://example.test/ui/profile/password", url.Values{"csrf_token": {"csrf-token"}})
		}},
		{name: "HTMX body token without header", request: func(server *Server) *http.Request {
			request := nativeProfilePost(server, "http://example.test/ui/profile", url.Values{"csrf_token": {"csrf-token"}})
			request.Header.Set("HX-Request", "true")
			return request
		}},
		{name: "invalid header with body token", request: func(server *Server) *http.Request {
			request := nativeProfilePost(server, "http://example.test/ui/profile", url.Values{"csrf_token": {"csrf-token"}})
			request.Header.Set("X-CSRF-Token", "wrong-token")
			return request
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authentication := &profileUpdateAuthenticator{}
			server := newNativeProfileTestServer(t, authentication)
			response := httptest.NewRecorder()
			server.httpServer.Handler.ServeHTTP(response, test.request(server))
			if response.Code != http.StatusForbidden || len(authentication.updated) != 0 {
				t.Fatalf("unsafe profile request = %d updates=%#v body=%s", response.Code, authentication.updated, response.Body.String())
			}
		})
	}
}

func TestHTMXProfileMutationStillUsesHeaderCSRFAndFragmentResponse(t *testing.T) {
	authentication := &profileUpdateAuthenticator{}
	server := newNativeProfileTestServer(t, authentication)
	request := nativeProfilePost(server, "http://example.test/ui/profile", url.Values{"display_name": {"Name"}})
	request.Header.Set("HX-Request", "true")
	request.Header.Set("X-CSRF-Token", "csrf-token")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("HX-Redirect") != "/profile" {
		t.Fatalf("HTMX profile response = %d HX-Redirect=%q", response.Code, response.Header().Get("HX-Redirect"))
	}
}
