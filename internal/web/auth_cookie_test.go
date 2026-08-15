package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
)

func TestScopedSessionCookieNameIsStablePerInstance(t *testing.T) {
	t.Parallel()

	primary := scopedSessionCookieName("/srv/sable-primary/data/sable.key")
	replica := scopedSessionCookieName("/srv/sable-replica/data/sable.key")

	if primary != scopedSessionCookieName("/srv/sable-primary/data/sable.key") {
		t.Fatal("cookie name changed for the same instance scope")
	}
	if primary == replica {
		t.Fatal("different instance scopes produced the same cookie name")
	}
	if !strings.HasPrefix(primary, sessionCookiePrefix) {
		t.Fatalf("cookie name %q does not use prefix %q", primary, sessionCookiePrefix)
	}
	if got := scopedSessionCookieName("  "); got != legacySessionCookieName {
		t.Fatalf("empty scope cookie name = %q, want %q", got, legacySessionCookieName)
	}
}

func TestSessionCookieUsesInstanceName(t *testing.T) {
	t.Parallel()

	server := &Server{sessionCookie: scopedSessionCookieName("/srv/sable-primary/data/sable.key")}
	request := httptest.NewRequest("POST", "http://127.0.0.1:5380/login", nil)
	response := httptest.NewRecorder()
	setSessionCookie(response, request, server.sessionCookieName(), auth.Credentials{
		SessionToken: "session-token",
		Expires:      time.Now().Add(time.Hour),
	}, false)

	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookie count = %d, want 1", len(cookies))
	}
	if cookies[0].Name != server.sessionCookie {
		t.Fatalf("cookie name = %q, want %q", cookies[0].Name, server.sessionCookie)
	}
	if cookies[0].Name == legacySessionCookieName {
		t.Fatalf("cookie unexpectedly used shared legacy name %q", legacySessionCookieName)
	}
}
