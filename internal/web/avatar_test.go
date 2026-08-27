package web

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/web/pages"
)

// avatarAuthenticator serves one stored picture, or none.
type avatarAuthenticator struct {
	testAuthenticator
	avatar auth.Avatar
	stored bool
}

func (authenticator avatarAuthenticator) Avatar(context.Context, auth.Principal) (auth.Avatar, error) {
	if !authenticator.stored {
		return auth.Avatar{}, auth.ErrNotFound
	}
	return authenticator.avatar, nil
}

func avatarTestServer(t *testing.T, authenticator Authenticator) *Server {
	t.Helper()
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		testConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}},
		testZones{}, "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, authenticator, true, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

// serveAvatar drives the handler directly with a principal attached, which is
// what the authentication middleware would have done.
func serveAvatar(server *Server, principal auth.Principal, ifNoneMatch string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, avatarPath, nil)
	if ifNoneMatch != "" {
		request.Header.Set("If-None-Match", ifNoneMatch)
	}
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal))
	response := httptest.NewRecorder()
	server.ownAvatar(response, request)
	return response
}

func TestOwnAvatarServesTheStoredImage(t *testing.T) {
	t.Parallel()
	image := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	server := avatarTestServer(t, avatarAuthenticator{
		avatar: auth.Avatar{ContentType: "image/png", Data: image, ETag: `"abc"`}, stored: true,
	})

	response := serveAvatar(server, auth.Principal{UserID: 1, Username: "nick"}, "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if !bytes.Equal(response.Body.Bytes(), image) {
		t.Error("the served bytes are not the stored image")
	}
	if got := response.Header().Get("Content-Type"); got != "image/png" {
		t.Errorf("content type = %q, want image/png", got)
	}
	if got := response.Header().Get("ETag"); got != `"abc"` {
		t.Errorf("etag = %q, want the stored tag", got)
	}
	// A picture is personal data behind one shared address, so a shared cache
	// must never keep it.
	if got := response.Header().Get("Cache-Control"); !strings.HasPrefix(got, "private") {
		t.Errorf("cache-control = %q, want a private cache", got)
	}
}

func TestOwnAvatarAnswersNotModifiedForAPictureTheBrowserHas(t *testing.T) {
	t.Parallel()
	server := avatarTestServer(t, avatarAuthenticator{
		avatar: auth.Avatar{ContentType: "image/png", Data: []byte{0x89, 'P'}, ETag: `"abc"`}, stored: true,
	})

	response := serveAvatar(server, auth.Principal{UserID: 1}, `"abc"`)
	if response.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", response.Code)
	}
	if response.Body.Len() != 0 {
		t.Error("a 304 carried a body")
	}
}

func TestOwnAvatarIsNotFoundWithoutAStoredPicture(t *testing.T) {
	t.Parallel()
	server := avatarTestServer(t, avatarAuthenticator{})

	if response := serveAvatar(server, auth.Principal{UserID: 1}, ""); response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
}

// Without a session there is nobody to serve a picture to, and the handler
// must not fall back to anyone else's.
func TestOwnAvatarIsNotFoundWithoutAPrincipal(t *testing.T) {
	t.Parallel()
	server := avatarTestServer(t, avatarAuthenticator{
		avatar: auth.Avatar{ContentType: "image/png", Data: []byte{0x89}, ETag: `"abc"`}, stored: true,
	})

	request := httptest.NewRequest(http.MethodGet, avatarPath, nil)
	response := httptest.NewRecorder()
	server.ownAvatar(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
}

func TestAvatarURLCarriesTheTagAndIsEmptyWithoutOne(t *testing.T) {
	t.Parallel()
	if got := avatarURL(""); got != "" {
		t.Errorf("avatarURL(\"\") = %q, want an empty string", got)
	}
	got := avatarURL(`"abc123"`)
	if !strings.HasPrefix(got, avatarPath+"?v=") || strings.Contains(got, `"`) {
		t.Errorf("avatarURL = %q, want %s with an unquoted tag", got, avatarPath)
	}
}

// The sidebar falls back to an initial rather than a broken image when nothing
// has been synced from the provider.
func TestAccountAvatarFallsBackToTheInitial(t *testing.T) {
	t.Parallel()
	withPicture := renderAccountAvatar(t, pages.DashboardView{Username: "nick", AvatarURL: "/ui/avatar?v=abc"})
	if !strings.Contains(withPicture, `<img`) || !strings.Contains(withPicture, "/ui/avatar?v=abc") {
		t.Errorf("rendered avatar = %q, want an image element", withPicture)
	}
	withoutPicture := renderAccountAvatar(t, pages.DashboardView{Username: "nick"})
	// The initial is uppercased by the stylesheet, not by the template.
	if strings.Contains(withoutPicture, "<img") || !strings.Contains(withoutPicture, ">n<") {
		t.Errorf("rendered avatar = %q, want the account initial", withoutPicture)
	}
}

func renderAccountAvatar(t *testing.T, view pages.DashboardView) string {
	t.Helper()
	var rendered strings.Builder
	if err := pages.AccountAvatar(view).Render(context.Background(), &rendered); err != nil {
		t.Fatalf("render avatar: %v", err)
	}
	return rendered.String()
}
