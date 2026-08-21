package oidc

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pngOfSize renders a square PNG, which is the closest a test gets to the real
// thing without carrying a binary fixture around.
func pngOfSize(t *testing.T, side int) []byte {
	t.Helper()
	canvas := image.NewRGBA(image.Rect(0, 0, side, side))
	for x := range side {
		for y := range side {
			canvas.Set(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 0x40, A: 0xff})
		}
	}
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, canvas); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buffer.Bytes()
}

// pictureServer answers one path with whatever a test hands it.
func pictureServer(t *testing.T, status int, contentType string, body []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			writer.Header().Set("Content-Type", contentType)
		}
		writer.WriteHeader(status)
		_, _ = writer.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestFetchPictureStoresTheImageAndATagOverItsBytes(t *testing.T) {
	provider := newFakeProvider(t)
	party := provider.relyingParty(t, nil)
	image := pngOfSize(t, 64)
	images := pictureServer(t, http.StatusOK, "image/png", image)

	picture, err := party.FetchPicture(context.Background(), images.URL+"/avatar.png")
	if err != nil {
		t.Fatalf("fetch picture: %v", err)
	}
	if picture.ContentType != "image/png" {
		t.Errorf("content type = %q, want image/png", picture.ContentType)
	}
	if !bytes.Equal(picture.Data, image) {
		t.Error("stored bytes are not the ones the provider served")
	}
	if !strings.HasPrefix(picture.ETag, `"`) || !strings.HasSuffix(picture.ETag, `"`) {
		t.Errorf("etag = %q, want a quoted entity tag", picture.ETag)
	}

	again, err := party.FetchPicture(context.Background(), images.URL+"/avatar.png")
	if err != nil {
		t.Fatalf("fetch picture again: %v", err)
	}
	if again.ETag != picture.ETag {
		t.Error("the same image produced two different tags")
	}
}

func TestFetchPictureTrustsTheDecoderRatherThanTheContentType(t *testing.T) {
	provider := newFakeProvider(t)
	party := provider.relyingParty(t, nil)
	// A provider claiming SVG while serving PNG is harmless; the point is that
	// the stored type comes from the bytes, because a page served under a type
	// the console did not verify is script running on its own origin.
	images := pictureServer(t, http.StatusOK, "image/svg+xml", pngOfSize(t, 32))

	picture, err := party.FetchPicture(context.Background(), images.URL+"/avatar")
	if err != nil {
		t.Fatalf("fetch picture: %v", err)
	}
	if picture.ContentType != "image/png" {
		t.Errorf("content type = %q, want image/png", picture.ContentType)
	}
}

func TestFetchPictureRefusesWhatIsNotAnImage(t *testing.T) {
	provider := newFakeProvider(t)
	party := provider.relyingParty(t, nil)
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	images := pictureServer(t, http.StatusOK, "image/svg+xml", svg)

	if _, err := party.FetchPicture(context.Background(), images.URL+"/avatar.svg"); err == nil {
		t.Fatal("an SVG was accepted as a profile picture")
	}
}

func TestFetchPictureRefusesAnOversizedImage(t *testing.T) {
	provider := newFakeProvider(t)
	party := provider.relyingParty(t, nil)
	oversized := bytes.Repeat([]byte{0x41}, pictureLimit+1)
	images := pictureServer(t, http.StatusOK, "image/png", oversized)

	_, err := party.FetchPicture(context.Background(), images.URL+"/huge.png")
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("error = %v, want a size refusal", err)
	}
}

func TestFetchPictureReportsAProviderFailureWithoutStoringAnything(t *testing.T) {
	provider := newFakeProvider(t)
	party := provider.relyingParty(t, nil)
	images := pictureServer(t, http.StatusNotFound, "text/plain", []byte("gone"))

	if _, err := party.FetchPicture(context.Background(), images.URL+"/missing.png"); err == nil {
		t.Fatal("a 404 produced a picture")
	}
}

func TestFetchPictureRequiresTLSAwayFromLoopback(t *testing.T) {
	provider := newFakeProvider(t)
	party := provider.relyingParty(t, nil)

	if _, err := party.FetchPicture(context.Background(), "http://avatars.example.com/a.png"); err == nil {
		t.Fatal("a plain HTTP picture host was accepted")
	}
	if _, err := party.FetchPicture(context.Background(), ""); !errors.Is(err, ErrNoPicture) {
		t.Fatalf("error = %v, want ErrNoPicture", err)
	}
}

func TestCompleteReadsThePictureClaim(t *testing.T) {
	provider := newFakeProvider(t)
	provider.claims["picture"] = "https://id.example.com/avatar/nick.png"
	party := provider.relyingParty(t, nil)

	request, err := party.Begin(context.Background(), "")
	if err != nil {
		t.Fatalf("begin sign-in: %v", err)
	}
	provider.claims["nonce"] = request.Nonce

	identity, err := party.Complete(context.Background(), "code-1", request)
	if err != nil {
		t.Fatalf("complete sign-in: %v", err)
	}
	if identity.Picture != "https://id.example.com/avatar/nick.png" {
		t.Errorf("picture = %q, want the claim value", identity.Picture)
	}
}

func TestCompleteReadsThePictureFromUserInfoWhenTheTokenOmitsIt(t *testing.T) {
	provider := newFakeProvider(t)
	delete(provider.claims, "picture")
	provider.userInfo = map[string]any{
		"sub":     "user-1",
		"picture": "https://id.example.com/avatar/from-userinfo.png",
	}
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
	if identity.Picture != "https://id.example.com/avatar/from-userinfo.png" {
		t.Errorf("picture = %q, want the UserInfo value", identity.Picture)
	}
}

func TestPictureClaimNameIsConfigurable(t *testing.T) {
	provider := newFakeProvider(t)
	delete(provider.claims, "picture")
	provider.claims["avatar_url"] = "https://id.example.com/avatar/custom.png"
	party := provider.relyingParty(t, func(config *Config) { config.Claims.Picture = "avatar_url" })

	request, err := party.Begin(context.Background(), "")
	if err != nil {
		t.Fatalf("begin sign-in: %v", err)
	}
	provider.claims["nonce"] = request.Nonce

	identity, err := party.Complete(context.Background(), "code-1", request)
	if err != nil {
		t.Fatalf("complete sign-in: %v", err)
	}
	if identity.Picture != "https://id.example.com/avatar/custom.png" {
		t.Errorf("picture = %q, want the configured claim", identity.Picture)
	}
}
