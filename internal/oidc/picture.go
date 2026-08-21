package oidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"io"
	"net/http"

	// Registering the decoders is what lets DecodeConfig recognise the three
	// formats below. Nothing here decodes a whole image: the header is enough
	// to prove the bytes really are the picture the Content-Type advertises.
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
)

// pictureLimit caps a downloaded profile picture. Providers serve avatars of a
// few tens of kilobytes; a quarter megabyte leaves room for an unscaled photo
// while keeping a hostile or misconfigured provider from filling the database
// one sign-in at a time.
const pictureLimit = 256 << 10

// pictureDimensionLimit rejects an image whose header claims a size no avatar
// needs. The console renders it at 32 pixels, and refusing the absurd cases
// costs nothing because only the header is read to find out.
const pictureDimensionLimit = 4096

// ErrNoPicture reports that the provider offered no image to download.
var ErrNoPicture = errors.New("no profile picture is available")

// Picture is a profile image downloaded from the identity provider, ready to
// be stored and served back by the console.
type Picture struct {
	// SourceURL is where the image came from, kept so a later sign-in can tell
	// a changed picture from an unchanged one.
	SourceURL   string
	ContentType string
	Data        []byte
	// ETag identifies these exact bytes. It is derived from the content rather
	// than taken from the provider's own header, so it stays meaningful across
	// a provider that does not send one and across a move to a new URL.
	ETag string
}

// pictureTypes maps what a decoder recognises onto the type the console will
// serve the bytes back as. Anything outside this set is refused rather than
// stored: an SVG or an HTML error page served from Sable's own origin would be
// script running inside the console's own security policy.
var pictureTypes = map[string]string{
	"png":  "image/png",
	"jpeg": "image/jpeg",
	"gif":  "image/gif",
}

// FetchPicture downloads the image a verified identity pointed at.
//
// The URL comes from the identity provider, which the operator configured and
// Sable already trusts to assert who somebody is, so it is fetched as given
// rather than pinned to the issuer's own host: Google, Entra, and Gravatar all
// serve avatars from a different hostname than they sign tokens with. What is
// not trusted is the response. It is read under a byte cap, the bytes must
// decode as one of three raster formats, and the stored content type comes
// from what the decoder recognised rather than from the provider's header.
//
// A failure is never fatal to a sign-in. The caller logs it and carries on
// with the initials the console has always shown.
func (provider *Provider) FetchPicture(ctx context.Context, pictureURL string) (Picture, error) {
	if pictureURL == "" {
		return Picture{}, ErrNoPicture
	}
	if err := requireSecureURL(pictureURL); err != nil {
		return Picture{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pictureURL, nil)
	if err != nil {
		return Picture{}, err
	}
	request.Header.Set("Accept", "image/png, image/jpeg, image/gif")
	request.Header.Set("User-Agent", provider.fetcher.agent)
	response, err := provider.fetcher.client.Do(request)
	if err != nil {
		return Picture{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Picture{}, fmt.Errorf("provider answered %s for the profile picture", response.Status)
	}
	// One byte past the cap is read on purpose: reading exactly the cap cannot
	// tell a picture that just fits from one that was truncated.
	data, err := io.ReadAll(io.LimitReader(response.Body, pictureLimit+1))
	if err != nil {
		return Picture{}, err
	}
	if len(data) > pictureLimit {
		return Picture{}, fmt.Errorf("profile picture is larger than %d bytes", pictureLimit)
	}
	if len(data) == 0 {
		return Picture{}, ErrNoPicture
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return Picture{}, fmt.Errorf("profile picture is not a PNG, JPEG, or GIF: %w", err)
	}
	contentType, supported := pictureTypes[format]
	if !supported {
		return Picture{}, fmt.Errorf("profile picture format %q is not supported", format)
	}
	if config.Width <= 0 || config.Height <= 0 ||
		config.Width > pictureDimensionLimit || config.Height > pictureDimensionLimit {
		return Picture{}, fmt.Errorf("profile picture is %dx%d, which is outside the allowed range", config.Width, config.Height)
	}
	digest := sha256.Sum256(data)
	return Picture{
		SourceURL:   pictureURL,
		ContentType: contentType,
		Data:        data,
		// The quotes are what makes this a valid entity tag in the header the
		// console later serves it with.
		ETag: `"` + hex.EncodeToString(digest[:]) + `"`,
	}, nil
}
