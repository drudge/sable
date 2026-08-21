package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/drudge/sable/internal/auth"
)

// avatarPath serves the signed-in operator their own profile picture. It is a
// separate request rather than a data URI in the page because the image is
// stable while the pages around it are not: one cached copy serves every
// render, and the console's HTML stays small.
const avatarPath = "/ui/avatar"

// avatarMaxAge is how long a browser may keep an avatar without asking again.
// The URL carries the image's tag, so a changed picture arrives under a new
// URL and a long life costs nothing in staleness.
const avatarMaxAge = 86400

// avatarURL builds the address a page points at for a stored picture, or an
// empty string when the account has none and the initial is drawn instead.
func avatarURL(etag string) string {
	if etag == "" {
		return ""
	}
	// The tag is a quoted hex digest, and the quotes have no business in a
	// URL. Trimming them keeps the query readable and the value unambiguous.
	return avatarPath + "?v=" + url.QueryEscape(strings.Trim(etag, `"`))
}

// ownAvatar answers with the picture stored for the requesting session.
func (server *Server) ownAvatar(writer http.ResponseWriter, request *http.Request) {
	if server.auth == nil {
		http.NotFound(writer, request)
		return
	}
	principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	avatar, err := server.auth.Avatar(request.Context(), principal)
	if err != nil {
		if !errors.Is(err, auth.ErrNotFound) {
			server.logger.Warn("read profile picture", "client", requestClientIP(request), "error", err)
		}
		http.NotFound(writer, request)
		return
	}
	// A picture is personal data on a shared address, so only the browser that
	// asked may keep it. Without private, a proxy in front of the console
	// could hand one operator's face to the next one.
	writer.Header().Set("Cache-Control", "private, max-age="+strconv.Itoa(avatarMaxAge))
	writer.Header().Set("ETag", avatar.ETag)
	if match := request.Header.Get("If-None-Match"); match != "" && match == avatar.ETag {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	writer.Header().Set("Content-Type", avatar.ContentType)
	writer.Header().Set("Content-Length", strconv.Itoa(len(avatar.Data)))
	if _, err := writer.Write(avatar.Data); err != nil {
		server.logger.Warn("send profile picture", "error", err)
	}
}
