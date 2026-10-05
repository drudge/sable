package web

import (
	"encoding/json"
	"net/http"

	"github.com/a-h/templ"
)

// render writes component as the response. A failed render is logged unless
// the client has already gone away. It reports whether the render succeeded,
// so a handler that writes more than one component can stop early.
func (server *Server) render(writer http.ResponseWriter, request *http.Request, component templ.Component) bool {
	err := component.Render(request.Context(), writer)
	if err == nil {
		return true
	}
	if request.Context().Err() == nil {
		server.logger.Error("render response", "path", request.URL.Path, "error", err)
	}
	return false
}

// apiError writes the JSON error body every API endpoint uses:
// {"error": message}. The caller sees the message, so a validation error may
// pass through, but a server-side failure is logged and answered with a plain
// message rather than its internal error text.
func apiError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}

// decodeJSON decodes the request body into value and rejects fields value
// does not declare, so a mistyped field fails instead of being ignored. The
// route's bodyLimit already caps the body.
func decodeJSON(request *http.Request, value any) error {
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}
