package web

import (
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode"
)

// contentSecurityPolicy builds the console's policy.
//
// formActionOrigins names origins a form submission is allowed to end up at
// besides this server. It is empty everywhere except the sign-in page: that
// page posts to a handler which redirects to the identity provider, and
// browsers apply form-action across the redirect, so the provider has to be
// named or the redirect is dropped and single sign-on cannot start.
func contentSecurityPolicy(formActionOrigins []string) string {
	return buildContentSecurityPolicy(formActionOrigins, devScriptHashes())
}

func buildContentSecurityPolicy(formActionOrigins, scriptHashes []string) string {
	formAction := "form-action 'self'"
	for _, origin := range formActionOrigins {
		formAction += " " + origin
	}
	script := "script-src 'self'"
	for _, hash := range scriptHashes {
		script += " '" + hash + "'"
	}
	return strings.Join([]string{
		"default-src 'self'",
		"base-uri 'none'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		formAction,
		"style-src 'self'",
		script,
		"connect-src 'self'",
		"img-src 'self' data:",
	}, "; ")
}

// devScriptHashesEnv names inline scripts a development tool adds to each
// page, by their hashes. `go tool mage dev` and `devDemo` set it to the hash of
// Air's live reload script, so Air can reload the page after a rebuild. Nothing
// else sets it, so a server in production allows no inline script at all.
const devScriptHashesEnv = "SABLE_DEV_SCRIPT_HASHES"

var devScriptHashes = sync.OnceValue(func() []string { return scriptHashSources(os.Getenv(devScriptHashesEnv)) })

var scriptHashPattern = regexp.MustCompile(`^sha256-[A-Za-z0-9+/]{43}=$`)

// scriptHashSources reads SHA-256 script hashes separated by spaces or commas.
// Anything else is dropped, so the value can never widen the policy beyond
// the exact scripts it names.
func scriptHashSources(value string) []string {
	var hashes []string
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		if scriptHashPattern.MatchString(field) && !slices.Contains(hashes, field) {
			hashes = append(hashes, field)
		}
	}
	return hashes
}

func secureHeaders(next http.Handler, forceHTTPS bool) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", contentSecurityPolicy(nil))
		writer.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		if forceHTTPS || request.TLS != nil {
			writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(writer, request)
	})
}
