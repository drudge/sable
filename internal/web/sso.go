package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/oidc"
)

const (
	ssoStateCookieName = "sable_sso_state"
	// ssoStartPath and ssoCallbackPath are reachable without a session, so
	// both are listed in publicRequest.
	ssoStartPath    = "/auth/oidc/start"
	ssoCallbackPath = "/auth/oidc/callback"
)

// ssoController is the single sign-on provider the application wires in. It is
// nil when the deployment has no provider configured, which is what makes the
// sign-in button disappear rather than fail.
type ssoController interface {
	// Enabled reports whether a provider is configured and switched on. It is
	// read on every sign-in page render, so it must not perform network calls.
	Enabled() bool
	Label() string
	// SignInOrigins reports where starting a sign-in sends the browser, so the
	// sign-in page's form-action policy can name the provider. It is read on
	// every sign-in page render, so it must not perform network calls either.
	SignInOrigins() []string
	Begin(context.Context, string) (oidc.Request, error)
	Complete(context.Context, string, oidc.Request, string, string) (auth.Credentials, error)
	LogoutURL(context.Context, string) (string, bool)
}

// SetSSO installs the single sign-on provider. It is separate from New the way
// the other optional controllers are, because a deployment without a provider
// is the ordinary case.
func (server *Server) SetSSO(controller ssoController) {
	server.sso = controller
}

// ssoAvailable reports whether the sign-in page should offer the button.
func (server *Server) ssoAvailable() bool {
	return server.securityEnabled && server.sso != nil && server.sso.Enabled()
}

// ssoFormActionOrigins reports the extra form-action sources the sign-in page
// needs so the redirect out to the identity provider is not dropped by the
// console's Content-Security-Policy. Anything the provider reported that does
// not reduce to a plain origin is discarded rather than written into a header.
func (server *Server) ssoFormActionOrigins() []string {
	if !server.ssoAvailable() {
		return nil
	}
	var origins []string
	for _, candidate := range server.sso.SignInOrigins() {
		origin, ok := oidc.OriginOf(candidate)
		if !ok || slices.Contains(origins, origin) {
			continue
		}
		origins = append(origins, origin)
	}
	return origins
}

// startSSO sends the browser to the identity provider. It is a POST rather
// than a link so the pre-auth token can prove the request came from a sign-in
// page this server rendered, which keeps an attacker from silently starting
// sign-ins from somewhere else.
func (server *Server) startSSO(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if !server.ssoAvailable() {
		http.NotFound(writer, request)
		return
	}
	if server.setupRequired.Load() {
		http.Redirect(writer, request, "/setup", http.StatusSeeOther)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, authFormLimit)
	if err := request.ParseForm(); err != nil {
		server.renderAuthPage(writer, request, false, "Invalid sign-in form.", http.StatusBadRequest)
		return
	}
	if !server.preAuthTokens.consume(request.FormValue("csrf_token")) {
		server.logger.Warn("rejected single sign-on start with missing or expired token", "client", requestClientIP(request))
		server.renderAuthPage(
			writer, request, false,
			"This sign-in form is no longer valid. Reload the page and try again.",
			http.StatusForbidden,
		)
		return
	}
	if !server.requestOriginAllowed(request) {
		server.logger.Warn(
			"rejected cross-origin single sign-on start",
			"client", requestClientIP(request), "host", request.Host, "origin", requestOrigin(request),
		)
		server.renderAuthPage(
			writer, request, false,
			"The sign-in page origin does not match this Sable address. Reload this address and try again.",
			http.StatusForbidden,
		)
		return
	}

	returnTo := validatedReturnTarget(request.FormValue("return_to"), request.Host)
	started, err := server.sso.Begin(request.Context(), returnTo)
	if err != nil {
		server.logger.Error("start single sign-on", "client", requestClientIP(request), "error", err)
		server.renderAuthPage(
			writer, request, false,
			"Sable could not reach the identity provider. Try again, or sign in with a password.",
			http.StatusBadGateway,
		)
		return
	}
	key, err := server.ssoStateStore.issue(started)
	if err != nil {
		server.logger.Error("store single sign-on state", "error", err)
		server.renderAuthPage(writer, request, false, "Sign-in is temporarily unavailable.", http.StatusInternalServerError)
		return
	}
	setSSOStateCookie(writer, request, key, server.secureCookies)
	http.Redirect(writer, request, started.URL, http.StatusSeeOther)
}

// completeSSO handles the provider's redirect back. Everything it is given
// arrives through the browser and is therefore untrusted until the stored
// sign-in state and the provider's own token endpoint agree with it.
func (server *Server) completeSSO(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if !server.ssoAvailable() {
		http.NotFound(writer, request)
		return
	}
	// The state cookie is single use whatever happens next, so a failed
	// attempt cannot be retried against the same stored verifier.
	cookie, cookieErr := request.Cookie(ssoStateCookieName)
	clearSSOStateCookie(writer, request, server.secureCookies)

	query := request.URL.Query()
	if providerError := query.Get("error"); providerError != "" {
		// The provider's description is for the log. Rendering it would put
		// attacker-influenced text on the sign-in page.
		server.logger.Warn(
			"identity provider refused the sign-in",
			"client", requestClientIP(request),
			"error", providerError,
			"description", query.Get("error_description"),
		)
		server.renderAuthPage(writer, request, false, "The identity provider refused the sign-in.", http.StatusUnauthorized)
		return
	}
	if cookieErr != nil {
		server.logger.Warn("single sign-on callback without a state cookie", "client", requestClientIP(request))
		server.renderAuthPage(
			writer, request, false,
			"That sign-in did not start here, or it expired. Try again.",
			http.StatusForbidden,
		)
		return
	}
	started, found := server.ssoStateStore.consume(cookie.Value)
	if !found {
		server.logger.Warn("single sign-on callback with unknown or expired state", "client", requestClientIP(request))
		server.renderAuthPage(
			writer, request, false,
			"That sign-in did not start here, or it expired. Try again.",
			http.StatusForbidden,
		)
		return
	}
	// The state value ties the provider's redirect to the sign-in this browser
	// started. Without the comparison, a callback forged by another site would
	// be redeemed against this browser's stored verifier.
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(started.State)) != 1 {
		server.logger.Warn("single sign-on callback with a mismatched state", "client", requestClientIP(request))
		server.renderAuthPage(writer, request, false, "That sign-in could not be verified. Try again.", http.StatusForbidden)
		return
	}
	code := query.Get("code")
	if code == "" {
		server.renderAuthPage(writer, request, false, "The identity provider returned no authorization code.", http.StatusBadRequest)
		return
	}

	credentials, err := server.sso.Complete(
		request.Context(), code, started, requestClientIP(request), request.UserAgent(),
	)
	if err != nil {
		server.logger.Warn(
			"single sign-on did not complete",
			"client", requestClientIP(request), "error", err,
		)
		server.renderAuthPage(writer, request, false, ssoFailureMessage(err), ssoFailureStatus(err))
		return
	}
	setSessionCookie(writer, request, server.sessionCookieName(), credentials, server.secureCookies)
	http.Redirect(writer, request, validatedReturnTarget(started.ReturnTo, request.Host), http.StatusSeeOther)
}

// ssoFailureMessage turns a completion failure into something an operator can
// act on without telling an anonymous caller anything about who exists here.
func ssoFailureMessage(err error) string {
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		return "Too many sign-in attempts. Try again shortly."
	case errors.Is(err, auth.ErrNoFederatedAccount):
		return "That account is not set up in Sable. Ask an administrator to add it."
	case errors.Is(err, auth.ErrForbidden):
		return "That account is not allowed to sign in to this console."
	case errors.Is(err, oidc.ErrDiscovery), errors.Is(err, oidc.ErrExchange):
		return "Sable could not reach the identity provider. Try again, or sign in with a password."
	default:
		return "Single sign-on failed. Try again, or sign in with a password."
	}
}

func ssoFailureStatus(err error) int {
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		return http.StatusTooManyRequests
	case errors.Is(err, auth.ErrForbidden), errors.Is(err, auth.ErrNoFederatedAccount):
		return http.StatusForbidden
	case errors.Is(err, oidc.ErrDiscovery), errors.Is(err, oidc.ErrExchange):
		return http.StatusBadGateway
	default:
		return http.StatusUnauthorized
	}
}

// setSSOStateCookie stores the lookup key for an in-flight sign-in.
//
// SameSite is Lax rather than the Strict the session cookie uses, and that is
// required rather than a relaxation: the callback is a top-level navigation
// from the provider's own domain, and Strict would withhold the cookie on
// exactly that request, so no sign-in could ever complete.
func setSSOStateCookie(writer http.ResponseWriter, request *http.Request, key string, forceSecure bool) {
	http.SetCookie(writer, &http.Cookie{
		Name: ssoStateCookieName, Value: key, Path: "/",
		MaxAge:   int(ssoStateTTL / time.Second),
		HttpOnly: true, Secure: forceSecure || request.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
}

func clearSSOStateCookie(writer http.ResponseWriter, request *http.Request, forceSecure bool) {
	http.SetCookie(writer, &http.Cookie{
		Name: ssoStateCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: forceSecure || request.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
}
