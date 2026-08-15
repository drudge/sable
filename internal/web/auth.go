package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/web/pages"
)

const (
	legacySessionCookieName = "sable_session"
	sessionCookiePrefix     = "sable_session_"
	authFormLimit           = 32 << 10
)

type principalContextKey struct{}

func (server *Server) accessControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !server.securityEnabled {
			next.ServeHTTP(writer, request)
			return
		}
		if publicRequest(request.URL.Path) {
			next.ServeHTTP(writer, request)
			return
		}
		if server.setupRequired.Load() {
			server.authenticationFailure(writer, request, http.StatusServiceUnavailable, "/setup")
			return
		}

		principal, err := server.authenticateRequest(request)
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, auth.ErrForbidden) {
				status = http.StatusForbidden
			} else if !errors.Is(err, auth.ErrUnauthorized) {
				server.logger.Error("authenticate console request", "error", err)
				status = http.StatusInternalServerError
			}
			server.authenticationFailure(writer, request, status, "/login")
			return
		}
		if permission := requiredPermission(request); permission != "" && !auth.HasPermission(principal, permission) {
			server.authenticationFailure(writer, request, http.StatusForbidden, "")
			return
		}
		if !safeMethod(request.Method) && !server.auth.ValidateCSRF(principal, request.Header.Get("X-CSRF-Token")) {
			server.authenticationFailure(writer, request, http.StatusForbidden, "")
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(writer, request.WithContext(context.WithValue(
			request.Context(), principalContextKey{}, principal,
		)))
	})
}

func requiredPermission(request *http.Request) string {
	path := request.URL.Path
	write := !safeMethod(request.Method)
	switch {
	case path == "/settings" || path == "/cache" || path == "/integrations" ||
		strings.HasPrefix(path, "/ui/settings") || strings.HasPrefix(path, "/ui/integrations/") ||
		strings.HasPrefix(path, "/ui/certificates/") ||
		strings.HasPrefix(path, "/ui/cache/") || strings.HasPrefix(path, "/api/v1/config/") ||
		strings.HasPrefix(path, "/api/v1/cache/"):
		if write {
			return auth.PermissionSettingsWrite
		}
		return auth.PermissionSettingsRead
	case path == "/administration" || strings.HasPrefix(path, "/ui/administration"):
		if write {
			return auth.PermissionUsersWrite
		}
		return auth.PermissionUsersRead
	case path == "/cluster" || strings.HasPrefix(path, "/ui/cluster/") || strings.HasPrefix(path, "/api/v1/cluster"):
		if write {
			return auth.PermissionClusterWrite
		}
		return auth.PermissionClusterRead
	case path == "/zones" || strings.HasPrefix(path, "/zones/") || strings.HasPrefix(path, "/ui/zones") || strings.HasPrefix(path, "/api/v1/zones"):
		if write {
			// Zone mutations authorize their exact action and immutable zone ID
			// after parsing the form. A broad middleware check would reject
			// legitimate delete-only or DNSSEC-only groups.
			return ""
		}
		if path == "/api/v1/zones/export" || path == "/api/v1/zones/ds" {
			return auth.PermissionZonesExport
		}
		return auth.PermissionZonesRead
	case path == "/blocked" || strings.HasPrefix(path, "/ui/blocking") ||
		strings.HasPrefix(path, "/api/v1/blocking") || path == "/api/v1/policy":
		if write {
			return auth.PermissionBlockingWrite
		}
		return auth.PermissionBlockingRead
	case path == "/logs" || strings.HasPrefix(path, "/ui/query-log") ||
		strings.HasPrefix(path, "/ui/logs/") || strings.HasPrefix(path, "/api/v1/query-log") ||
		strings.HasPrefix(path, "/api/v1/logs/"):
		return auth.PermissionLogsRead
	case path == "/metrics":
		return auth.PermissionMetricsRead
	case path == "/ui/updates" || path == "/ui/updates/check":
		// Checking reaches out to GitHub but changes nothing locally.
		return auth.PermissionUpdatesRead
	case strings.HasPrefix(path, "/ui/updates/"):
		// Installing replaces the running executable, so it is a separate
		// permission from reading the available release.
		return auth.PermissionUpdatesApply
	default:
		return ""
	}
}

func (server *Server) authenticateRequest(request *http.Request) (auth.Principal, error) {
	if bearer, found := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer "); found && tokenRequest(request.URL.Path) {
		return server.auth.AuthenticateToken(request.Context(), strings.TrimSpace(bearer))
	}
	cookie, err := request.Cookie(server.sessionCookieName())
	if err != nil {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	return server.auth.AuthenticateSession(request.Context(), cookie.Value)
}

func (server *Server) setupPage(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if !server.securityEnabled || !server.setupRequired.Load() {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	server.renderAuthPage(writer, request, true, "", http.StatusOK)
}

func (server *Server) setup(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if !server.securityEnabled || !server.setupRequired.Load() {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, authFormLimit)
	if err := request.ParseForm(); err != nil {
		server.renderAuthPage(writer, request, true, "Invalid setup form.", http.StatusBadRequest)
		return
	}
	if !server.preAuthTokens.consume(request.FormValue("csrf_token")) {
		server.logger.Warn("rejected setup form with missing or expired token", "client", requestClientIP(request))
		server.renderAuthPage(
			writer, request, true,
			"This setup form expired after Sable restarted. Enter the details again to continue.",
			http.StatusForbidden,
		)
		return
	}
	if !server.requestOriginAllowed(request) {
		server.logger.Warn(
			"rejected cross-origin setup form",
			"client", requestClientIP(request),
			"host", request.Host,
			"origin", requestOrigin(request),
			"fetch_site", request.Header.Get("Sec-Fetch-Site"),
		)
		server.renderAuthPage(
			writer, request, true,
			"The setup page origin does not match this Sable address. Reload this address and try again.",
			http.StatusForbidden,
		)
		return
	}
	if request.FormValue("password") != request.FormValue("confirm_password") {
		server.renderAuthPage(writer, request, true, "Passwords do not match.", http.StatusUnprocessableEntity)
		return
	}
	credentials, err := server.auth.Setup(
		request.Context(), request.FormValue("username"), request.FormValue("password"),
		requestClientIP(request), request.UserAgent(),
	)
	if err != nil {
		server.renderAuthPage(writer, request, true, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	server.setupRequired.Store(false)
	setSessionCookie(writer, request, server.sessionCookieName(), credentials, server.secureCookies)
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

func (server *Server) loginPage(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if !server.securityEnabled {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	if server.setupRequired.Load() {
		http.Redirect(writer, request, "/setup", http.StatusSeeOther)
		return
	}
	server.renderAuthPage(writer, request, false, "", http.StatusOK)
}

func (server *Server) login(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if !server.securityEnabled {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	if server.setupRequired.Load() {
		http.Redirect(writer, request, "/setup", http.StatusSeeOther)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, authFormLimit)
	if err := request.ParseForm(); err != nil {
		server.renderAuthPage(writer, request, false, "Invalid login form.", http.StatusBadRequest)
		return
	}
	if !server.preAuthTokens.consume(request.FormValue("csrf_token")) {
		server.logger.Warn("rejected login form with missing or expired token", "client", requestClientIP(request))
		server.renderAuthPage(
			writer, request, false,
			"This sign-in form expired after Sable restarted. Enter your credentials again to continue.",
			http.StatusForbidden,
		)
		return
	}
	if !server.requestOriginAllowed(request) {
		server.logger.Warn(
			"rejected cross-origin login form",
			"client", requestClientIP(request),
			"host", request.Host,
			"origin", requestOrigin(request),
			"fetch_site", request.Header.Get("Sec-Fetch-Site"),
		)
		server.renderAuthPage(
			writer, request, false,
			"The sign-in page origin does not match this Sable address. Reload this address and try again.",
			http.StatusForbidden,
		)
		return
	}
	credentials, err := server.auth.Login(
		request.Context(), request.FormValue("username"), request.FormValue("password"),
		requestClientIP(request), request.UserAgent(),
	)
	if err != nil {
		status := http.StatusUnprocessableEntity
		message := "Invalid username or password."
		if errors.Is(err, auth.ErrRateLimited) {
			status = http.StatusTooManyRequests
			message = err.Error()
		}
		server.renderAuthPage(writer, request, false, message, status)
		return
	}
	setSessionCookie(writer, request, server.sessionCookieName(), credentials, server.secureCookies)
	http.Redirect(writer, request, validatedReturnTarget(request.FormValue("return_to"), request.Host), http.StatusSeeOther)
}

func (server *Server) logout(writer http.ResponseWriter, request *http.Request) {
	if !server.securityEnabled {
		http.NotFound(writer, request)
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	if err := server.auth.Logout(
		request.Context(), principal, requestClientIP(request), request.UserAgent(),
	); err != nil {
		http.Error(writer, "logout failed", http.StatusInternalServerError)
		return
	}
	clearSessionCookie(writer, request, server.sessionCookieName(), server.secureCookies)
	writer.Header().Set("HX-Redirect", "/login")
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) createAPIToken(writer http.ResponseWriter, request *http.Request) {
	if !server.securityEnabled {
		http.NotFound(writer, request)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, authFormLimit)
	if err := request.ParseForm(); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		_ = pages.APITokenResult("", "", "Invalid token form.").Render(request.Context(), writer)
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	ownerID := principal.UserID
	if value := request.FormValue("user_id"); value != "" {
		parsed, err := formID(value)
		if err != nil {
			writer.WriteHeader(http.StatusUnprocessableEntity)
			_ = pages.APITokenResult("", "", err.Error()).Render(request.Context(), writer)
			return
		}
		ownerID = parsed
	}
	expiration, err := apiTokenExpiration(request.FormValue("expiration"))
	if err != nil {
		writer.WriteHeader(http.StatusUnprocessableEntity)
		_ = pages.APITokenResult("", "", err.Error()).Render(request.Context(), writer)
		return
	}
	token, expires, err := server.auth.CreateAPIToken(
		request.Context(), principal, ownerID, request.FormValue("name"), request.Form["groups"],
		expiration,
		requestClientIP(request), request.UserAgent(),
	)
	if err != nil {
		writer.WriteHeader(http.StatusUnprocessableEntity)
		_ = pages.APITokenResult("", "", err.Error()).Render(request.Context(), writer)
		return
	}
	writer.Header().Set("HX-Trigger", "apiTokensChanged")
	expiresLabel := ""
	if !expires.IsZero() {
		expiresLabel = pages.FormatDateTime(expires, requestTimeDisplay(request))
	}
	_ = pages.APITokenResult(token, expiresLabel, "").Render(request.Context(), writer)
}

func apiTokenExpiration(value string) (auth.APITokenExpiration, error) {
	value = strings.TrimSpace(value)
	switch value {
	case "", "default":
		return auth.APITokenExpiration{}, nil
	case "never":
		return auth.APITokenExpiration{Never: true}, nil
	default:
		lifetime, err := time.ParseDuration(value)
		if err != nil || lifetime <= 0 {
			return auth.APITokenExpiration{}, errors.New("token expiration is invalid")
		}
		return auth.APITokenExpiration{Lifetime: lifetime}, nil
	}
}

func scopedSessionCookieName(scope string) string {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return legacySessionCookieName
	}
	digest := sha256.Sum256([]byte(scope))
	return sessionCookiePrefix + hex.EncodeToString(digest[:8])
}

func (server *Server) sessionCookieName() string {
	if strings.TrimSpace(server.sessionCookie) == "" {
		return legacySessionCookieName
	}
	return server.sessionCookie
}

func setSessionCookie(
	writer http.ResponseWriter,
	request *http.Request,
	name string,
	credentials auth.Credentials,
	forceSecure bool,
) {
	http.SetCookie(writer, &http.Cookie{
		Name: name, Value: credentials.SessionToken, Path: "/",
		Expires: credentials.Expires, MaxAge: int(time.Until(credentials.Expires).Seconds()),
		HttpOnly: true, Secure: forceSecure || request.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(writer http.ResponseWriter, request *http.Request, name string, forceSecure bool) {
	http.SetCookie(writer, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: forceSecure || request.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}

func publicRequest(path string) bool {
	return path == "/setup" || path == "/login" || path == "/api/v1/health" || path == "/api/v1/cluster/enroll" || path == "/api/v1/cluster/sync" || strings.HasPrefix(path, "/assets/")
}

func tokenRequest(path string) bool {
	return path == "/metrics" || strings.HasPrefix(path, "/api/")
}

func safeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func (server *Server) authenticationFailure(writer http.ResponseWriter, request *http.Request, status int, redirect string) {
	if tokenRequest(request.URL.Path) {
		writeJSON(writer, status, map[string]string{"error": http.StatusText(status)})
		return
	}
	if redirect != "" {
		if redirect == "/login" {
			clearSessionCookie(writer, request, server.sessionCookieName(), server.secureCookies)
			redirect = loginLocation(request)
			if request.Header.Get("HX-Request") == "true" {
				writer.Header().Set("HX-Redirect", redirect)
				writer.WriteHeader(http.StatusNoContent)
				return
			}
		}
		http.Redirect(writer, request, redirect, http.StatusSeeOther)
		return
	}
	http.Error(writer, http.StatusText(status), status)
}

func loginLocation(request *http.Request) string {
	returnTo := requestedConsolePage(request)
	if returnTo == "/" {
		return "/login"
	}
	return "/login?" + url.Values{"return_to": {returnTo}}.Encode()
}

func requestedConsolePage(request *http.Request) string {
	if request.Header.Get("HX-Request") == "true" {
		if target := validatedReturnTarget(request.Header.Get("HX-Current-URL"), request.Host); target != "/" {
			return target
		}
	}
	if safeMethod(request.Method) {
		return validatedReturnTarget(request.URL.RequestURI(), request.Host)
	}
	return validatedReturnTarget(request.Header.Get("Referer"), request.Host)
}

func validatedReturnTarget(rawTarget, requestHost string) string {
	rawTarget = strings.TrimSpace(rawTarget)
	if rawTarget == "" || strings.HasPrefix(rawTarget, "//") {
		return "/"
	}
	target, err := url.Parse(rawTarget)
	if err != nil || target.User != nil {
		return "/"
	}
	if target.IsAbs() {
		if target.Scheme != "http" && target.Scheme != "https" {
			return "/"
		}
		if !strings.EqualFold(target.Host, requestHost) {
			return "/"
		}
	}
	if !strings.HasPrefix(target.Path, "/") || strings.HasPrefix(target.Path, "//") {
		return "/"
	}
	if target.Path == "/login" || target.Path == "/setup" || target.Path == "/logout" ||
		tokenRequest(target.Path) || strings.HasPrefix(target.Path, "/ui/") || strings.HasPrefix(target.Path, "/assets/") {
		return "/"
	}
	target.Scheme = ""
	target.Host = ""
	target.User = nil
	target.Fragment = ""
	return target.RequestURI()
}

func requestClientIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return request.RemoteAddr
	}
	return host
}

func (server *Server) renderAuthPage(
	writer http.ResponseWriter,
	request *http.Request,
	setup bool,
	errorMessage string,
	status int,
) {
	token, err := server.preAuthTokens.issue()
	if err != nil {
		server.logger.Error("issue authentication form token", "error", err)
		http.Error(writer, "authentication form unavailable", http.StatusInternalServerError)
		return
	}
	if status != http.StatusOK {
		writer.WriteHeader(status)
	}
	returnTo := "/"
	if !setup {
		rawReturnTo := request.URL.Query().Get("return_to")
		if request.PostForm != nil && request.PostForm.Has("return_to") {
			rawReturnTo = request.PostForm.Get("return_to")
		}
		returnTo = validatedReturnTarget(rawReturnTo, request.Host)
	}
	if err := pages.AuthPage(setup, errorMessage, token, returnTo).Render(request.Context(), writer); err != nil {
		server.logger.Error("render authentication page", "error", err)
	}
}

func (server *Server) requestOriginAllowed(request *http.Request) bool {
	return server.crossOrigin.Check(request) == nil
}

func requestOrigin(request *http.Request) string {
	if origin := request.Header.Get("Origin"); origin != "" {
		return origin
	}
	return request.Header.Get("Referer")
}
