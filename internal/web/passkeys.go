package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type PasskeyAuthenticator interface {
	EnableOwnPassword(context.Context, auth.Principal, string, string) error
	Passkeys(context.Context, auth.Principal) ([]auth.Passkey, error)
	PasskeyAccount(context.Context, string, string) (auth.PasskeyUser, error)
	DiscoverPasskey(context.Context, []byte, string) (auth.PasskeyUser, auth.Passkey, error)
	AddPasskey(context.Context, auth.Principal, auth.PasskeyUser, string, string, webauthn.Credential, string, string) error
	CompletePasskeyLogin(context.Context, auth.Passkey, webauthn.Credential, string, string) (auth.Credentials, error)
	RemovePasskey(context.Context, auth.Principal, string, string, string) error
	DisableOwnPassword(context.Context, auth.Principal, string, string) error
	AllowPasskeyAttempt(string) error
	RecordPasskeyFailure(context.Context, string, string)
}

func (server *Server) passkeyAuth() PasskeyAuthenticator {
	authentication, _ := server.auth.(PasskeyAuthenticator)
	return authentication
}

const passkeyLoginBegin = "/auth/passkey/login/begin"
const passkeyLoginFinish = "/auth/passkey/login/finish"
const passkeyCeremonyTTL = 5 * time.Minute
const maxPasskeyCeremonies = 2048

type passkeyCeremony struct {
	Session     webauthn.SessionData
	Account     auth.PasskeyUser
	Origin      string
	Name        string
	Purpose     string
	SessionHash string
	Expires     time.Time
}
type passkeyCeremonyStore struct {
	mu      sync.Mutex
	entries map[string]passkeyCeremony
}

func (store *passkeyCeremonyStore) issue(ceremony passkeyCeremony) (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(token)
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.entries == nil {
		store.entries = make(map[string]passkeyCeremony)
	}
	for key, entry := range store.entries {
		if !time.Now().Before(entry.Expires) {
			delete(store.entries, key)
		}
	}
	if len(store.entries) >= maxPasskeyCeremonies {
		return "", auth.ErrRateLimited
	}
	ceremony.Expires = time.Now().Add(passkeyCeremonyTTL)
	store.entries[id] = ceremony
	return id, nil
}
func (store *passkeyCeremonyStore) consume(id string) (passkeyCeremony, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.entries[id]
	delete(store.entries, id)
	return entry, ok && time.Now().Before(entry.Expires)
}

func (server *Server) passkeyRelyingParty(request *http.Request) (*webauthn.WebAuthn, string, error) {
	origin := strings.TrimSuffix(absoluteURL(request, "/"), "/")
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return nil, "", errors.New("invalid Sable address")
	}
	if parsed.Scheme != "https" && parsed.Hostname() != "localhost" {
		return nil, "", errors.New("passkeys require HTTPS or localhost")
	}
	if origins := server.passkeyTrustedOrigins(request.Context()); len(origins) > 0 && !slices.Contains(origins, origin) {
		return nil, "", errors.New("use a configured HTTPS hostname or cluster node address for passkeys")
	}
	rpID, err := defaultPasskeyRPID(parsed.Hostname())
	if err != nil {
		return nil, "", err
	}
	party, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Sable", RPID: rpID, RPOrigins: []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired},
	})
	return party, origin, err
}

func (server *Server) passkeyRequest(writer http.ResponseWriter, request *http.Request) bool {
	writer.Header().Set("Cache-Control", "no-store")
	request.Body = http.MaxBytesReader(writer, request.Body, authFormLimit)
	// A custom header prevents simple cross-site form submissions. Explicit
	// origin matching also protects login ceremonies before a session exists.
	if !server.securityEnabled || server.passkeyAuth() == nil || server.setupRequired.Load() || request.Header.Get("X-Sable-Passkey") != "1" || !server.requestOriginAllowed(request) || request.Header.Get("Origin") != strings.TrimSuffix(absoluteURL(request, "/"), "/") {
		passkeyError(writer, http.StatusForbidden, "Passkey request rejected. Reload this Sable address and try again.")
		return false
	}
	return true
}
func passkeyError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}

func (server *Server) beginPasskeyRegistration(writer http.ResponseWriter, request *http.Request) {
	if !server.requirePasskeysEnabled(writer) {
		return
	}
	if !server.passkeyRequest(writer, request) {
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	party, origin, err := server.passkeyRelyingParty(request)
	if err != nil {
		passkeyError(writer, http.StatusBadRequest, err.Error())
		return
	}
	account, err := server.passkeyAuth().PasskeyAccount(request.Context(), principal.Username, party.Config.RPID)
	if err != nil {
		passkeyError(writer, http.StatusForbidden, "Unable to register a passkey for this account.")
		return
	}
	if len(account.Keys) >= auth.MaximumPasskeys {
		passkeyError(writer, http.StatusBadRequest, "Remove an unused passkey before adding another.")
		return
	}
	name := strings.TrimSpace(request.URL.Query().Get("name"))
	if name == "" || len(name) > 100 {
		passkeyError(writer, http.StatusBadRequest, "Enter a passkey name (up to 100 characters).")
		return
	}
	exclusions := make([]protocol.CredentialDescriptor, 0, len(account.Keys))
	for _, key := range account.Keys {
		exclusions = append(exclusions, key.Descriptor())
	}
	options, session, err := party.BeginRegistration(account, webauthn.WithExclusions(exclusions))
	if err != nil {
		passkeyError(writer, http.StatusInternalServerError, "Unable to start passkey registration.")
		return
	}
	server.issuePasskeyCeremony(writer, request, passkeyCeremony{Session: *session, Account: account, Origin: origin, Name: name, Purpose: "register", SessionHash: principal.SessionHash}, options)
}

func (server *Server) issuePasskeyCeremony(writer http.ResponseWriter, request *http.Request, ceremony passkeyCeremony, options any) {
	id, err := server.passkeyCeremonies.issue(ceremony)
	if err != nil {
		passkeyError(writer, http.StatusTooManyRequests, "Too many passkey requests. Try again later.")
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: server.sessionCookieName() + "_passkey", Value: id, Path: "/", MaxAge: int(passkeyCeremonyTTL.Seconds()), HttpOnly: true, Secure: server.secureCookies || strings.HasPrefix(ceremony.Origin, "https://"), SameSite: http.SameSiteStrictMode})
	writeJSON(writer, http.StatusOK, options)
}

func (server *Server) consumePasskeyCeremony(writer http.ResponseWriter, request *http.Request, purpose string) (passkeyCeremony, *webauthn.WebAuthn, bool) {
	cookie, err := request.Cookie(server.sessionCookieName() + "_passkey")
	if err != nil {
		passkeyError(writer, http.StatusBadRequest, "Passkey request expired. Try again.")
		return passkeyCeremony{}, nil, false
	}
	ceremony, ok := server.passkeyCeremonies.consume(cookie.Value)
	party, origin, err := server.passkeyRelyingParty(request)
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	if !ok || err != nil || ceremony.Origin != origin || ceremony.Purpose != purpose || ceremony.SessionHash != principal.SessionHash {
		passkeyError(writer, http.StatusBadRequest, "Passkey request expired or changed. Try again.")
		return passkeyCeremony{}, nil, false
	}
	return ceremony, party, true
}

func (server *Server) finishPasskeyRegistration(writer http.ResponseWriter, request *http.Request) {
	if !server.requirePasskeysEnabled(writer) {
		return
	}
	if !server.passkeyRequest(writer, request) {
		return
	}
	ceremony, party, ok := server.consumePasskeyCeremony(writer, request, "register")
	if !ok {
		return
	}
	credential, err := party.FinishRegistration(ceremony.Account, ceremony.Session, request)
	if err != nil {
		passkeyError(writer, http.StatusBadRequest, "Passkey registration could not be verified.")
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	err = server.passkeyAuth().AddPasskey(request.Context(), principal, ceremony.Account, party.Config.RPID, ceremony.Name, *credential, requestClientIP(request), request.UserAgent())
	if err != nil {
		passkeyError(writer, http.StatusBadRequest, "Unable to save this passkey. It may already be registered.")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"redirect": "/profile"})
}

func (server *Server) beginPasskeyLogin(writer http.ResponseWriter, request *http.Request) {
	if !server.requirePasskeysEnabled(writer) {
		return
	}
	if !server.passkeyRequest(writer, request) {
		return
	}
	if err := server.passkeyAuth().AllowPasskeyAttempt(requestClientIP(request)); err != nil {
		passkeyError(writer, http.StatusTooManyRequests, err.Error())
		return
	}
	party, origin, err := server.passkeyRelyingParty(request)
	if err != nil {
		passkeyError(writer, http.StatusBadRequest, err.Error())
		return
	}
	options, session, err := party.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		passkeyError(writer, http.StatusInternalServerError, "Unable to start passkey sign-in.")
		return
	}
	server.issuePasskeyCeremony(writer, request, passkeyCeremony{Session: *session, Origin: origin, Purpose: "login"}, options)
}

func (server *Server) finishPasskeyLogin(writer http.ResponseWriter, request *http.Request) {
	if !server.requirePasskeysEnabled(writer) {
		return
	}
	if !server.passkeyRequest(writer, request) {
		return
	}
	ceremony, party, ok := server.consumePasskeyCeremony(writer, request, "login")
	if !ok {
		return
	}
	var key auth.Passkey
	credential, err := party.FinishDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		account, stored, err := server.passkeyAuth().DiscoverPasskey(request.Context(), rawID, party.Config.RPID)
		if err != nil || !bytes.Equal(account.Handle, userHandle) || !server.passkeyCredentialOriginAllowed(request.Context(), stored, ceremony.Origin) {
			return nil, auth.ErrUnauthorized
		}
		key = stored
		return account, nil
	}, ceremony.Session, request)
	if err != nil {
		server.passkeyAuth().RecordPasskeyFailure(request.Context(), requestClientIP(request), request.UserAgent())
		passkeyError(writer, http.StatusUnauthorized, "Unable to sign in with this passkey.")
		return
	}
	credentials, err := server.passkeyAuth().CompletePasskeyLogin(request.Context(), key, *credential, requestClientIP(request), request.UserAgent())
	if err != nil {
		server.passkeyAuth().RecordPasskeyFailure(request.Context(), requestClientIP(request), request.UserAgent())
		passkeyError(writer, http.StatusUnauthorized, "Unable to sign in with this passkey.")
		return
	}
	setSessionCookie(writer, request, server.sessionCookieName(), credentials, server.secureCookies || strings.HasPrefix(ceremony.Origin, "https://"))
	writeJSON(writer, http.StatusOK, map[string]string{"redirect": validatedReturnTarget(request.URL.Query().Get("return_to"), request.Host)})
}

func (server *Server) removeOwnPasskey(writer http.ResponseWriter, request *http.Request) {
	if !server.passkeyRequest(writer, request) {
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	err := server.passkeyAuth().RemovePasskey(request.Context(), principal, request.URL.Query().Get("id"), requestClientIP(request), request.UserAgent())
	if err != nil {
		passkeyError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"redirect": "/profile"})
}

func (server *Server) disableOwnPassword(writer http.ResponseWriter, request *http.Request) {
	if !server.requirePasskeysEnabled(writer) {
		return
	}
	if !server.passkeyRequest(writer, request) {
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	err := server.passkeyAuth().DisableOwnPassword(request.Context(), principal, requestClientIP(request), request.UserAgent())
	if err != nil {
		passkeyError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"redirect": "/profile"})
}

func (server *Server) enableOwnPassword(writer http.ResponseWriter, request *http.Request) {
	if !server.passkeyRequest(writer, request) {
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	err := server.passkeyAuth().EnableOwnPassword(request.Context(), principal, requestClientIP(request), request.UserAgent())
	if err != nil {
		passkeyError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"redirect": "/profile"})
}

func (server *Server) passkeysEnabled() bool {
	return server.config == nil || !server.config.Current().Config.Security.PasskeysDisabled
}

func (server *Server) requirePasskeysEnabled(writer http.ResponseWriter) bool {
	if server.passkeysEnabled() {
		return true
	}
	passkeyError(writer, http.StatusForbidden, "Passkeys are disabled by the administrator.")
	return false
}
