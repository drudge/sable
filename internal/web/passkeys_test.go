package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/web/pages"
	"github.com/fxamacker/cbor/v2"
)

const testPasskeyOrigin = "https://sable.example"

type virtualPasskey struct {
	private *ecdsa.PrivateKey
	rpID    string
	id      []byte
	handle  string
	count   uint32
}

func jsonBytes(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func base64url(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
func (key *virtualPasskey) response(t *testing.T, challenge, origin string, register bool, flags byte) []byte {
	t.Helper()
	kind := "webauthn.get"
	if register {
		kind = "webauthn.create"
	}
	client := jsonBytes(t, map[string]any{"type": kind, "challenge": challenge, "origin": origin})
	rpID := key.rpID
	if rpID == "" {
		rpID = "sable.example"
	}
	rpHash := sha256.Sum256([]byte(rpID))
	data := append([]byte{}, rpHash[:]...)
	data = append(data, flags)
	if !register {
		key.count++
	}
	data = binary.BigEndian.AppendUint32(data, key.count)
	response := map[string]any{"clientDataJSON": base64url(client)}
	if register {
		cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.private.X.FillBytes(make([]byte, 32)), -3: key.private.Y.FillBytes(make([]byte, 32))})
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, make([]byte, 16)...)
		data = binary.BigEndian.AppendUint16(data, uint16(len(key.id)))
		data = append(data, key.id...)
		data = append(data, cose...)
		attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": data})
		if err != nil {
			t.Fatal(err)
		}
		response["attestationObject"] = base64url(attestation)
		response["transports"] = []string{"internal"}
	} else {
		clientHash := sha256.Sum256(client)
		signed := append(append([]byte{}, data...), clientHash[:]...)
		digest := sha256.Sum256(signed)
		signature, err := ecdsa.SignASN1(rand.Reader, key.private, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		response["authenticatorData"] = base64url(data)
		response["signature"] = base64url(signature)
		response["userHandle"] = key.handle
	}
	return jsonBytes(t, map[string]any{"id": base64url(key.id), "rawId": base64url(key.id), "type": "public-key", "response": response, "clientExtensionResults": map[string]any{}})
}

func TestPasskeyRegistrationAndPasswordlessLogin(t *testing.T) {
	ctx := context.Background()
	database, err := store.Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	service, err := auth.NewService(database, auth.Options{LoginAttempts: 100})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := service.Setup(ctx, "admin", "test-password-12345", "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := service.AuthenticateSession(ctx, credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{auth: service, securityEnabled: true, crossOrigin: http.NewCrossOriginProtection(), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := virtualPasskey{private: private, id: []byte("test-credential-id")}
	var ceremony *http.Cookie
	call := func(handler http.HandlerFunc, path string, body []byte, authenticated bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest("POST", testPasskeyOrigin+path, bytes.NewReader(body))
		request.Header.Set("Origin", testPasskeyOrigin)
		request.Header.Set("X-Sable-Passkey", "1")
		request.Header.Set("Content-Type", "application/json")
		if ceremony != nil {
			request.AddCookie(ceremony)
		}
		if authenticated {
			request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: credentials.SessionToken})
			request.Header.Set("X-CSRF-Token", principal.CSRFToken)
		}
		response := httptest.NewRecorder()
		server.accessControl(handler).ServeHTTP(response, request)
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == server.sessionCookieName()+"_passkey" {
				ceremony = cookie
			}
		}
		return response
	}
	options := func(response *httptest.ResponseRecorder) (string, string) {
		t.Helper()
		if response.Code != 200 {
			t.Fatalf("options status %d: %s", response.Code, response.Body.String())
		}
		var value struct {
			PublicKey struct {
				Challenge string
				User      struct{ ID string }
			}
		}
		if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		return value.PublicKey.Challenge, value.PublicKey.User.ID
	}
	challenge, handle := options(call(server.beginPasskeyRegistration, "/ui/profile/passkeys/begin?name=Test%20device", nil, true))
	key.handle = handle
	registration := key.response(t, challenge, testPasskeyOrigin, true, 0x45)
	response := call(server.finishPasskeyRegistration, "/ui/profile/passkeys/finish", registration, true)
	if response.Code != 200 {
		t.Fatalf("registration %d: %s", response.Code, response.Body.String())
	}
	if response = call(server.finishPasskeyRegistration, "/ui/profile/passkeys/finish", registration, true); response.Code != 400 {
		t.Fatalf("registration replay accepted: %d", response.Code)
	}
	if response = call(server.disableOwnPassword, "/ui/profile/password/disable", nil, true); response.Code != 200 {
		t.Fatalf("disable password %d: %s", response.Code, response.Body.String())
	}
	if _, err := service.Login(ctx, "admin", "test-password-12345", "test", "test"); err == nil {
		t.Fatal("disabled password still accepted")
	}
	if err := service.ValidatePasskeyDisable(ctx, ""); err == nil {
		t.Fatal("allowed disabling the only sign-in method")
	}
	if err := database.LinkIdentity(ctx, "oidc", "subject", "https://id.example.test", principal.UserID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := service.ValidatePasskeyDisable(ctx, "https://other.example.test"); err == nil {
		t.Fatal("accepted an inactive identity provider")
	}
	if err := service.ValidatePasskeyDisable(ctx, "https://id.example.test"); err != nil {
		t.Fatalf("OIDC alternative rejected: %v", err)
	}
	if response = call(server.enableOwnPassword, "/ui/profile/password/enable", nil, true); response.Code != 200 {
		t.Fatalf("enable password: %s", response.Body.String())
	}
	if err := service.ValidatePasskeyDisable(ctx, ""); err != nil {
		t.Fatalf("password alternative rejected: %v", err)
	}
	if _, err := service.Login(ctx, "admin", "test-password-12345", "test", "test"); err != nil {
		t.Fatalf("existing password not restored: %v", err)
	}
	if response = call(server.disableOwnPassword, "/ui/profile/password/disable", nil, true); response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	for _, test := range []struct {
		name, origin string
		flags        byte
		tamper       bool
	}{
		{"valid", testPasskeyOrigin, 0x05, false},
		{"wrong origin", "https://evil.example", 0x05, false},
		{"no user verification", testPasskeyOrigin, 0x01, false},
		{"bad signature", testPasskeyOrigin, 0x05, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			challenge, _ := options(call(server.beginPasskeyLogin, passkeyLoginBegin, nil, false))
			assertion := key.response(t, challenge, test.origin, false, test.flags)
			if test.tamper {
				var value map[string]any
				json.Unmarshal(assertion, &value)
				value["response"].(map[string]any)["signature"] = base64url([]byte("bad signature"))
				assertion = jsonBytes(t, value)
			}
			response := call(server.finishPasskeyLogin, passkeyLoginFinish+"?return_to=/profile", assertion, false)
			if test.name == "valid" {
				if response.Code != 200 {
					t.Fatalf("login %d: %s", response.Code, response.Body.String())
				}
				var session string
				for _, cookie := range response.Result().Cookies() {
					if cookie.Name == server.sessionCookieName() {
						session = cookie.Value
					}
				}
				got, err := service.AuthenticateSession(ctx, session)
				if err != nil || got.UserID != principal.UserID {
					t.Fatalf("invalid login session: %+v %v", got, err)
				}
				if response = call(server.finishPasskeyLogin, passkeyLoginFinish, assertion, false); response.Code != 400 {
					t.Fatalf("assertion replay accepted: %d", response.Code)
				}
			} else if response.Code != 401 {
				t.Fatalf("invalid assertion accepted: %d %s", response.Code, response.Body.String())
			}
		})
	}
	if response = call(server.removeOwnPasskey, "/ui/profile/passkeys/remove?id="+base64url(key.id), nil, true); response.Code != 400 {
		t.Fatalf("removed last passwordless passkey: %d", response.Code)
	}
	// A passkey account can deliberately return to password sign-in.
	if err := service.ChangeOwnPassword(ctx, principal, "", "new-password-12345", "test", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticateSession(ctx, credentials.SessionToken); err == nil {
		t.Fatal("setting password did not revoke sessions")
	}
	if _, err := service.Login(ctx, "admin", "new-password-12345", "test", "test"); err != nil {
		t.Fatalf("new password is unusable: %v", err)
	}
}

func TestPasskeyCeremonyBindingAndExpiry(t *testing.T) {
	server := &Server{}
	for _, test := range []struct{ name, purpose, session, origin string }{
		{"wrong purpose", "login", "session", testPasskeyOrigin},
		{"wrong session", "register", "other", testPasskeyOrigin},
		{"wrong origin", "register", "session", "https://other.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			id, err := server.passkeyCeremonies.issue(passkeyCeremony{Purpose: "register", SessionHash: "session", Origin: testPasskeyOrigin})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest("POST", test.origin+"/", nil)
			request.AddCookie(&http.Cookie{Name: server.sessionCookieName() + "_passkey", Value: id})
			request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, auth.Principal{SessionHash: test.session}))
			if _, _, ok := server.consumePasskeyCeremony(httptest.NewRecorder(), request, test.purpose); ok {
				t.Fatal("accepted mismatched ceremony")
			}
			if _, ok := server.passkeyCeremonies.consume(id); ok {
				t.Fatal("failed ceremony was not consumed")
			}
		})
	}
	id, _ := server.passkeyCeremonies.issue(passkeyCeremony{})
	server.passkeyCeremonies.entries[id] = passkeyCeremony{}
	if _, ok := server.passkeyCeremonies.consume(id); ok {
		t.Fatal("accepted expired ceremony")
	}
}

func TestPasskeyRequestRejectsCrossOriginAndInsecureHosts(t *testing.T) {
	database, err := store.Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	service, err := auth.NewService(database, auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{auth: service, securityEnabled: true, crossOrigin: http.NewCrossOriginProtection()}
	for _, test := range []struct{ name, origin, header string }{
		{"cross origin", "https://evil.example", "1"},
		{"missing origin", "", "1"},
		{"simple request", testPasskeyOrigin, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", testPasskeyOrigin+passkeyLoginBegin, nil)
			request.Header.Set("Origin", test.origin)
			request.Header.Set("X-Sable-Passkey", test.header)
			response := httptest.NewRecorder()
			if server.passkeyRequest(response, request) || response.Code != http.StatusForbidden {
				t.Fatal("accepted cross-site or simple passkey request")
			}
		})
	}
	for _, address := range []string{"http://sable.example", "http://127.0.0.1"} {
		if _, _, err := server.passkeyRelyingParty(httptest.NewRequest("POST", address, nil)); err == nil {
			t.Fatalf("accepted unsupported origin %s", address)
		}
	}
	request := httptest.NewRequest("POST", "http://sable.example", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	if party, origin, err := server.passkeyRelyingParty(request); err != nil || origin != testPasskeyOrigin || party.Config.RPID != "sable.example" {
		t.Fatalf("HTTPS proxy configuration: %s %v", origin, err)
	}
	for _, path := range []string{passkeyLoginBegin, passkeyLoginFinish} {
		if !publicRequest(path) || !replicaLocalWrite(path) {
			t.Fatalf("passkey login unavailable on replicas: %s", path)
		}
	}
	for _, path := range []string{"/ui/profile/passkeys/begin", "/ui/profile/passkeys/finish", "/ui/profile/passkeys/remove", "/ui/profile/password/disable", "/ui/profile/password/enable"} {
		if publicRequest(path) || replicaLocalWrite(path) {
			t.Fatalf("unprotected credential mutation: %s", path)
		}
	}
}

func TestPasskeysDisabledBlocksCeremoniesAndHidesLogin(t *testing.T) {
	configuration := config.Defaults()
	if configuration.Security.PasskeysDisabled {
		t.Fatal("passkeys should default on")
	}
	configuration.Security.PasskeysDisabled = true
	server := &Server{config: testConfiguration{snapshot: config.Snapshot{Config: configuration}}}
	for _, handler := range []http.HandlerFunc{server.beginPasskeyRegistration, server.finishPasskeyRegistration, server.beginPasskeyLogin, server.finishPasskeyLogin, server.disableOwnPassword} {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest("POST", "/", nil))
		if response.Code != http.StatusForbidden {
			t.Fatalf("disabled passkey endpoint returned %d", response.Code)
		}
	}
	var rendered bytes.Buffer
	if err := pages.AuthPage(false, "", "csrf", "/", "Example SSO", false).Render(context.Background(), &rendered); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered.String(), `data-passkey-action="login"`) || !strings.Contains(rendered.String(), "/auth/oidc/start") {
		t.Fatal("passkey toggle changed OIDC or left passkey login visible")
	}
}
