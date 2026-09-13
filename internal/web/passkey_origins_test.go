package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/store"
)

type passkeyTestCluster struct {
	clusterController
	state cluster.State
}

func (controller *passkeyTestCluster) Snapshot() cluster.State { return controller.state }

func TestDefaultPasskeyRPID(t *testing.T) {
	for _, test := range []struct{ host, want string }{
		{"ns1.penree.net", "penree.net"},
		{"ns2.penree.net", "penree.net"},
		{"ns.penree.net", "penree.net"},
		{"NS1.PENREE.NET", "penree.net"},
		{"ns1.example.co.uk", "example.co.uk"},
		{"ns1.alice.github.io", "alice.github.io"},
		{"ns1.bob.github.io", "bob.github.io"},
		{"ns1.example.internal", "example.internal"},
		{"localhost", "localhost"},
		{"127.0.0.1", ""},
		{"::1", ""},
		{"co.uk", ""},
		{"github.io", ""},
		{"", ""},
	} {
		t.Run(test.host, func(t *testing.T) {
			got, err := defaultPasskeyRPID(test.host)
			if got != test.want || (err != nil) != (test.want == "") {
				t.Fatalf("RP ID = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestPasskeySharedScopeKeepsOriginsRestricted(t *testing.T) {
	key := auth.Passkey{RPID: "penree.net"}
	key.Credential.Attestation.ClientDataJSON = jsonBytes(t, map[string]string{"origin": "https://ns1.penree.net"})
	membership := &passkeyTestCluster{state: cluster.State{Initialized: true, ClusterDomain: "ns.penree.net", Nodes: []cluster.Node{
		{ID: "ns1", AdvertiseURL: "https://ns1.penree.net:5443"},
		{ID: "ns2", AdvertiseURL: "https://ns2.penree.net:5443"},
		{ID: "foreign", AdvertiseURL: "https://ns1.other.net"},
	}}}
	server := &Server{cluster: membership}
	for _, test := range []struct {
		origin string
		want   bool
	}{
		{"https://ns1.penree.net", true},
		{"https://ns2.penree.net", true},
		{"https://ns2.penree.net:5443", true},
		{"https://ns2.penree.net:444", false},
		{"https://unrelated.penree.net", false},
		{"https://ns2.penree.net.attacker.net", false},
		{"http://ns2.penree.net", false},
		{"https://ns1.other.net", false},
		{"https://penree.net", false},
	} {
		if got := server.passkeyCredentialOriginAllowed(context.Background(), key, test.origin); got != test.want {
			t.Errorf("origin %s = %t, want %t", test.origin, got, test.want)
		}
	}
	membership.state.Nodes = membership.state.Nodes[:1]
	if server.passkeyCredentialOriginAllowed(context.Background(), key, "https://ns2.penree.net") {
		t.Fatal("removed replica remains authorized")
	}
	server.cluster = nil
	if server.passkeyCredentialOriginAllowed(context.Background(), key, "https://ns2.penree.net") {
		t.Fatal("standalone node trusts an unrelated sibling")
	}
	if !server.passkeyCredentialOriginAllowed(context.Background(), key, "https://ns1.penree.net") {
		t.Fatal("standalone enrollment origin stopped working")
	}
}

func TestPasskeyWorksAfterClusterFailoverWithoutConfiguration(t *testing.T) {
	ctx := context.Background()
	makeServer := func(name string) (*Server, *store.Store, *auth.Service) {
		t.Helper()
		database, err := store.Open(ctx, "sqlite", filepath.Join(t.TempDir(), name+".db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { database.Close() })
		service, err := auth.NewService(database, auth.Options{LoginAttempts: 100})
		if err != nil {
			t.Fatal(err)
		}
		server := &Server{auth: service, securityEnabled: true, crossOrigin: http.NewCrossOriginProtection(), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		return server, database, service
	}
	primary, database, service := makeServer("primary")
	credentials, err := service.Setup(ctx, "admin", "test-bootstrap-12345", "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := service.AuthenticateSession(ctx, credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := virtualPasskey{private: private, id: []byte("cluster-passkey"), rpID: "penree.net"}
	call := func(server *Server, handler http.HandlerFunc, origin, path string, body []byte, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, origin+path, bytes.NewReader(body))
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Sable-Passkey", "1")
		request.Header.Set("X-CSRF-Token", csrf)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		server.accessControl(handler).ServeHTTP(response, request)
		return response
	}
	options := func(response *httptest.ResponseRecorder) (string, string, string) {
		t.Helper()
		if response.Code != 200 {
			t.Fatalf("options status %d: %s", response.Code, response.Body.String())
		}
		var value struct {
			PublicKey struct {
				Challenge string
				RPID      string `json:"rpId"`
				RP        struct{ ID string }
				User      struct{ ID string }
			}
		}
		if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		rpID := value.PublicKey.RPID
		if rpID == "" {
			rpID = value.PublicKey.RP.ID
		}
		return value.PublicKey.Challenge, value.PublicKey.User.ID, rpID
	}
	// Enroll before clustering: joining later must not invalidate the credential.
	cookies := []*http.Cookie{{Name: primary.sessionCookieName(), Value: credentials.SessionToken}}
	begin := call(primary, primary.beginPasskeyRegistration, "https://ns1.penree.net", "/ui/profile/passkeys/begin?name=Cluster", nil, cookies, principal.CSRFToken)
	challenge, handle, rpID := options(begin)
	key.handle = handle
	if rpID != "penree.net" {
		t.Fatalf("unexpected standalone RP ID: %s", rpID)
	}
	cookies = append(cookies, begin.Result().Cookies()...)
	finish := call(primary, primary.finishPasskeyRegistration, "https://ns1.penree.net", "/ui/profile/passkeys/finish", key.response(t, challenge, "https://ns1.penree.net", true, 0x45), cookies, principal.CSRFToken)
	if finish.Code != 200 {
		t.Fatalf("registration: %d %s", finish.Code, finish.Body.String())
	}
	if err := service.DisableOwnPassword(ctx, principal, "test", "test"); err != nil {
		t.Fatal(err)
	}
	membership := &passkeyTestCluster{state: cluster.State{Initialized: true, ClusterDomain: "ns.penree.net", PrimaryID: "ns1", LocalRole: cluster.RoleReplica, Nodes: []cluster.Node{
		{ID: "ns1", AdvertiseURL: "https://ns1.penree.net:5443"},
		{ID: "ns2", AdvertiseURL: "https://ns2.penree.net:5443"},
	}}}
	replica, replicaDatabase, replicaService := makeServer("replica")
	replica.cluster = membership
	state, err := database.ExportAuthorizationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := replicaDatabase.ReplaceAuthorizationState(ctx, state); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{cluster.RoleReplica, cluster.RolePrimary} {
		t.Run(role, func(t *testing.T) {
			membership.state.LocalRole = role
			if role == cluster.RolePrimary {
				membership.state.PrimaryID = "ns2"
				membership.state.Nodes = membership.state.Nodes[1:]
			}
			begin := call(replica, replica.beginPasskeyLogin, "https://ns2.penree.net", passkeyLoginBegin, nil, nil, "")
			challenge, _, rpID := options(begin)
			if rpID != "penree.net" {
				t.Fatalf("failover changed RP ID: %s", rpID)
			}
			finish := call(replica, replica.finishPasskeyLogin, "https://ns2.penree.net", passkeyLoginFinish, key.response(t, challenge, "https://ns2.penree.net", false, 0x05), begin.Result().Cookies(), "")
			if finish.Code != 200 {
				t.Fatalf("passkey login after %s: %d %s", role, finish.Code, finish.Body.String())
			}
			var token string
			for _, cookie := range finish.Result().Cookies() {
				if cookie.Name == replica.sessionCookieName() {
					token = cookie.Value
				}
			}
			got, err := replicaService.AuthenticateSession(ctx, token)
			if err != nil || got.UserID != principal.UserID {
				t.Fatalf("replica session: %+v %v", got, err)
			}
		})
	}
	// A configured HTTPS alias need not be duplicated in the cluster registry.
	configuration := config.Defaults()
	configuration.Server.HTTPSListen = "0.0.0.0:8443"
	configuration.EncryptedDNS.CertificateMode = "acme"
	configuration.EncryptedDNS.ACME.Domains = []string{"ns.penree.net"}
	replica.config = testConfiguration{snapshot: config.Snapshot{Config: configuration}}
	begin = call(replica, replica.beginPasskeyLogin, "https://ns.penree.net:8443", passkeyLoginBegin, nil, nil, "")
	challenge, _, _ = options(begin)
	finish = call(replica, replica.finishPasskeyLogin, "https://ns.penree.net:8443", passkeyLoginFinish, key.response(t, challenge, "https://ns.penree.net:8443", false, 0x05), begin.Result().Cookies(), "")
	if finish.Code != http.StatusOK {
		t.Fatalf("configured HTTPS alias sign-in: %d %s", finish.Code, finish.Body.String())
	}
	// The authoritative registry now rejects unconfigured sibling origins
	// before a ceremony even begins, including forged Host/Origin pairs.
	begin = call(replica, replica.beginPasskeyLogin, "https://unrelated.penree.net", passkeyLoginBegin, nil, nil, "")
	if begin.Code != http.StatusBadRequest {
		t.Fatalf("unrelated sibling began a ceremony: %d", begin.Code)
	}
}

type passkeyTestCertificates struct {
	certificateController
	names []string
}

func (controller *passkeyTestCertificates) Status(context.Context, config.EncryptedDNS) certificates.Status {
	return certificates.Status{CoveredNames: controller.names}
}

func TestPasskeyOriginsUseExistingHTTPSNames(t *testing.T) {
	for _, mode := range []string{"acme", "manual"} {
		t.Run(mode, func(t *testing.T) {
			configuration := config.Defaults()
			configuration.Server.HTTPSListen = "0.0.0.0:8443"
			configuration.EncryptedDNS.CertificateMode = mode
			names := []string{"ns.penree.net", "ALT.PENREE.NET.", "*.penree.net", "192.0.2.10"}
			configuration.EncryptedDNS.ACME.Domains = names
			configured := &editableTestConfiguration{snapshot: config.Snapshot{Config: configuration}}
			certificates := &passkeyTestCertificates{names: names}
			server := &Server{config: configured, certificates: certificates, cluster: &passkeyTestCluster{state: cluster.State{Initialized: true, Nodes: []cluster.Node{
				{ID: "ns1", AdvertiseURL: "https://ns1.penree.net:5443"},
				{ID: "ns2", AdvertiseURL: "https://ns2.penree.net:5443"},
			}}}}
			key := auth.Passkey{RPID: "penree.net"}
			key.Credential.Attestation.ClientDataJSON = jsonBytes(t, map[string]string{"origin": "https://ns.penree.net"})
			for _, test := range []struct {
				origin string
				want   bool
			}{
				{"https://ns.penree.net", true},
				{"https://ns.penree.net:8443", true},
				{"https://alt.penree.net", true},
				{"https://ns2.penree.net", true},
				{"https://ns2.penree.net:5443", true},
				{"https://alt.penree.net:9443", false},
				{"https://other.penree.net", false},
				{"https://ns.penree.net.attacker.net", false},
				{"http://ns.penree.net:8443", false},
			} {
				if got := server.passkeyCredentialOriginAllowed(context.Background(), key, test.origin); got != test.want {
					t.Errorf("origin %s = %t, want %t", test.origin, got, test.want)
				}
				_, _, err := server.passkeyRelyingParty(httptest.NewRequest(http.MethodPost, test.origin+passkeyLoginBegin, nil))
				if (err == nil) != test.want {
					t.Errorf("ceremony origin %s: %v", test.origin, err)
				}
			}
			// An updated TLS configuration takes effect immediately, even for the
			// original enrollment address persisted inside the credential.
			configured.snapshot.Config.EncryptedDNS.ACME.Domains = []string{"alt.penree.net"}
			certificates.names = []string{"alt.penree.net"}
			if server.passkeyCredentialOriginAllowed(context.Background(), key, "https://ns.penree.net") {
				t.Fatal("removed certificate name remains trusted")
			}
			if _, _, err := server.passkeyRelyingParty(httptest.NewRequest(http.MethodPost, "https://ns.penree.net"+passkeyLoginBegin, nil)); err == nil {
				t.Fatal("removed certificate name can start a ceremony")
			}
		})
	}
}
