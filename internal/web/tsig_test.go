package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/tsig"
	zonemodel "github.com/drudge/sable/internal/zone"
)

type testTSIGVault struct{ values map[string][]byte }

func (vault testTSIGVault) Put(_ context.Context, name string, value []byte) error {
	vault.values[name] = append([]byte(nil), value...)
	return nil
}

func (vault testTSIGVault) Get(_ context.Context, name string) ([]byte, error) {
	value, found := vault.values[name]
	if !found {
		return nil, errors.New("secret not found")
	}
	return value, nil
}

func (vault testTSIGVault) Delete(_ context.Context, name string) error {
	delete(vault.values, name)
	return nil
}

func newTSIGTestServer(t *testing.T, zones []zonemodel.Zone) (*Server, *editableTestConfiguration, testTSIGVault) {
	t.Helper()
	configuration := &editableTestConfiguration{
		snapshot:     config.Snapshot{Config: config.Defaults(), Revision: 1},
		zoneSnapshot: zonemodel.Snapshot{Zones: zones},
	}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)), testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration, configuration.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	vault := testTSIGVault{values: make(map[string][]byte)}
	server.SetTSIGController(tsig.NewManager(configuration, tsig.NewStore(vault)))
	return server, configuration, vault
}

func postTSIGForm(t *testing.T, server *Server, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

func TestAddingATSIGKeyShowsItsSecretOnceAndKeepsItOutOfTheConfiguration(t *testing.T) {
	t.Parallel()
	server, configuration, vault := newTSIGTestServer(t, nil)

	response := postTSIGForm(t, server, "/ui/settings/tsig/save", url.Values{
		"tsig_name": {"transfer-key"}, "tsig_algorithm": {"hmac-sha256"},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("add key = %d %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "Added TSIG key transfer-key.") || !strings.Contains(body, `data-active-tab="tsig"`) {
		t.Fatalf("add key rendered %s", body)
	}
	if !strings.Contains(body, "Copy this secret now") || !strings.Contains(body, "generated-tsig-secret") {
		t.Fatal("the generated secret was not shown to the operator")
	}

	keys := configuration.Current().Config.TSIGKeys
	if len(keys) != 1 || keys[0].Name != "transfer-key." || keys[0].Secret != "" {
		t.Fatalf("configured keys = %+v", keys)
	}
	secret, found := vault.values["tsig/transfer-key."]
	if !found || len(secret) == 0 {
		t.Fatal("the secret did not reach the vault")
	}

	// Rendering the page again must not repeat the secret.
	list := httptest.NewRequest(http.MethodGet, "/settings?tab=tsig", nil)
	listResponse := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(listResponse, list)
	if strings.Contains(listResponse.Body.String(), string(secret)) {
		t.Fatal("the settings page showed a stored secret")
	}
	// A stored secret is the normal state and goes unremarked; the row only
	// carries the algorithm and what depends on the key.
	if strings.Contains(listResponse.Body.String(), "No secret stored") {
		t.Fatal("a key with a stored secret was flagged as missing one")
	}
	if !strings.Contains(listResponse.Body.String(), "HMAC-SHA256 · Not referenced by any zone") {
		t.Fatalf("the key row did not describe the key: %s", listResponse.Body.String())
	}
}

func TestAKeyWithNoStoredSecretIsFlagged(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newTSIGTestServer(t, nil)
	// A key restored from configuration without its vault entry, which is what
	// a partial restore or a lost key file leaves behind.
	if err := configuration.Update(context.Background(), func(candidate *config.Config) error {
		candidate.TSIGKeys = []config.TSIGKey{{Name: "orphan-key.", Algorithm: "hmac-sha256."}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/settings?tab=tsig", nil)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), "No secret stored") {
		t.Fatalf("a key missing its secret was not flagged: %s", response.Body.String())
	}
}

func TestRotatingATSIGKeyReplacesTheStoredSecret(t *testing.T) {
	t.Parallel()
	server, _, vault := newTSIGTestServer(t, nil)

	if response := postTSIGForm(t, server, "/ui/settings/tsig/save", url.Values{
		"tsig_name": {"transfer-key"}, "tsig_algorithm": {"hmac-sha256"},
	}); response.Code != http.StatusOK {
		t.Fatalf("add key = %d", response.Code)
	}
	original := string(vault.values["tsig/transfer-key."])

	response := postTSIGForm(t, server, "/ui/settings/tsig/save", url.Values{
		"tsig_name": {"transfer-key"}, "tsig_algorithm": {"hmac-sha256"}, "tsig_rotate": {"true"},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("rotate key = %d %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Rotated the secret for TSIG key transfer-key.") {
		t.Fatalf("rotate rendered %s", response.Body.String())
	}
	if rotated := string(vault.values["tsig/transfer-key."]); rotated == original || rotated == "" {
		t.Fatal("rotation did not replace the stored secret")
	}
}

func TestDeletingATSIGKeyInUseNamesTheZonesThatDependOnIt(t *testing.T) {
	t.Parallel()
	server, configuration, vault := newTSIGTestServer(t, []zonemodel.Zone{{
		ID: "zone-1", Name: "example.test", Type: "primary", TSIGKey: "transfer-key.",
	}})
	if response := postTSIGForm(t, server, "/ui/settings/tsig/save", url.Values{
		"tsig_name": {"transfer-key"}, "tsig_algorithm": {"hmac-sha256"},
	}); response.Code != http.StatusOK {
		t.Fatalf("add key = %d", response.Code)
	}

	response := postTSIGForm(t, server, "/ui/settings/tsig/delete", url.Values{"tsig_name": {"transfer-key"}})
	if response.Code != http.StatusConflict {
		t.Fatalf("delete in-use key = %d %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "example.test") {
		t.Fatalf("the refusal did not name the zone: %s", response.Body.String())
	}
	if len(configuration.Current().Config.TSIGKeys) != 1 || len(vault.values) != 1 {
		t.Fatal("a refused delete changed the key or its secret")
	}
}

func TestDeletingAnUnusedTSIGKeyDestroysItsSecret(t *testing.T) {
	t.Parallel()
	server, configuration, vault := newTSIGTestServer(t, nil)
	if response := postTSIGForm(t, server, "/ui/settings/tsig/save", url.Values{
		"tsig_name": {"transfer-key"}, "tsig_algorithm": {"hmac-sha256"},
	}); response.Code != http.StatusOK {
		t.Fatalf("add key = %d", response.Code)
	}

	response := postTSIGForm(t, server, "/ui/settings/tsig/delete", url.Values{"tsig_name": {"transfer-key"}})
	if response.Code != http.StatusOK {
		t.Fatalf("delete key = %d %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Removed TSIG key transfer-key.") {
		t.Fatalf("delete rendered %s", response.Body.String())
	}
	if len(configuration.Current().Config.TSIGKeys) != 0 || len(vault.values) != 0 {
		t.Fatalf("keys = %+v vault = %v", configuration.Current().Config.TSIGKeys, vault.values)
	}
}

func TestAddingATSIGKeyRejectsAWeakSuppliedSecret(t *testing.T) {
	t.Parallel()
	server, configuration, _ := newTSIGTestServer(t, nil)

	response := postTSIGForm(t, server, "/ui/settings/tsig/save", url.Values{
		"tsig_name": {"transfer-key"}, "tsig_algorithm": {"hmac-sha256"}, "tsig_secret": {"c2hvcnQ="},
	})
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("weak secret = %d %s", response.Code, response.Body.String())
	}
	if len(configuration.Current().Config.TSIGKeys) != 0 {
		t.Fatal("a rejected secret still configured the key")
	}
}

func TestZoneFormsOfferTheConfiguredTSIGKeys(t *testing.T) {
	t.Parallel()
	server, _, _ := newTSIGTestServer(t, []zonemodel.Zone{{
		ID: "zone-1", Name: "example.test", Type: "primary",
	}})
	if response := postTSIGForm(t, server, "/ui/settings/tsig/save", url.Values{
		"tsig_name": {"transfer-key"}, "tsig_algorithm": {"hmac-sha256"},
	}); response.Code != http.StatusOK {
		t.Fatalf("add key = %d", response.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/zones/example.test", nil)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	body := response.Body.String()
	if !strings.Contains(body, `<select class="mono-input" name="tsig_key">`) {
		t.Fatalf("the zone form still uses a free-text TSIG field: %s", body)
	}
	// The option carries the canonical name so it round-trips, but reads
	// without the root label, the same way zone names are shown.
	if !strings.Contains(body, `<option value="transfer-key.">transfer-key</option>`) {
		t.Fatalf("the zone form did not offer the configured key: %s", body)
	}
}

func TestKeyNamesAreShownWithoutTheRootLabel(t *testing.T) {
	t.Parallel()
	server, _, _ := newTSIGTestServer(t, nil)
	if response := postTSIGForm(t, server, "/ui/settings/tsig/save", url.Values{
		"tsig_name": {"transfer-key"}, "tsig_algorithm": {"hmac-sha256"},
	}); response.Code != http.StatusOK {
		t.Fatalf("add key = %d", response.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/settings?tab=tsig", nil)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), "<strong>transfer-key</strong>") {
		t.Fatalf("the key row showed a fully qualified name: %s", response.Body.String())
	}
}
