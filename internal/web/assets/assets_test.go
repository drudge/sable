package assets

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFingerprintURLServesImmutableCompressedAsset(t *testing.T) {
	t.Parallel()

	path := URL("app.js")
	if !strings.HasPrefix(path, "/assets/") || !strings.HasSuffix(path, "/app.js") || path == "/assets/app.js" {
		t.Fatalf("URL(app.js) = %q, want a fingerprinted path", path)
	}
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Accept-Encoding", "br, gzip")
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("asset status = %d", response.Code)
	}
	if got := response.Header().Get("Cache-Control"); got != immutableCachePolicy {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := response.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := response.Header().Get("Vary"); got != "Accept-Encoding" {
		t.Fatalf("Vary = %q", got)
	}
	if response.Header().Get("ETag") == "" {
		t.Fatal("ETag is empty")
	}
	reader, err := gzip.NewReader(bytes.NewReader(response.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decompressed, manifest["app.js"].content) {
		t.Fatal("compressed response does not expand to app.js")
	}
}

func TestAssetETagReturnsNotModified(t *testing.T) {
	t.Parallel()

	path := URL("app.css")
	firstRequest := httptest.NewRequest(http.MethodGet, path, nil)
	firstRequest.Header.Set("Accept-Encoding", "gzip")
	first := httptest.NewRecorder()
	Handler().ServeHTTP(first, firstRequest)

	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Accept-Encoding", "gzip")
	request.Header.Set("If-None-Match", first.Header().Get("ETag"))
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotModified || response.Body.Len() != 0 {
		t.Fatalf("conditional asset response = %d, %d bytes", response.Code, response.Body.Len())
	}
	if response.Header().Get("Cache-Control") != immutableCachePolicy {
		t.Fatal("304 response lost immutable caching")
	}
}

func TestLegacyAssetPathRevalidatesAndWrongFingerprintFails(t *testing.T) {
	t.Parallel()

	legacy := httptest.NewRecorder()
	Handler().ServeHTTP(legacy, httptest.NewRequest(http.MethodGet, "/assets/sable-mark.svg", nil))
	if legacy.Code != http.StatusOK || legacy.Header().Get("Cache-Control") != legacyCachePolicy {
		t.Fatalf("legacy response = %d, Cache-Control %q", legacy.Code, legacy.Header().Get("Cache-Control"))
	}

	missing := httptest.NewRecorder()
	Handler().ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/assets/not-the-hash/sable-mark.svg", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("wrong fingerprint status = %d, want 404", missing.Code)
	}
}

func TestGzipQualityZeroKeepsIdentityRepresentation(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, URL("app.css"), nil)
	request.Header.Set("Accept-Encoding", "gzip;q=0.0, br")
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, request)
	if response.Header().Get("Content-Encoding") != "" {
		t.Fatalf("Content-Encoding = %q, want identity", response.Header().Get("Content-Encoding"))
	}
	if !bytes.Equal(response.Body.Bytes(), manifest["app.css"].content) {
		t.Fatal("identity response does not match app.css")
	}
}

func TestVendoredHTMXVersion(t *testing.T) {
	t.Parallel()

	if content := string(manifest["htmx.min.js"].content); !strings.Contains(content, `version="4.0.0"`) {
		t.Fatal("vendored htmx asset is not version 4.0.0")
	}
}

func TestAccessibilityInteractionAssets(t *testing.T) {
	t.Parallel()

	script := string(manifest["app.js"].content)
	for _, expected := range []string{
		"const tabFromKey", "setupDialogAccessibility", "setupScrollableRegion",
		"Live log updates paused", "data-chart-keyboard-status", "sidebar-mobile-open",
		`!control.closest("[hidden]")`, `mobileOpen ? "Close navigation" : "Open navigation"`,
		"setupCommandPalette", "sable-command", "sable-search", "commandRank", "commandAcronym", "beginSearch", "selectSearchMode", "commandSearchModesConfig", "commandSearchModeExtraParam", "commandSearchModeValueTarget", "searchModeFooterItems", `["ArrowLeft", "ArrowRight"].includes(event.key)`, "requestSubmit", "runSearch", "runPostCommand", "visibleDialogTrigger", `target.closest("dialog")`, "responseDocument", "toast-region", "commandValues", `event.key.toLowerCase() !== "k"`,
	} {
		if !strings.Contains(script, expected) {
			t.Errorf("application script does not contain accessibility behavior %q", expected)
		}
	}

	stylesheet := string(manifest["app.css"].content)
	for _, expected := range []string{".skip-links", ".command-palette", ":focus-visible", "prefers-reduced-motion", "forced-colors"} {
		if !strings.Contains(stylesheet, expected) {
			t.Errorf("application stylesheet does not contain accessibility rule %q", expected)
		}
	}
}
