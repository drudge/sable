package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestServiceWorkerAndManifestAreServedWithoutSigningIn(t *testing.T) {
	t.Parallel()
	server := newInsightsTestServer(t)
	worker := server.get(t, "", "/sw.js", false)
	if worker.Code != http.StatusOK || !strings.Contains(worker.Body.String(), `addEventListener("push"`) ||
		!strings.HasPrefix(worker.Header().Get("Content-Type"), "text/javascript") || worker.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("service worker = %d %v", worker.Code, worker.Header())
	}
	manifest := server.get(t, "", "/manifest.webmanifest", false)
	var described struct {
		Display string `json:"display"`
		Icons   []struct {
			Source string `json:"src"`
		} `json:"icons"`
	}
	if err := json.Unmarshal(manifest.Body.Bytes(), &described); err != nil || described.Display != "standalone" || len(described.Icons) == 0 {
		t.Fatalf("manifest = %d %s", manifest.Code, manifest.Body.String())
	}
}

func TestBrowserLabelsNameTheBrowserAndSystem(t *testing.T) {
	t.Parallel()
	for userAgent, want := range map[string]string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1": "Safari on iPhone",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0 Safari/537.36 Edg/152.0":                   "Edge on Windows",
		"Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0":                                                                  "Firefox on Linux",
		"Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0 Mobile Safari/537.36":                                "Chrome on Android",
		"curl/8.7.1": "A browser",
	} {
		if got := browserLabel(userAgent); got != want {
			t.Errorf("browserLabel(%q) = %q, want %q", userAgent, got, want)
		}
	}
}
