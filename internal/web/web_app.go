package web

import (
	"encoding/json"
	"net/http"

	webassets "github.com/drudge/sable/internal/web/assets"
)

const (
	// serviceWorkerPath is where the service worker lives. A worker controls
	// only the paths under its own, so it sits at the root.
	serviceWorkerPath = "/sw.js"
	// webManifestPath describes Sable as an app, which iPhone and iPad need
	// before a site added to the Home Screen may show notifications.
	webManifestPath = "/manifest.webmanifest"
)

type webManifestIcon struct {
	Source string `json:"src"`
	Sizes  string `json:"sizes"`
	Type   string `json:"type"`
}

// serveWebManifest describes the console as an app that opens on its own.
func serveWebManifest(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/manifest+json")
	writer.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"name": "Sable", "short_name": "Sable", "id": "/", "start_url": "/", "scope": "/",
		"display": "standalone", "background_color": "#0a0a0a", "theme_color": "#0a0a0a",
		"icons": []webManifestIcon{
			{Source: webassets.URL("sable-icon-180.png"), Sizes: "180x180", Type: "image/png"},
			{Source: webassets.URL("sable-mark.svg"), Sizes: "any", Type: "image/svg+xml"},
		},
	})
}
