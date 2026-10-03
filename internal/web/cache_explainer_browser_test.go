//go:build browser

package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"

	webassets "github.com/drudge/sable/internal/web/assets"
	"github.com/drudge/sable/internal/web/pages"
)

// The cache explainer starts collapsed on phones and must stay collapsed
// after the refresh button swaps the whole cache fragment.
func TestBrowserCacheExplainerAfterRefresh(t *testing.T) {
	var refreshes atomic.Int64
	mux := http.NewServeMux()
	mux.Handle("/assets/", webassets.Handler())
	mux.HandleFunc("GET /ui/cache/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = pages.CacheContent(pages.CachePageView{Entries: int(1000 + refreshes.Add(1))}).Render(r.Context(), w)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		view := pages.CachePageView{Console: pages.DashboardView{CSRFToken: "fixture-csrf"}, Entries: 1000}
		_ = pages.CachePage(view).Render(r.Context(), w)
	})
	server := httptest.NewServer(secureHeaders(mux, false))
	defer server.Close()
	command := exec.Command("node", "../../scripts/browser/cache-explainer.cjs", server.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser cache explainer: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
