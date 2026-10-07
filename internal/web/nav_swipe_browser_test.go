//go:build browser

package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"

	webassets "github.com/drudge/sable/internal/web/assets"
	"github.com/drudge/sable/internal/web/pages"
)

// On phones a drag to the right pulls out the navigation drawer, while
// vertical scrolls and sideways scrollers keep their own gestures.
func TestBrowserNavSwipe(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/assets/", webassets.Handler())
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		view := pages.CachePageView{Console: pages.DashboardView{CSRFToken: "fixture-csrf"}, Entries: 1000}
		_ = pages.CachePage(view).Render(r.Context(), w)
	})
	server := httptest.NewServer(secureHeaders(mux, false))
	defer server.Close()
	command := exec.Command("node", "../../scripts/browser/nav-swipe.cjs", server.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser nav swipe: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
