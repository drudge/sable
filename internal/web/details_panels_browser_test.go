//go:build browser

package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/drudge/sable/internal/config"
)

// Block lists open their panels at their own addresses: from a click, from
// Back and Forward, and from a link opened fresh.
func TestBrowserDetailsPanels(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("0.0.0.0 one.example\n0.0.0.0 two.example\n"))
	}))
	defer remote.Close()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}, baseDirectory: t.TempDir()}
	configuration.snapshot.Config.Blocking.Lists = []config.BlockList{{Name: "Test Feed", URL: remote.URL + "/hosts", Path: "blocklists/test-feed.txt", Format: "auto"}}
	cached := filepath.Join(configuration.baseDirectory, "blocklists/test-feed.txt")
	if err := os.MkdirAll(filepath.Dir(cached), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cached, []byte("cached.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := newDetailsPanelTestServer(t, configuration)
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/details-panels.cjs", server.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser details panels: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
