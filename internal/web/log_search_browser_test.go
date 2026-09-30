//go:build browser

package web

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

// The server log search keeps what was typed while its panel refreshes
// around the box.
func TestBrowserLogSearch(t *testing.T) {
	app, _ := newCheckDomainTestServer(t)
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/log-search.cjs", server.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser log search: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
