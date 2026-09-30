//go:build browser

package web

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

// Both log searches keep what was typed while their panels refresh around
// the box, and the query log search keeps its terms in the address.
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
