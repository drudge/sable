//go:build browser

package web

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

// Queries, domain checks, and Settings cards open at their own addresses:
// from a click, from Back and Forward, and from a link opened fresh.
func TestBrowserDeepLinks(t *testing.T) {
	app, _ := newCheckDomainTestServer(t)
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/deep-links.cjs", server.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser deep links: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
