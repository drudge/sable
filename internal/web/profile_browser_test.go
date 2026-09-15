//go:build browser

package web

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

func TestBrowserNativeProfileFallback(t *testing.T) {
	authentication := &profileUpdateAuthenticator{}
	app := newNativeProfileTestServer(t, authentication)
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/profile.cjs", server.URL, app.sessionCookieName())
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser native profile fallback: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
	authentication.mu.Lock()
	defer authentication.mu.Unlock()
	if len(authentication.updated) < 2 || authentication.updated[0] != "Native Name" || authentication.updated[1] != "native@example.test" {
		t.Fatalf("native profile saves = %#v", authentication.updated)
	}
}
