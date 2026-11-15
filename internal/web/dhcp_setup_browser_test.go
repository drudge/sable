//go:build browser

package web

import (
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"testing"
)

// The setup flow, in a browser: pick the host's network, add the scope it
// suggests, and turn DHCP on past another server the probe found.
func TestBrowserDHCPSetup(t *testing.T) {
	app, configuration, controller := newDHCPSetupServer(t)
	controller.others = []DHCPOtherServer{{Interface: "eth0", Server: netip.MustParseAddr("192.0.2.1"), Offered: netip.MustParseAddr("192.0.2.57")}}
	server := httptest.NewServer(app.httpServer.Handler)
	defer server.Close()

	command := exec.Command("node", "../../scripts/browser/dhcp-setup.cjs", server.URL)
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("browser DHCP setup: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
	settings := configuration.snapshot.Config.DHCP
	if !settings.Enabled || len(settings.Scopes) != 1 || settings.Scopes[0].ID != "lan" || settings.Scopes[0].Subnet != "192.0.2.0/24" ||
		settings.Scopes[0].Router != "192.0.2.1" || controller.probes != 1 {
		t.Fatalf("after setup: %+v, probes %d", settings, controller.probes)
	}
}
