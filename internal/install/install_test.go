package install

import (
	"strings"
	"testing"

	"github.com/drudge/sable/internal/config"
)

func TestInitialConfigurationIsValidAndUsesAppliancePaths(t *testing.T) {
	paths := defaultLayout()
	contents := initialConfiguration(paths)
	configuration, err := config.Decode(strings.NewReader(contents))
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Server.DNSListen[0] != "0.0.0.0:53" {
		t.Fatalf("DNS listener = %q", configuration.Server.DNSListen[0])
	}
	if configuration.Server.HTTPSListen != "0.0.0.0:443" || !configuration.Security.SecureCookies {
		t.Fatalf("HTTPS defaults = %q, secure cookies = %v", configuration.Server.HTTPSListen, configuration.Security.SecureCookies)
	}
	if !configuration.SharesHTTPSWithDoH() || len(configuration.DedicatedDoHListeners()) != 0 {
		t.Fatalf("HTTPS and DoH should share the appliance TLS listener: %+v", configuration.EncryptedDNS.DoHListen)
	}
	if configuration.Database.DSN != "/var/lib/sable/sable.db" {
		t.Fatalf("database DSN = %q", configuration.Database.DSN)
	}
}

func TestSystemdUnitIsHardenedAndRestartable(t *testing.T) {
	unit := systemdUnit(defaultLayout())
	for _, required := range []string{
		"ExecStart=/usr/local/bin/sable serve --config /etc/sable/sable.toml",
		"Restart=on-failure",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"ProtectSystem=strict",
		"ReadWritePaths=/var/lib/sable /etc/sable",
	} {
		if !strings.Contains(unit, required) {
			t.Fatalf("systemd unit is missing %q", required)
		}
	}
}

func TestWebUpdatesKeepTheServiceExecutableInsideTheSandbox(t *testing.T) {
	paths := layoutForOptions(Options{WebUpdates: true})
	if paths.binaryPath != "/usr/local/bin/sable" {
		t.Fatalf("command binary = %q", paths.binaryPath)
	}
	if paths.serviceBinaryPath != "/var/lib/sable/bin/sable" {
		t.Fatalf("service binary = %q", paths.serviceBinaryPath)
	}
	unit := systemdUnit(paths)
	for _, required := range []string{
		"User=sable",
		"ExecStart=/var/lib/sable/bin/sable serve --config /etc/sable/sable.toml",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ReadWritePaths=/var/lib/sable /etc/sable",
	} {
		if !strings.Contains(unit, required) {
			t.Fatalf("web-updateable systemd unit is missing %q", required)
		}
	}
	if !webUpdateServiceInstalled(unit, paths) {
		t.Fatal("the web-updateable unit was not recognized")
	}
	if webUpdateServiceInstalled(systemdUnit(defaultLayout()), paths) {
		t.Fatal("the standard unit was recognized as web-updateable")
	}
}

func TestConsoleHostPrefersReachableAddress(t *testing.T) {
	if got := consoleHost([]string{"sable-1", "localhost", "127.0.0.1", "192.0.2.53"}, "sable-1"); got != "192.0.2.53" {
		t.Fatalf("console host = %q", got)
	}
}
