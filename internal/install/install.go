package install

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	// ServiceName is the systemd unit that runs Sable.
	ServiceName = "sable.service"
	// ServiceUnitPath is where the systemd unit is installed.
	ServiceUnitPath = "/etc/systemd/system/sable.service"

	serviceUser             = "sable"
	defaultBinaryPath       = "/usr/local/bin/sable"
	defaultConfigurationDir = "/etc/sable"
	defaultDataDirectory    = "/var/lib/sable"
)

type Options struct {
	CertificateNames []string
	Start            bool
	// WebUpdates installs the service executable inside Sable's writable data
	// directory. The service still runs as the unprivileged sable user, but it
	// can replace that executable after verifying a published release.
	WebUpdates bool
	// DisableWebUpdates moves a web-update installation back to running the
	// root-owned /usr/local/bin/sable. Without either option a reinstall keeps
	// the layout the installed unit already uses.
	DisableWebUpdates bool
}

type Result struct {
	BinaryPath        string
	ServiceBinaryPath string
	ConfigurationPath string
	DataDirectory     string
	ConsoleHost       string
	Started           bool
	WebUpdates        bool
	// WebUpdatesKept reports that web updates stayed on because the installed
	// unit already used them, not because this run asked for them.
	WebUpdatesKept bool
}

type layout struct {
	binaryPath        string
	serviceBinaryPath string
	configurationDir  string
	configurationPath string
	dataDirectory     string
	servicePath       string
}

func defaultLayout() layout {
	return layout{
		binaryPath:        defaultBinaryPath,
		serviceBinaryPath: defaultBinaryPath,
		configurationDir:  defaultConfigurationDir,
		configurationPath: filepath.Join(defaultConfigurationDir, "sable.toml"),
		dataDirectory:     defaultDataDirectory,
		servicePath:       ServiceUnitPath,
	}
}

func layoutForOptions(options Options) layout {
	paths := defaultLayout()
	if options.WebUpdates {
		paths.serviceBinaryPath = filepath.Join(paths.dataDirectory, "bin", "sable")
	}
	return paths
}

// InstalledWebUpdateBinaryPath returns the alternate service executable when
// the installed unit opted into web updates. The unit is root-owned, so it is
// also the authoritative marker used by the root CLI updater.
func InstalledWebUpdateBinaryPath() string {
	contents, err := os.ReadFile(ServiceUnitPath)
	if err != nil {
		return ""
	}
	paths := layoutForOptions(Options{WebUpdates: true})
	if !webUpdateServiceInstalled(string(contents), paths) {
		return ""
	}
	return paths.serviceBinaryPath
}

// resolveWebUpdates decides which layout an install writes. The opt-in is
// recorded only in the installed unit, so a run that asks for neither keeps the
// unit's current layout. Re-running the bootstrap is the documented way to
// update, and it passes no options: without this, every such run moved the
// service back to the root-owned /usr/local/bin and silently took away the
// console's ability to install releases (#500).
func resolveWebUpdates(options Options, installedUnit string) (enabled, kept bool, err error) {
	switch {
	case options.WebUpdates && options.DisableWebUpdates:
		return false, false, errors.New("choose either --enable-web-updates or --disable-web-updates, not both")
	case options.WebUpdates:
		return true, false, nil
	case options.DisableWebUpdates:
		return false, false, nil
	}
	installed := webUpdateServiceInstalled(installedUnit, layoutForOptions(Options{WebUpdates: true}))
	return installed, installed, nil
}

func webUpdateServiceInstalled(unit string, paths layout) bool {
	execStart := "ExecStart=" + paths.serviceBinaryPath + " serve --config " + paths.configurationPath
	return slices.Contains(strings.Split(unit, "\n"), execStart)
}

func initialCertificateNames(additional []string) ([]string, string) {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "localhost"
	}
	names := []string{hostname, "localhost", "127.0.0.1", "::1"}
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, networkInterface := range interfaces {
			addresses, addressErr := networkInterface.Addrs()
			if addressErr != nil {
				continue
			}
			for _, address := range addresses {
				ip, _, parseErr := net.ParseCIDR(address.String())
				if parseErr == nil && !ip.IsLoopback() {
					names = append(names, ip.String())
				}
			}
		}
	}
	names = append(names, additional...)
	cleaned := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name != "" && !slices.Contains(cleaned, name) {
			cleaned = append(cleaned, name)
		}
	}
	return cleaned, hostname
}

func consoleHost(names []string, hostname string) string {
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil && !ip.IsLoopback() {
			return name
		}
	}
	return hostname
}

func systemdUnit(paths layout) string {
	return fmt.Sprintf(`[Unit]
Description=Sable DNS Server
Documentation=https://github.com/drudge/sable
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=%[1]s
Group=%[1]s
WorkingDirectory=%[2]s
ExecStart=%[3]s serve --config %[4]s
Restart=on-failure
RestartSec=2s
TimeoutStopSec=30s
KillSignal=SIGTERM
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ReadWritePaths=%[2]s %[5]s
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
`, serviceUser, paths.dataDirectory, paths.serviceBinaryPath, paths.configurationPath, paths.configurationDir)
}

func initialConfiguration(paths layout) string {
	certificateFile := filepath.Join(paths.configurationDir, "tls", "manual", "certificate.pem")
	privateKeyFile := filepath.Join(paths.configurationDir, "tls", "manual", "private-key.pem")
	return fmt.Sprintf(`[server]
http_listen = "127.0.0.1:5380"
https_listen = "0.0.0.0:443"
dns_listen = ["0.0.0.0:53"]
shutdown_timeout = "15s"

[database]
driver = "sqlite"
dsn = %q

[resolver]
# Recursion is restricted even when DNS listeners bind all interfaces.
recursion = "private"
mode = "forward"
forwarders = ["1.1.1.1:53", "9.9.9.9:53"]

[blocking]
enabled = true

[query_log]
enabled = true

[encrypted_dns]
dot_listen = []
doh_listen = ["0.0.0.0:443"]
certificate_mode = "manual"
certificate_file = %q
private_key_file = %q
minimum_tls_version = "1.3"

[encrypted_dns.acme]
storage_dir = %q

[security]
enabled = true
secure_cookies = true
secret_key_file = %q

[cluster]
data_dir = %q

[config]
watch = true
debounce = "250ms"
`, filepath.Join(paths.dataDirectory, "sable.db"), certificateFile, privateKeyFile,
		filepath.Join(paths.dataDirectory, "tls", "acme"), filepath.Join(paths.dataDirectory, "sable.key"),
		filepath.Join(paths.dataDirectory, "cluster"))
}
