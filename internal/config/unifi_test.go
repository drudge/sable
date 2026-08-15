package config

import (
	"strings"
	"testing"
	"time"
)

func decodeUniFi(t *testing.T, body string) (Config, error) {
	t.Helper()
	return Decode(strings.NewReader(baseConfiguration + body))
}

const baseConfiguration = `
[server]
http_listen = "127.0.0.1:5380"
dns_listen = ["127.0.0.1:8053"]
`

func TestUniFiDefaults(t *testing.T) {
	loaded, err := decodeUniFi(t, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	settings := loaded.UniFi
	if settings.Enabled {
		t.Fatal("UniFi synchronization defaults to enabled")
	}
	if settings.Site != "default" {
		t.Fatalf("site = %q, want default", settings.Site)
	}
	if settings.Interval.Duration != 2*time.Minute {
		t.Fatalf("interval = %s, want 2m", settings.Interval.Duration)
	}
	if !settings.SyncsReservations() || !settings.SyncsActiveClients() {
		t.Fatalf("sources = %v, want both reservations and active", settings.Sources)
	}
	if settings.Runnable() {
		t.Fatal("an unconfigured integration reported itself runnable")
	}
}

func TestUniFiNormalizesMappings(t *testing.T) {
	loaded, err := decodeUniFi(t, `
[unifi]
controller_url = "https://192.168.1.1/"
site = "  "

[[unifi.networks]]
id = "net-iot"
name = "IoT"
zone = "IoT.Example.NET."
enabled = true
`)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if loaded.UniFi.ControllerURL != "https://192.168.1.1" {
		t.Fatalf("controller URL = %q, want the trailing slash removed", loaded.UniFi.ControllerURL)
	}
	if loaded.UniFi.Site != "default" {
		t.Fatalf("site = %q, want default", loaded.UniFi.Site)
	}
	network := loaded.UniFi.Networks[0]
	if network.Zone != "iot.example.net" {
		t.Fatalf("zone = %q, want it normalized", network.Zone)
	}
	if network.HostnameTemplate != "{{host}}.{{network}}.{{zone}}" {
		t.Fatalf("hostname template = %q, want the default", network.HostnameTemplate)
	}
	if network.TTL != 300 {
		t.Fatalf("ttl = %d, want the 300 second default", network.TTL)
	}
}

func TestUniFiValidationRejectsBadConfiguration(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "enabled without a controller",
			body: "\n[unifi]\nenabled = true\n",
			want: "unifi.controller_url is required",
		},
		{
			name: "unsupported source",
			body: "\n[unifi]\nsources = [\"leases\"]\n",
			want: "unsupported source",
		},
		{
			name: "interval below the floor",
			body: "\n[unifi]\ninterval = \"5s\"\n",
			want: "unifi.interval must be at least",
		},
		{
			name: "mapping without a zone",
			body: "\n[[unifi.networks]]\nid = \"net-iot\"\n",
			want: "zone is required",
		},
		{
			name: "duplicate network mapping",
			body: `
[[unifi.networks]]
id = "net-iot"
zone = "a.example.net"

[[unifi.networks]]
id = "net-iot"
zone = "b.example.net"
`,
			want: "duplicate unifi network mapping",
		},
		{
			name: "bad template",
			body: "\n[[unifi.networks]]\nid = \"net-iot\"\nzone = \"a.example.net\"\nhostname_template = \"{{mac}}.{{zone}}\"\n",
			want: "unknown template placeholder",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := decodeUniFi(t, testCase.body)
			if err == nil {
				t.Fatal("Decode succeeded, want a validation error")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to mention %q", err, testCase.want)
			}
		})
	}
}

// Two networks publishing into one zone need {{network}} in their names, or
// the same hostname on two VLANs overwrites itself on every sync.
func TestUniFiRejectsCollidingSharedZone(t *testing.T) {
	shared := `
[[unifi.networks]]
id = "net-lan"
zone = "clients.example.net"
hostname_template = "{{host}}.{{zone}}"
enabled = true

[[unifi.networks]]
id = "net-iot"
zone = "clients.example.net"
hostname_template = "{{host}}.{{network}}.{{zone}}"
enabled = true
`
	_, err := decodeUniFi(t, shared)
	if err == nil || !strings.Contains(err.Error(), "must contain {{network}}") {
		t.Fatalf("Decode error = %v, want a collision warning", err)
	}

	separated := strings.Replace(shared, `zone = "clients.example.net"
hostname_template = "{{host}}.{{zone}}"`, `zone = "lan.example.net"
hostname_template = "{{host}}.{{zone}}"`, 1)
	if _, err := decodeUniFi(t, separated); err != nil {
		t.Fatalf("Decode with distinct zones: %v", err)
	}
}

// A disabled mapping is inert, so it cannot collide with an active one.
func TestUniFiIgnoresDisabledMappingsForCollisions(t *testing.T) {
	_, err := decodeUniFi(t, `
[[unifi.networks]]
id = "net-lan"
zone = "clients.example.net"
hostname_template = "{{host}}.{{zone}}"
enabled = true

[[unifi.networks]]
id = "net-iot"
zone = "clients.example.net"
hostname_template = "{{host}}.{{zone}}"
enabled = false
`)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
}
