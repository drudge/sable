package config

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// dhcpExample is the example from docs/design/dhcp.md, with every field set.
const dhcpExample = `
[dhcp]
enabled = true

[[dhcp.scopes]]
id = "lan"
name = "LAN"
subnet = "10.0.7.9/24"
enabled = true
lease = "24h"
router = "10.0.7.1"
dns = ["10.0.7.2", "10.0.7.3"]
domain = "LAN.Example.com."
search = ["lan.example.com", "Example.COM"]
ntp = ["10.0.7.1"]
routes = [{ to = "10.9.0.7/16", via = "10.0.7.2" }]
register_names = true
reverse = false
ttl = "5m"
ipv6_only_preferred = "30m"
reserved_only = false
ignore_client_id = true
block_random_macs = true
offer_delay = "250ms"
conflict_probe = "0s"
boot = { next_server = "10.0.7.5", server_name = "tftp.lan.example.com", file = "pxelinux.0" }

[[dhcp.scopes.ranges]]
start = "10.0.7.100"
end = "10.0.7.139"
node = "node-a"

[[dhcp.scopes.ranges]]
start = "10.0.7.150"
end = "10.0.7.179"
node = "node-b"

[[dhcp.scopes.reservations]]
mac = "AA-BB-CC-DD-EE-FF"
address = "10.0.7.20"
name = "NAS"
comment = "rack 1"

[[dhcp.scopes.options]]
code = 44
value = ["10.0.7.5"]

[[dhcp.scopes.options]]
code = 224
hex = "DEADbeef"
`

func decodeDHCP(t *testing.T, body string) (Config, error) {
	t.Helper()
	return Decode(strings.NewReader(baseConfiguration + body))
}

func TestDHCPOffByDefaultAndLeftOutOfTheFile(t *testing.T) {
	loaded, err := decodeDHCP(t, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if loaded.DHCP.Enabled || len(loaded.DHCP.Scopes) != 0 || !loaded.DHCP.IsZero() {
		t.Fatalf("dhcp = %+v, want off with no scopes", loaded.DHCP)
	}
	var encoded bytes.Buffer
	if err := toml.NewEncoder(&encoded).Encode(loaded); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// A node that predates DHCP decodes strictly, so an unused section must
	// stay out of any file it may be handed.
	if strings.Contains(encoded.String(), "dhcp") {
		t.Fatalf("encoded configuration mentions dhcp while it is unset:\n%s", encoded.String())
	}
}

func TestDHCPExampleRoundTrips(t *testing.T) {
	loaded, err := decodeDHCP(t, dhcpExample)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	scope := loaded.DHCP.Scopes[0]
	checks := []struct {
		name      string
		got, want any
	}{
		{"subnet", scope.Subnet, "10.0.7.0/24"},
		{"domain", scope.Domain, "lan.example.com"},
		{"search", scope.Search, []string{"lan.example.com", "example.com"}},
		{"route", scope.Routes[0], DHCPRoute{To: "10.9.0.0/16", Via: "10.0.7.2"}},
		{"mac", scope.Reservations[0].MAC, "aa:bb:cc:dd:ee:ff"},
		{"name", scope.Reservations[0].Name, "nas"},
		{"hex", scope.Options[1].Hex, "deadbeef"},
		{"serves", scope.Serves(), true},
		{"registers", scope.RegistersNames(), true},
		{"reverse", scope.Reverse != nil && *scope.Reverse, false},
		{"probe", scope.ConflictProbeTimeout(), time.Duration(0)},
		{"lease", scope.LeaseDuration(), 24 * time.Hour},
		{"ttl", scope.RecordTTL(), 5 * time.Minute},
		{"boot", scope.Boot, &DHCPBoot{NextServer: "10.0.7.5", ServerName: "tftp.lan.example.com", File: "pxelinux.0"}},
	}
	for _, check := range checks {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", check.name, check.got, check.want)
		}
	}
	encoded, err := toml.Marshal(loaded)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	again, err := Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode the encoded configuration: %v\n%s", err, encoded)
	}
	if !reflect.DeepEqual(again.DHCP, loaded.DHCP) {
		t.Fatalf("round trip changed dhcp:\n got %+v\nwant %+v", again.DHCP, loaded.DHCP)
	}
}

func TestDHCPDefaultsForUnsetScopeKeys(t *testing.T) {
	loaded, err := decodeDHCP(t, "\n[[dhcp.scopes]]\nid = \"lan\"\nname = \"LAN\"\nsubnet = \"10.0.7.0/24\"\n[[dhcp.scopes.ranges]]\nstart = \"10.0.7.100\"\nend = \"10.0.7.199\"\n")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	scope := loaded.DHCP.Scopes[0]
	if !scope.Serves() || !scope.RegistersNames() || !scope.PublishesReverse() {
		t.Fatal("an unset enabled, register_names, or reverse should default to true")
	}
	if scope.LeaseDuration() != DefaultDHCPLeaseTime || scope.RecordTTL() != DefaultDHCPRecordTTL ||
		scope.ConflictProbeTimeout() != DefaultDHCPConflictProbe {
		t.Fatalf("lease %s, ttl %s, probe %s", scope.LeaseDuration(), scope.RecordTTL(), scope.ConflictProbeTimeout())
	}
}

func TestDHCPConfigurationValidation(t *testing.T) {
	edit := func(pairs ...string) string { return strings.NewReplacer(pairs...).Replace(dhcpExample) }
	cases := []struct{ name, body, want string }{
		{"enabled without scopes", "\n[dhcp]\nenabled = true\n", "dhcp.enabled requires at least one scope"},
		{"missing id", edit(`id = "lan"`, `id = ""`), "dhcp.scopes[0].id is required"},
		{"bad id", edit(`id = "lan"`, `id = "LAN 1"`), "dhcp.scopes[0].id must be"},
		{"ipv6 subnet", edit(`subnet = "10.0.7.9/24"`, `subnet = "fd00::/64"`), "dhcp.scopes[0].subnet must be an IPv4 prefix"},
		{"subnet too small", edit(`subnet = "10.0.7.9/24"`, `subnet = "10.0.7.0/31"`), "dhcp.scopes[0].subnet must be between /8 and /30"},
		{"off-subnet range", edit(`end = "10.0.7.139"`, `end = "10.0.8.139"`), "dhcp.scopes[0].ranges[0].end must be inside 10.0.7.0/24"},
		{"broadcast in range", edit(`end = "10.0.7.179"`, `end = "10.0.7.255"`), "dhcp.scopes[0].ranges[1].end is the subnet's network or broadcast address"},
		{"reversed range", edit(`start = "10.0.7.100"`, `start = "10.0.7.140"`, `end = "10.0.7.139"`, `end = "10.0.7.100"`), "dhcp.scopes[0].ranges[0] starts after it ends"},
		{"overlapping ranges", edit(`start = "10.0.7.150"`, `start = "10.0.7.130"`), "dhcp.scopes[0].ranges[1] overlaps ranges[0]"},
		{"router in a range", edit(`router = "10.0.7.1"`, `router = "10.0.7.120"`), "dhcp.scopes[0].router is inside ranges[0]"},
		{"off-subnet router", edit(`router = "10.0.7.1"`, `router = "10.0.8.1"`), "dhcp.scopes[0].router must be inside 10.0.7.0/24"},
		{"bad dns", edit(`dns = ["10.0.7.2", "10.0.7.3"]`, `dns = ["fd00::53"]`), "dhcp.scopes[0].dns[0] must be an IPv4 address"},
		{"bad ntp", edit(`ntp = ["10.0.7.1"]`, `ntp = ["time.example"]`), "dhcp.scopes[0].ntp[0] must be an IPv4 address"},
		{"bad domain", edit(`domain = "LAN.Example.com."`, `domain = "bad..name"`), "dhcp.scopes[0].domain"},
		{"bad search", edit(`"Example.COM"`, `"a..b"`), "dhcp.scopes[0].search[1]"},
		{"off-link route", edit(`via = "10.0.7.2"`, `via = "10.0.9.2"`), "dhcp.scopes[0].routes[0].via must be inside 10.0.7.0/24"},
		{"bad route", edit(`to = "10.9.0.7/16"`, `to = "nowhere"`), "dhcp.scopes[0].routes[0].to must be an IPv4 prefix"},
		{"lease too short", edit(`lease = "24h"`, `lease = "30s"`), "dhcp.scopes[0].lease must be between 2m"},
		{"v6only too short", edit(`ipv6_only_preferred = "30m"`, `ipv6_only_preferred = "1m"`), "dhcp.scopes[0].ipv6_only_preferred must be at least 5m"},
		{"offer delay too long", edit(`offer_delay = "250ms"`, `offer_delay = "10s"`), "dhcp.scopes[0].offer_delay must be between"},
		{"probe too long", edit(`conflict_probe = "0s"`, `conflict_probe = "10s"`), "dhcp.scopes[0].conflict_probe must be between"},
		{"offer delay and probe past a retransmit", edit(`offer_delay = "250ms"`, `offer_delay = "2s"`, `conflict_probe = "0s"`, `conflict_probe = "2s"`), "dhcp.scopes[0].offer_delay and conflict_probe together must be at most 2.5s, not 4s"},
		{"v6only past option 108", edit(`ipv6_only_preferred = "30m"`, `ipv6_only_preferred = "1200000h"`), "dhcp.scopes[0].ipv6_only_preferred must be at most 4294967295 seconds"},
		{"boot file too long", edit(`file = "pxelinux.0"`, `file = "`+strings.Repeat("x", 128)+`"`), "dhcp.scopes[0].boot.file must be at most 127 bytes"},
		{"bad next server", edit(`next_server = "10.0.7.5"`, `next_server = "tftp"`), "dhcp.scopes[0].boot.next_server must be an IPv4 address"},
		{"bad mac", edit(`mac = "AA-BB-CC-DD-EE-FF"`, `mac = "nope"`), "dhcp.scopes[0].reservations[0].mac must be a 48-bit MAC address"},
		{"off-subnet reservation", edit(`address = "10.0.7.20"`, `address = "10.0.9.20"`), "dhcp.scopes[0].reservations[0].address must be inside 10.0.7.0/24"},
		{"reservation on router", edit(`address = "10.0.7.20"`, `address = "10.0.7.1"`), "dhcp.scopes[0].reservations[0].address is the router"},
		{"dotted reservation name", edit(`name = "NAS"`, `name = "nas.lan"`), "dhcp.scopes[0].reservations[0].name must be a single DNS label"},
		{"reserved option code", edit(`code = 44`, `code = 51`), "dhcp.scopes[0].options[0].code 51 is set by"},
		{"option with a field", edit(`code = 44`, `code = 121`), "dhcp.scopes[0].options[0].code 121 is set by"},
		{"untyped option value", edit(`code = 224`, `code = 225`, `hex = "DEADbeef"`, `value = ["x"]`), "dhcp.scopes[0].options[1] code 225 has no known type; use hex"},
		{"mistyped option value", edit(`value = ["10.0.7.5"]`, `value = ["ten"]`), "dhcp.scopes[0].options[0].value[0] must be an IPv4 address"},
		{"value and hex", edit(`hex = "DEADbeef"`, `hex = "00"`+"\n"+`value = ["1"]`), "dhcp.scopes[0].options[1] needs value or hex, not both"},
		{"bad hex", edit(`hex = "DEADbeef"`, `hex = "xyz"`), "dhcp.scopes[0].options[1].hex must be hexadecimal"},
		{"duplicate option", edit(`code = 224`, `code = 44`, `hex = "DEADbeef"`, `hex = "0a000705"`), "dhcp.scopes[0].options[1].code duplicates options[0]"},
		{"empty scope", "\n[[dhcp.scopes]]\nid = \"e\"\nname = \"E\"\nsubnet = \"10.0.0.0/24\"\n", "dhcp.scopes[0] needs at least one range or reservation"},
		{"reserved only without reservations", "\n[[dhcp.scopes]]\nid = \"e\"\nname = \"E\"\nsubnet = \"10.0.0.0/24\"\nreserved_only = true\n[[dhcp.scopes.ranges]]\nstart = \"10.0.0.10\"\nend = \"10.0.0.20\"\n", "dhcp.scopes[0].reserved_only needs at least one reservation"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := decodeDHCP(t, testCase.body)
			if err == nil {
				t.Fatal("Decode succeeded, want a validation error")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to mention %q", err, testCase.want)
			}
		})
	}
}

func TestDHCPValidationRejectsDuplicates(t *testing.T) {
	duplicateReservation := dhcpExample + `
[[dhcp.scopes.reservations]]
mac = "aa:bb:cc:dd:ee:ff"
address = "10.0.7.20"
name = "nas"
`
	overlappingScope := `
[[dhcp.scopes]]
id = "LAN"
name = "Other"
subnet = "10.0.0.0/16"

[[dhcp.scopes.ranges]]
start = "10.0.9.10"
end = "10.0.9.20"
`
	sharedDomainScope := `
[[dhcp.scopes]]
id = "iot"
name = "IoT"
subnet = "10.0.8.0/24"
domain = "lan.example.com"

[[dhcp.scopes.reservations]]
mac = "aa:bb:cc:dd:ee:01"
address = "10.0.8.20"
name = "Nas"
`
	cases := []struct {
		name, body string
		want       []string
	}{
		{"reservation name reused in a shared domain", dhcpExample + sharedDomainScope, []string{
			"dhcp.scopes[1].reservations[0].name nas.lan.example.com is already reserved by dhcp.scopes[0].reservations[0]",
		}},
		{"duplicate reservation", duplicateReservation, []string{
			"dhcp.scopes[0].reservations[1].mac duplicates reservations[0]",
			"dhcp.scopes[0].reservations[1].address duplicates reservations[0]",
			"dhcp.scopes[0].reservations[1].name duplicates reservations[0]",
		}},
		{"overlapping scopes", dhcpExample + overlappingScope, []string{
			"dhcp.scopes[1].id duplicates scopes[0]",
			"dhcp.scopes[1].subnet overlaps scopes[0]",
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := decodeDHCP(t, testCase.body)
			if err == nil {
				t.Fatal("Decode succeeded, want a validation error")
			}
			for _, want := range testCase.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v, want it to mention %q", err, want)
				}
			}
		})
	}
}

// Membership lives in the cluster data directory, not the file, so the node
// check runs where both are known.
func TestDHCPValidateNodesRejectsUnknownNode(t *testing.T) {
	loaded, err := decodeDHCP(t, dhcpExample)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if err := loaded.DHCP.ValidateNodes([]string{"node-a", "node-b"}); err != nil {
		t.Fatalf("ValidateNodes with both members: %v", err)
	}
	err = loaded.DHCP.ValidateNodes([]string{"node-a"})
	if err == nil || !strings.Contains(err.Error(), `dhcp.scopes[0].ranges[1].node "node-b" is not a cluster member`) {
		t.Fatalf("ValidateNodes = %v, want node-b rejected", err)
	}
	err = loaded.DHCP.ValidateNodes(nil)
	if err == nil || !strings.Contains(err.Error(), "dhcp.scopes[0].ranges[0].node is set but this server is not in a cluster") {
		t.Fatalf("ValidateNodes outside a cluster = %v", err)
	}
}

// The example in docs/configuration.md must decode, or readers copy a broken
// file.
func TestDHCPDocumentedExampleDecodes(t *testing.T) {
	documentation, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(documentation), "## DHCP server\n")
	if !found {
		t.Fatal("docs/configuration.md has no DHCP server section")
	}
	_, block, _ := strings.Cut(section, "```toml\n")
	block, _, found = strings.Cut(block, "```")
	if !found {
		t.Fatal("the DHCP server section has no TOML example")
	}
	if _, err := decodeDHCP(t, block); err != nil {
		t.Fatalf("documented example: %v", err)
	}
}

// Clone shares no memory with the original.
func TestDHCPCloneSharesNothing(t *testing.T) {
	on, probe := true, Duration{Duration: time.Second}
	original := DHCP{Enabled: true, Scopes: []DHCPScope{{ID: "lan", Enabled: &on, ConflictProbe: &probe, DNS: []string{"10.0.7.1"},
		Ranges: []DHCPRange{{Start: "10.0.7.100", End: "10.0.7.199", Node: "node-b"}}, Reservations: []DHCPReservation{{MAC: "aa:00:00:00:00:01"}},
		Options: []DHCPOption{{Code: 44, Value: []string{"10.0.7.5"}}}, Boot: &DHCPBoot{File: "pxelinux.0"}}}}
	copied := original.Clone()
	scope := &copied.Scopes[0]
	*scope.Enabled, *scope.ConflictProbe, scope.DNS[0] = false, Duration{}, "x"
	scope.Ranges[0].Node, scope.Reservations[0].MAC, scope.Options[0].Value[0], scope.Boot.File = "node-a", "x", "x", "x"
	kept := original.Scopes[0]
	if !*kept.Enabled || *kept.ConflictProbe != probe || kept.DNS[0] != "10.0.7.1" || kept.Ranges[0].Node != "node-b" ||
		kept.Reservations[0].MAC != "aa:00:00:00:00:01" || kept.Options[0].Value[0] != "10.0.7.5" || kept.Boot.File != "pxelinux.0" {
		t.Fatalf("editing the clone changed the original: %+v", kept)
	}
}

func TestDHCPScopeIDFromName(t *testing.T) {
	t.Parallel()
	for text, want := range map[string]string{
		"LAN":                                "lan",
		"Guest Wi-Fi":                        "guest-wi-fi",
		"  IoT -- Devices!  ":                "iot-devices",
		"br-lan":                             "br-lan",
		"日本":                                 "",
		"a very long scope name for the lab": "a-very-long-scope-name-for-the-l",
		"thirty one characters here okay x":  "thirty-one-characters-here-okay",
	} {
		if got := DHCPScopeID(text); got != want {
			t.Errorf("DHCPScopeID(%q) = %q, want %q", text, got, want)
		}
	}
}
