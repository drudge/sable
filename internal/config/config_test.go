package config

import (
	"crypto/tls"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDecodeValidatesAndNormalizesTSIGKeys(t *testing.T) {
	t.Parallel()

	configuration, err := Decode(strings.NewReader(`
[[tsig_keys]]
name = "Transfer-Key"
algorithm = "hmac-sha384"
secret = "c3VwZXItc2VjcmV0LXRoaXJ0eS10d28="
`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(configuration.TSIGKeys) != 1 || configuration.TSIGKeys[0].Name != "transfer-key." ||
		configuration.TSIGKeys[0].Algorithm != "hmac-sha384." {
		t.Fatalf("TSIG configuration = keys=%+v", configuration.TSIGKeys)
	}

	_, err = Decode(strings.NewReader(`
[[tsig_keys]]
name = "short"
secret = "dGlueQ=="
`))
	if err == nil || !strings.Contains(err.Error(), "at least 128 bits") {
		t.Fatalf("invalid TSIG Decode() error = %v", err)
	}
}

func TestDecodeRejectsZonesInTOML(t *testing.T) {
	t.Parallel()

	_, err := Decode(strings.NewReader(`
[[zones]]
name = "example.test"
`))
	if err == nil {
		t.Fatal("Decode() accepted zones in TOML")
	}
}

func TestDecodeAppliesDefaultsAndNormalizesDomains(t *testing.T) {
	t.Parallel()

	loaded, err := Decode(strings.NewReader(`
[blocking]
domains = ["Example.COM.", "example.com", " ads.example "]
`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if loaded.Server.HTTPListen != defaultHTTPListen {
		t.Fatalf("HTTPListen = %q, want %q", loaded.Server.HTTPListen, defaultHTTPListen)
	}
	if !loaded.Resolver.DNSSECValidation {
		t.Fatal("DNSSECValidation = false, want secure-by-default resolver")
	}
	if !loaded.Resolver.DNSSECTrustAnchorUpdates {
		t.Fatal("DNSSECTrustAnchorUpdates = false, want RFC 5011 updates by default")
	}
	want := []string{"ads.example", "example.com"}
	if strings.Join(loaded.Blocking.Domains, ",") != strings.Join(want, ",") {
		t.Fatalf("Domains = %v, want %v", loaded.Blocking.Domains, want)
	}
}

func TestDecodeValidatesDNSSECResolverPolicy(t *testing.T) {
	t.Parallel()
	loaded, err := Decode(strings.NewReader(`
[resolver]
dnssec_validation = true
dnssec_trust_anchors = [". DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"]
dnssec_negative_trust_anchors = [" Corp.Example. ", "corp.example"]
`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(loaded.Resolver.DNSSECTrustAnchors) != 1 || !slices.Equal(loaded.Resolver.DNSSECNegativeTrustAnchors, []string{"corp.example"}) {
		t.Fatalf("DNSSEC resolver policy = %+v", loaded.Resolver)
	}
	invalid := strings.ReplaceAll(`
[resolver]
dnssec_trust_anchors = [". TXT invalid"]
`, "invalid", "trust-anchor")
	if _, err := Decode(strings.NewReader(invalid)); err == nil || !strings.Contains(err.Error(), "dnssec_trust_anchors") {
		t.Fatalf("Decode() invalid trust anchor error = %v", err)
	}
}

func TestDecodeAllowsRecursiveModeWithoutForwarders(t *testing.T) {
	t.Parallel()
	loaded, err := Decode(strings.NewReader(`
[resolver]
mode = "recursive"
forwarders = []
root_hints = [" 192.0.2.1:53 ", "192.0.2.1:53"]
`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if loaded.Resolver.Mode != "recursive" || len(loaded.Resolver.Forwarders) != 0 || !slices.Equal(loaded.Resolver.RootHints, []string{"192.0.2.1:53"}) {
		t.Fatalf("recursive resolver configuration = %+v", loaded.Resolver)
	}
	if _, err := Decode(strings.NewReader("[resolver]\nmode = \"forward\"\nforwarders = []\n")); err == nil || !strings.Contains(err.Error(), "forward mode") {
		t.Fatalf("forward mode without upstreams error = %v", err)
	}
	if _, err := Decode(strings.NewReader("[resolver]\nmode = \"recursive\"\nforwarders = []\nroot_hints = [\"not-an-address\"]\n")); err == nil || !strings.Contains(err.Error(), "root_hints") {
		t.Fatalf("invalid root hint error = %v", err)
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	_, err := Decode(strings.NewReader("[server]\nunknown = true\n"))
	if err == nil {
		t.Fatal("Decode() error = nil, want unknown field error")
	}
}

func TestDurationUnmarshalText(t *testing.T) {
	t.Parallel()

	var duration Duration
	if err := duration.UnmarshalText([]byte("750ms")); err != nil {
		t.Fatalf("UnmarshalText() error = %v", err)
	}
	if duration.Duration != 750*time.Millisecond {
		t.Fatalf("Duration = %s, want 750ms", duration.Duration)
	}
}

func TestDecodeRejectsQueryLogBatchLargerThanBuffer(t *testing.T) {
	t.Parallel()

	_, err := Decode(strings.NewReader(`
[query_log]
buffer_size = 32
batch_size = 64
`))
	if err == nil {
		t.Fatal("Decode() error = nil, want query log validation error")
	}
}

func TestDecodeNormalizesConditionalForwardingRoutes(t *testing.T) {
	t.Parallel()

	loaded, err := Decode(strings.NewReader(`
[[resolver.routes]]
domain = " Corp.Example. "
forwarders = [" 192.0.2.53:53 ", "192.0.2.53:53"]
`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(loaded.Resolver.Routes) != 1 || loaded.Resolver.Routes[0].Domain != "corp.example" {
		t.Fatalf("Routes = %+v, want normalized route", loaded.Resolver.Routes)
	}
	if len(loaded.Resolver.Routes[0].Forwarders) != 1 {
		t.Fatalf("route forwarders = %v, want deduplicated", loaded.Resolver.Routes[0].Forwarders)
	}
}

func TestDecodeRejectsDuplicateConditionalForwardingRoutes(t *testing.T) {
	t.Parallel()

	_, err := Decode(strings.NewReader(`
[[resolver.routes]]
domain = "corp.example"
forwarders = ["192.0.2.1:53"]

[[resolver.routes]]
domain = "CORP.EXAMPLE."
forwarders = ["192.0.2.2:53"]
`))
	if err == nil {
		t.Fatal("Decode() error = nil, want duplicate route error")
	}
}

func TestDecodeNormalizesBlockListAndResolvesRelativePath(t *testing.T) {
	t.Parallel()

	loaded, err := Decode(strings.NewReader(`
[[blocking.lists]]
name = " Local "
path = " lists/block.txt "
`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	list := loaded.Blocking.Lists[0]
	if list.Name != "Local" || list.Format != "auto" {
		t.Fatalf("block list = %+v, want normalized auto list", list)
	}
	paths := loaded.BlockListPaths("/etc/sable")
	if len(paths) != 1 || paths[0] != "/etc/sable/lists/block.txt" {
		t.Fatalf("BlockListPaths() = %v", paths)
	}
}

func TestDecodeRejectsUnknownBlockListFormat(t *testing.T) {
	t.Parallel()

	_, err := Decode(strings.NewReader(`
[[blocking.lists]]
name = "bad"
path = "bad.txt"
format = "mystery"
`))
	if err == nil {
		t.Fatal("Decode() error = nil, want block list format error")
	}
}

func TestDecodeNormalizesRemoteBlockListAndBlockingPolicy(t *testing.T) {
	t.Parallel()

	loaded, err := Decode(strings.NewReader(`
[blocking]
allowed_domains = [" Safe.Example. ", " *.Wild.Example. "]
update_interval = "6h"
response_type = "CUSTOM"
response_ttl = 45
custom_addresses = [" 192.0.2.8 ", "::ffff:192.0.2.8"]
bypass_clients = [" 10.0.0.0/8 ", "192.0.2.1"]
allow_txt_report = false

[[blocking.lists]]
name = " OISD "
url = " https://big.oisd.nl/ "
`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if loaded.Blocking.ResponseType != "custom" || loaded.Blocking.ResponseTTL != 45 || loaded.Blocking.UpdateInterval.Duration != 6*time.Hour {
		t.Fatalf("blocking policy = %+v", loaded.Blocking)
	}
	if got := loaded.Blocking.AllowedDomains; len(got) != 2 || got[0] != "*.wild.example" || got[1] != "safe.example" {
		t.Fatalf("allowed domains = %v", got)
	}
	if got := loaded.Blocking.CustomAddresses; len(got) != 1 || got[0] != "192.0.2.8" {
		t.Fatalf("custom addresses = %v", got)
	}
	list := loaded.Blocking.Lists[0]
	if list.Name != "OISD" || list.URL != "https://big.oisd.nl/" || list.Path == "" || list.Format != "auto" {
		t.Fatalf("remote block list = %+v", list)
	}
}

func TestDecodeRejectsInvalidBlockingPolicy(t *testing.T) {
	t.Parallel()

	_, err := Decode(strings.NewReader(`
[blocking]
response_type = "custom"
custom_addresses = []
bypass_clients = ["not-an-address"]
update_interval = "-1h"
`))
	if err == nil {
		t.Fatal("Decode() error = nil, want blocking policy validation errors")
	}
	for _, expected := range []string{"custom_addresses", "bypass_clients", "update_interval"} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Decode() error %q does not mention %q", err, expected)
		}
	}
}

func TestDecodeValidatesEncryptedDNS(t *testing.T) {
	t.Parallel()

	_, err := Decode(strings.NewReader(`
[encrypted_dns]
dot_listen = ["127.0.0.1:853"]
`))
	if err == nil {
		t.Fatal("Decode() error = nil, want missing certificate error")
	}

	loaded, err := Decode(strings.NewReader(`
[encrypted_dns]
doh_listen = ["127.0.0.1:443"]
certificate_file = "certs/sable.crt"
private_key_file = "certs/sable.key"
minimum_tls_version = "1.2"
`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	certificate, privateKey := loaded.EncryptedDNSCertificatePaths("/etc/sable")
	if certificate != "/etc/sable/certs/sable.crt" || privateKey != "/etc/sable/certs/sable.key" {
		t.Fatalf("certificate paths = %q, %q", certificate, privateKey)
	}
	if loaded.EncryptedDNS.MinimumTLSVersion() != tls.VersionTLS12 {
		t.Fatalf("MinimumTLSVersion() = %d, want TLS 1.2", loaded.EncryptedDNS.MinimumTLSVersion())
	}
}

func TestReloadDependencyPathsIncludeEncryptedDNSCertificates(t *testing.T) {
	t.Parallel()

	configuration := Defaults()
	configuration.EncryptedDNS.CertificateFile = "tls/cert.pem"
	configuration.EncryptedDNS.PrivateKeyFile = "/run/secrets/key.pem"
	paths := configuration.ReloadDependencyPaths("/etc/sable")
	want := []string{"/etc/sable/tls/cert.pem", "/run/secrets/key.pem"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("ReloadDependencyPaths() = %v, want %v", paths, want)
	}
}

func TestDecodeRejectsTCPListenerConflicts(t *testing.T) {
	t.Parallel()

	_, err := Decode(strings.NewReader(`
[server]
dns_listen = ["127.0.0.1:8053"]

[encrypted_dns]
dot_listen = ["127.0.0.1:8053"]
certificate_file = "cert.pem"
private_key_file = "key.pem"
`))
	if err == nil {
		t.Fatal("Decode() error = nil, want TCP listener conflict")
	}
}

func TestDecodeRejectsDoQConflictWithPlainDNSUDPListener(t *testing.T) {
	t.Parallel()

	_, err := Decode(strings.NewReader(`
[server]
dns_listen = ["127.0.0.1:8053"]

[encrypted_dns]
doq_listen = ["127.0.0.1:8053"]
certificate_file = "cert.pem"
private_key_file = "key.pem"
`))
	if err == nil {
		t.Fatal("Decode() error = nil, want UDP listener conflict")
	}
}

func TestDecodeAcceptsDoQSharingTheDoTPort(t *testing.T) {
	t.Parallel()

	// DoT binds TCP and DoQ binds UDP, so the same port number is fine.
	loaded, err := Decode(strings.NewReader(`
[encrypted_dns]
dot_listen = ["127.0.0.1:853"]
doq_listen = ["127.0.0.1:853"]
certificate_file = "cert.pem"
private_key_file = "key.pem"
`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(loaded.EncryptedDNS.DoQListen) != 1 || loaded.EncryptedDNS.DoQListen[0] != "127.0.0.1:853" {
		t.Fatalf("doq_listen = %v", loaded.EncryptedDNS.DoQListen)
	}
}

func TestDecodeRequiresACertificateForDoQ(t *testing.T) {
	t.Parallel()

	_, err := Decode(strings.NewReader(`
[encrypted_dns]
doq_listen = ["127.0.0.1:853"]
`))
	if err == nil {
		t.Fatal("Decode() error = nil, want a missing certificate failure")
	}
}

func TestDecodeNormalizesLocalHostOverrides(t *testing.T) {
	t.Parallel()

	loaded, err := Decode(strings.NewReader(`
[[resolver.hosts]]
name = " Router.Home.Arpa. "
addresses = ["192.168.1.1", "::ffff:192.168.1.1", " FD00::1 "]
`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	host := loaded.Resolver.Hosts[0]
	if host.Name != "router.home.arpa" {
		t.Fatalf("host name = %q", host.Name)
	}
	if strings.Join(host.Addresses, ",") != "192.168.1.1,fd00::1" {
		t.Fatalf("host addresses = %v", host.Addresses)
	}
	if host.TTL != defaultHostTTL {
		t.Fatalf("host TTL = %d, want %d", host.TTL, defaultHostTTL)
	}
}

func TestDecodeRejectsInvalidLocalHostOverrides(t *testing.T) {
	t.Parallel()

	_, err := Decode(strings.NewReader(`
[[resolver.hosts]]
name = "router.home.arpa"
addresses = ["not-an-ip"]

[[resolver.hosts]]
name = "ROUTER.HOME.ARPA."
addresses = ["192.168.1.1"]
`))
	if err == nil {
		t.Fatal("Decode() error = nil, want address and duplicate-name errors")
	}
}

func TestSecurityDefaultsAndSecretKeyPath(t *testing.T) {
	t.Parallel()

	configuration := Defaults()
	if !configuration.Security.Enabled || configuration.Security.SessionTTL.Duration != defaultSessionTTL {
		t.Fatalf("security defaults = %+v", configuration.Security)
	}
	if got := configuration.SecuritySecretKeyPath("/etc/sable"); got != "/etc/sable/data/sable.key" {
		t.Fatalf("SecuritySecretKeyPath() = %q", got)
	}
}

func TestManagedCertificateConfigurationAndPaths(t *testing.T) {
	t.Parallel()

	configuration, err := Decode(strings.NewReader(`
[encrypted_dns]
certificate_mode = "acme"
dot_listen = ["127.0.0.1:853"]

[encrypted_dns.acme]
email = "dns-admin@example.com"
domains = ["dns.example.com", "*.example.com"]
dns_provider = "cloudflare"
dns_zone = "Example.COM."
storage_dir = "data/certificates"
renew_before = "480h"
`))
	if err != nil {
		t.Fatal(err)
	}
	certificate, key := configuration.EncryptedDNSCertificatePaths("/etc/sable")
	if certificate != "/etc/sable/data/certificates/certificate.pem" || key != "/etc/sable/data/certificates/private-key.pem" {
		t.Fatalf("managed certificate paths = %q, %q", certificate, key)
	}
	if configuration.EncryptedDNS.ACME.DNSZone != "example.com" || configuration.EncryptedDNS.ACME.DirectoryURL != defaultACMEDirectoryURL {
		t.Fatalf("managed certificate configuration = %+v", configuration.EncryptedDNS.ACME)
	}
	for _, source := range []string{
		"[encrypted_dns]\ncertificate_mode = \"acme\"\n",
		"[encrypted_dns]\ncertificate_mode = \"acme\"\n[encrypted_dns.acme]\nemail=\"admin@example.com\"\ndomains=[\"dns.example.com\"]\ndns_provider=\"unsupported\"\n",
	} {
		if _, err := Decode(strings.NewReader(source)); err == nil {
			t.Fatalf("Decode() accepted invalid managed certificate configuration:\n%s", source)
		}
	}
}

func TestHTTPSConsoleUsesPublicCertificateAndSharesPortWithDoH(t *testing.T) {
	t.Parallel()

	valid := `
[server]
https_listen = "0.0.0.0:5443"

[encrypted_dns]
certificate_file = "tls/certificate.pem"
private_key_file = "tls/private-key.pem"
`
	configuration, err := Decode(strings.NewReader(valid))
	if err != nil || configuration.Server.HTTPSListen != "0.0.0.0:5443" {
		t.Fatalf("HTTPS configuration = %+v, %v", configuration.Server, err)
	}
	shared, err := Decode(strings.NewReader(`
[server]
https_listen = "0.0.0.0:443"

[encrypted_dns]
doh_listen = ["0.0.0.0:443"]
certificate_file = "tls/certificate.pem"
private_key_file = "tls/private-key.pem"
`))
	if err != nil {
		t.Fatalf("shared HTTPS/DoH configuration: %v", err)
	}
	if !shared.SharesHTTPSWithDoH() || len(shared.DedicatedDoHListeners()) != 0 {
		t.Fatalf("shared HTTPS/DoH listeners = shared %v, dedicated %v", shared.SharesHTTPSWithDoH(), shared.DedicatedDoHListeners())
	}
	for _, invalid := range []string{
		"[server]\nhttps_listen = \"0.0.0.0:5443\"\n",
		"[server]\nhttps_listen = \"0.0.0.0:443\"\n[encrypted_dns]\ndot_listen = [\"0.0.0.0:443\"]\ncertificate_file = \"tls/certificate.pem\"\nprivate_key_file = \"tls/private-key.pem\"\n",
	} {
		if _, err := Decode(strings.NewReader(invalid)); err == nil {
			t.Fatalf("Decode() accepted invalid HTTPS listener:\n%s", invalid)
		}
	}
}

func TestClusterBootstrapDefaultsAndValidation(t *testing.T) {
	t.Parallel()

	configuration := Defaults()
	if got := configuration.ClusterDataPath("/etc/sable"); got != "/etc/sable/data/cluster" {
		t.Fatalf("ClusterDataPath() = %q", got)
	}
	configuration.Cluster.TrustAnchorFile = "data/cluster/pki/cluster-ca.pem"
	if got := configuration.ClusterTrustAnchorPath("/etc/sable"); got != "/etc/sable/data/cluster/pki/cluster-ca.pem" {
		t.Fatalf("ClusterTrustAnchorPath() = %q", got)
	}
	loaded, err := Decode(strings.NewReader(`
[cluster]
data_dir = " local/cluster "
node_name = " dns-1 "
advertise_url = "https://dns-1.example:5380/"
`))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Cluster.DataDirectory != "local/cluster" || loaded.Cluster.NodeName != "dns-1" || loaded.Cluster.AdvertiseURL != "https://dns-1.example:5380" {
		t.Fatalf("cluster configuration = %+v", loaded.Cluster)
	}
	for _, invalid := range []string{"dns-1.example:5380", "http://dns-1.example", "ftp://dns-1.example", "https://user@dns-1.example", "https://dns-1.example?token=x"} {
		_, err := Decode(strings.NewReader("[cluster]\nadvertise_url = \"" + invalid + "\"\n"))
		if err == nil {
			t.Fatalf("Decode() accepted cluster advertise URL %q", invalid)
		}
	}
}

func TestDecodeRequiresSecureCookiesForExternalConsole(t *testing.T) {
	t.Parallel()

	_, err := Decode(strings.NewReader(`
[server]
http_listen = "0.0.0.0:5380"
`))
	if err == nil {
		t.Fatal("Decode() error = nil for external console without secure cookies")
	}
	if _, err := Decode(strings.NewReader(`
[server]
http_listen = "0.0.0.0:5380"

[security]
secure_cookies = true
`)); err != nil {
		t.Fatalf("Decode() error = %v with secure cookies", err)
	}
}
