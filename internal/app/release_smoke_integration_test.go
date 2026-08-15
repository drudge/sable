//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	releaseSmokeZone       = "release-smoke.test"
	releaseSmokeImportZone = "imported.release-smoke.test"
	releaseSmokeCacheName  = "cache-release-smoke.invalid"
	releaseSmokeBlocked    = "blocked-release-smoke.invalid"
)

type releaseSmokeUpstream struct {
	address string
	server  *dns.Server
	queries atomic.Int64
}

func TestReleaseBinarySmoke(t *testing.T) {
	binaryPath := strings.TrimSpace(os.Getenv("SABLE_INTEGRATION_BINARY"))
	if binaryPath == "" {
		t.Skip("set SABLE_INTEGRATION_BINARY to the built Sable executable")
	}
	binaryPath, err := filepath.Abs(binaryPath)
	if err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	ports := allocateIntegrationNodePorts(t)
	dotAddress := allocateTCPAddress(t)
	dohAddress := allocateTCPAddress(t)
	upstream := startReleaseSmokeUpstream(t)
	certificate := generateReplicaCertificate(t, directory)
	configuration := integrationNodeConfiguration(directory, ports, "release-smoke", certificate)
	configuration.EncryptedDNS.DoTListen = []string{dotAddress}
	configuration.EncryptedDNS.DoHListen = []string{dohAddress}
	configuration.Resolver.Forwarders = []string{upstream.address}
	configuration.Resolver.SaveCache = true
	configuration.Blocking.Enabled = true
	configuration.QueryLog.Enabled = true
	configuration.QueryLog.FlushInterval.Duration = 25 * time.Millisecond
	configurationPath := writeIntegrationConfiguration(t, directory, configuration)
	client := trustedHTTPClient(t, filepath.Join(directory, certificate.CertificateFile))

	assertReleaseBinaryCommand(t, binaryPath, "version", "Sable ")
	assertReleaseBinaryCommand(t, binaryPath, "config", "check", "--config", configurationPath, "configuration valid:")

	first := startIntegrationNode(t, configurationPath, client, ports.https)
	verifyEmbeddedReleaseConsole(t, client, ports.https)
	createReleaseSmokeZone(t, client, ports.https)
	verifyReleaseSmokeZoneManagement(t, client, ports.https, ports.dns)
	verifyReleaseSmokeTransports(t, client, ports.dns, dotAddress, dohAddress)
	assertReleaseBinaryCommand(t, binaryPath, "query", "--server", ports.dns, "www."+releaseSmokeZone, "A", "192.0.2.20")

	addBlockedDomain(t, client, ports.https, configurationPath, releaseSmokeBlocked)
	waitForBlockedDNSResponse(t, first, ports.dns, releaseSmokeBlocked)

	assertDNSA(t, ports.dns, "udp", releaseSmokeCacheName, "198.51.100.44", nil)
	assertDNSA(t, ports.dns, "udp", releaseSmokeCacheName, "198.51.100.44", nil)
	if got := upstream.queries.Load(); got != 1 {
		t.Fatalf("upstream queries after cached lookup = %d, want 1", got)
	}
	waitForQueryLogEntry(t, first, client, ports.https, releaseSmokeCacheName)

	client.CloseIdleConnections()
	stopIntegrationNode(t, first)
	upstream.stop(t)

	second := startIntegrationNode(t, configurationPath, client, ports.https)
	assertDNSA(t, ports.dns, "udp", releaseSmokeCacheName, "198.51.100.44", nil)
	assertDNSA(t, ports.dns, "udp", "www."+releaseSmokeZone, "192.0.2.20", nil)
	waitForBlockedDNSResponse(t, second, ports.dns, releaseSmokeBlocked)
}

func verifyEmbeddedReleaseConsole(t *testing.T, client *http.Client, httpsAddress string) {
	t.Helper()
	page := releaseSmokeGET(t, client, "https://"+httpsAddress+"/")
	if !strings.Contains(page, "Sable") || !strings.Contains(page, "/assets/app.css") {
		t.Fatalf("embedded console shell is incomplete: %s", page)
	}
	stylesheet := releaseSmokeGET(t, client, "https://"+httpsAddress+"/assets/app.css")
	if !strings.Contains(stylesheet, "--background") {
		t.Fatal("embedded console stylesheet is incomplete")
	}
}

func assertReleaseBinaryCommand(t *testing.T, binaryPath string, arguments ...string) {
	t.Helper()
	want := arguments[len(arguments)-1]
	arguments = arguments[:len(arguments)-1]
	command := exec.Command(binaryPath, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", binaryPath, strings.Join(arguments, " "), err, output)
	}
	if !strings.Contains(string(output), want) {
		t.Fatalf("%s %s output does not contain %q: %s", binaryPath, strings.Join(arguments, " "), want, output)
	}
}

func startReleaseSmokeUpstream(t *testing.T) *releaseSmokeUpstream {
	t.Helper()
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start deterministic DNS upstream: %v", err)
	}
	upstream := &releaseSmokeUpstream{address: connection.LocalAddr().String()}
	server := &dns.Server{PacketConn: connection, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		upstream.queries.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		if len(request.Question) == 1 && strings.EqualFold(request.Question[0].Name, dns.Fqdn(releaseSmokeCacheName)) && request.Question[0].Qtype == dns.TypeA {
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("198.51.100.44").To4(),
			})
		} else {
			response.Rcode = dns.RcodeNameError
		}
		_ = writer.WriteMsg(response)
	})}
	upstream.server = server
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() {
		if upstream.server != nil {
			_ = upstream.server.Shutdown()
		}
	})
	return upstream
}

func (upstream *releaseSmokeUpstream) stop(t *testing.T) {
	t.Helper()
	if upstream.server == nil {
		return
	}
	if err := upstream.server.Shutdown(); err != nil {
		t.Fatalf("stop deterministic DNS upstream: %v", err)
	}
	upstream.server = nil
}

func createReleaseSmokeZone(t *testing.T, client *http.Client, httpsAddress string) {
	t.Helper()
	postReleaseSmokeForm(t, client, httpsAddress, "/ui/zones/add", url.Values{
		"name": {releaseSmokeZone}, "type": {"primary"}, "primary_ns": {"ns1." + releaseSmokeZone},
		"responsible": {"hostmaster@" + releaseSmokeZone}, "default_ttl": {"300"},
	})
	postReleaseSmokeForm(t, client, httpsAddress, "/ui/zones/records/add", url.Values{
		"zone": {releaseSmokeZone}, "name": {"www"}, "type": {"A"}, "value": {"192.0.2.10"}, "ttl": {"120"},
	})
	postReleaseSmokeForm(t, client, httpsAddress, "/ui/zones/records/update", url.Values{
		"zone": {releaseSmokeZone}, "name": {"www"}, "type": {"A"}, "value": {"192.0.2.10"}, "ttl": {"120"},
		"new_name": {"www"}, "new_value": {"192.0.2.20"}, "new_ttl": {"180"}, "enabled": {"true"},
	})
	postReleaseSmokeForm(t, client, httpsAddress, "/ui/zones/dnssec", url.Values{
		"zone": {releaseSmokeZone}, "enabled": {"true"}, "algorithm": {"ed25519"}, "denial": {"nsec"},
		"nsec3_iterations": {"0"}, "zsk_lifetime": {"720h"}, "ksk_lifetime": {"8760h"},
		"key_prepublish": {"24h"}, "key_retire_after": {"168h"},
	})
}

func verifyReleaseSmokeZoneManagement(t *testing.T, client *http.Client, httpsAddress, dnsAddress string) {
	t.Helper()
	exported := releaseSmokeGET(t, client, "https://"+httpsAddress+"/api/v1/zones/export?zone="+url.QueryEscape(releaseSmokeZone))
	if !strings.Contains(exported, "$ORIGIN "+releaseSmokeZone+".") || !strings.Contains(exported, "192.0.2.20") || !strings.Contains(exported, "DNSKEY") {
		t.Fatalf("exported signed zone is incomplete:\n%s", exported)
	}

	zoneFile := fmt.Sprintf(`$ORIGIN %s.
@ 300 IN SOA ns1.%s. hostmaster.%s. 2026081401 3600 600 1209600 300
@ 300 IN NS ns1.%s.
www 300 IN A 192.0.2.55
`, releaseSmokeImportZone, releaseSmokeImportZone, releaseSmokeImportZone, releaseSmokeImportZone)
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("file", "release-smoke.zone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, zoneFile); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://"+httpsAddress+"/ui/zones/import-new", &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", form.FormDataContentType())
	request.Header.Set("HX-Request", "true")
	releaseSmokeResponse(t, client, request)
	assertDNSA(t, dnsAddress, "udp", "www."+releaseSmokeImportZone, "192.0.2.55", nil)
	postReleaseSmokeForm(t, client, httpsAddress, "/ui/zones/delete", url.Values{"zone": {releaseSmokeImportZone}})
	if zones := releaseSmokeGET(t, client, "https://"+httpsAddress+"/api/v1/zones"); strings.Contains(zones, `"name":"`+releaseSmokeImportZone+`"`) {
		t.Fatalf("deleted imported zone remains in the catalog: %s", zones)
	}
}

func verifyReleaseSmokeTransports(t *testing.T, client *http.Client, dnsAddress, dotAddress, dohAddress string) {
	t.Helper()
	wantName := "www." + releaseSmokeZone
	assertDNSA(t, dnsAddress, "udp", wantName, "192.0.2.20", nil)
	assertDNSA(t, dnsAddress, "tcp", wantName, "192.0.2.20", nil)
	tlsConfiguration := client.Transport.(*http.Transport).TLSClientConfig.Clone()
	assertDNSA(t, dotAddress, "tcp-tls", wantName, "192.0.2.20", tlsConfiguration)
	assertDoHA(t, client, dohAddress, wantName, "192.0.2.20")
}

func assertDNSA(t *testing.T, address, transport, name, want string, tlsConfiguration *tls.Config) {
	t.Helper()
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(name), dns.TypeA)
	client := &dns.Client{Net: transport, Timeout: 2 * time.Second, TLSConfig: tlsConfiguration}
	response, _, err := client.Exchange(request, address)
	if err != nil {
		t.Fatalf("query %s over %s at %s: %v", name, transport, address, err)
	}
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("query %s over %s returned %s", name, transport, dns.RcodeToString[response.Rcode])
	}
	for _, answer := range response.Answer {
		if record, ok := answer.(*dns.A); ok && record.A.String() == want {
			return
		}
	}
	t.Fatalf("query %s over %s answers = %v, want A %s", name, transport, response.Answer, want)
}

func assertDoHA(t *testing.T, client *http.Client, address, name, want string) {
	t.Helper()
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), dns.TypeA)
	packed, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://"+address+"/dns-query", bytes.NewReader(packed))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("query %s over DoH: %v", name, err)
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("query %s over DoH = %d: %s", name, response.StatusCode, contents)
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(contents); err != nil {
		t.Fatal(err)
	}
	for _, record := range answer.Answer {
		if address, ok := record.(*dns.A); ok && address.A.String() == want {
			return
		}
	}
	t.Fatalf("query %s over DoH answers = %v, want A %s", name, answer.Answer, want)
}

func waitForQueryLogEntry(t *testing.T, node *runningIntegrationNode, client *http.Client, httpsAddress, name string) {
	t.Helper()
	waitForCondition(t, node, func() bool {
		return strings.Contains(releaseSmokeGET(t, client, "https://"+httpsAddress+"/api/v1/query-log?limit=100"), name)
	})
}

func postReleaseSmokeForm(t *testing.T, client *http.Client, httpsAddress, path string, values url.Values) string {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://"+httpsAddress+path, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	return releaseSmokeResponse(t, client, request)
}

func releaseSmokeGET(t *testing.T, client *http.Client, endpoint string) string {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	return releaseSmokeResponse(t, client, request)
}

func releaseSmokeResponse(t *testing.T, client *http.Client, request *http.Request) string {
	t.Helper()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("%s %s = %d: %s", request.Method, request.URL, response.StatusCode, contents)
	}
	return string(contents)
}
