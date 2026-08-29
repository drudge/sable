package web

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/miekg/dns"
)

func TestResolveDNSClientServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		preset     string
		custom     string
		customName string
		customIP   string
		local      string
		transport  string
		want       resolvedDNSServer
	}{
		{name: "this server UDP", preset: "this-server", local: "127.0.0.1:5353", transport: "udp", want: resolvedDNSServer{address: "127.0.0.1:5353"}},
		{name: "this server HTTPS", preset: "this-server", local: "https://sable.example/dns-query", transport: "doh", want: resolvedDNSServer{address: "https://sable.example/dns-query"}},
		{name: "recursive resolver", preset: "recursive-resolver", local: "127.0.0.1:5353", transport: "tcp", want: resolvedDNSServer{address: "127.0.0.1:5353"}},
		{name: "Cloudflare UDP", preset: "cloudflare", transport: "udp", want: resolvedDNSServer{address: "1.1.1.1:53"}},
		{name: "Cloudflare TLS", preset: "cloudflare", transport: "tcp-tls", want: resolvedDNSServer{address: "one.one.one.one:853"}},
		{name: "Cloudflare HTTPS", preset: "cloudflare", transport: "doh", want: resolvedDNSServer{address: "https://cloudflare-dns.com/dns-query"}},
		{name: "Google TLS", preset: "google", transport: "tcp-tls", want: resolvedDNSServer{address: "dns.google:853"}},
		{name: "Google HTTPS", preset: "google", transport: "doh", want: resolvedDNSServer{address: "https://dns.google/dns-query"}},
		{name: "Quad9 HTTPS", preset: "quad9", transport: "doh", want: resolvedDNSServer{address: "https://dns.quad9.net/dns-query"}},
		{name: "OpenDNS UDP", preset: "opendns", transport: "udp", want: resolvedDNSServer{address: "208.67.222.222:53"}},
		{name: "AdGuard TLS", preset: "adguard", transport: "tcp-tls", want: resolvedDNSServer{address: "dns.adguard-dns.com:853"}},
		{name: "root server", preset: "root-k", transport: "tcp", want: resolvedDNSServer{address: "193.0.14.129:53"}},
		{name: "legacy custom", preset: "custom", custom: "192.0.2.53:9953", transport: "udp", want: resolvedDNSServer{address: "192.0.2.53:9953"}},
		{name: "custom IP UDP", preset: "custom", customIP: "192.0.2.53", transport: "udp", want: resolvedDNSServer{address: "192.0.2.53:53"}},
		{name: "custom name TCP", preset: "custom", customName: "dns.example", transport: "tcp", want: resolvedDNSServer{address: "dns.example:53"}},
		{name: "pinned custom TLS", preset: "custom", customName: "dns.example", customIP: "192.0.2.53", transport: "tcp-tls", want: resolvedDNSServer{address: "192.0.2.53:853", tlsName: "dns.example"}},
		{name: "pinned custom HTTPS", preset: "custom", customName: "dns.example", customIP: "192.0.2.53", transport: "doh", want: resolvedDNSServer{address: "https://dns.example/dns-query", dialIP: "192.0.2.53"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveDNSClientServer(test.preset, test.custom, test.customName, test.customIP, test.local, test.transport)
			if err != nil {
				t.Fatalf("resolveDNSClientServer() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("resolveDNSClientServer() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestResolveClusterDNSClientServer(t *testing.T) {
	t.Parallel()
	state := cluster.State{
		Initialized: true,
		NodeID:      "node-local",
		Nodes: []cluster.Node{
			{ID: "node-local", Name: "ns1", Role: cluster.RolePrimary, Addresses: []string{"192.0.2.10"}},
			{ID: "node-standard", Name: "ns2", Role: cluster.RoleReplica, Addresses: []string{"192.0.2.11"}},
			{ID: "node-dev", Name: "ns-dev", Role: cluster.RoleReplica, Addresses: []string{"127.0.0.1:8054"}},
			{ID: "node-v6", Name: "ns-v6", Role: cluster.RoleReplica, Addresses: []string{"[2001:db8::53]:5353"}},
		},
	}
	tests := []struct {
		name      string
		resolver  string
		transport string
		want      string
	}{
		{name: "local listener", resolver: "cluster-node:node-local", transport: "udp", want: "127.0.0.1:8053"},
		{name: "standard DNS port", resolver: "cluster-node:node-standard", transport: "tcp", want: "192.0.2.11:53"},
		{name: "development port", resolver: "cluster-node:node-dev", transport: "udp", want: "127.0.0.1:8054"},
		{name: "IPv6 development port", resolver: "cluster-node:node-v6", transport: "udp", want: "[2001:db8::53]:5353"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resolved, err := resolveClusterDNSClientServer(test.resolver, state, "127.0.0.1:8053", test.transport)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.address != test.want {
				t.Fatalf("address = %q, want %q", resolved.address, test.want)
			}
		})
	}
}

func TestResolveClusterDNSClientServerRejectsInvalidSelection(t *testing.T) {
	t.Parallel()
	state := cluster.State{NodeID: "local", Nodes: []cluster.Node{{ID: "remote", Name: "ns2", Addresses: []string{"192.0.2.2"}}}}
	for _, test := range []struct {
		name, resolver, transport, want string
	}{
		{name: "removed node", resolver: "cluster-node:gone", transport: "udp", want: "no longer a member"},
		{name: "encrypted endpoint", resolver: "cluster-node:remote", transport: "doh", want: "do not advertise"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := resolveClusterDNSClientServer(test.resolver, state, "127.0.0.1:8053", test.transport)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestResolveDNSClientServerRejectsUnsupportedSelections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		preset     string
		customName string
		customIP   string
		local      string
		transport  string
		wantError  string
	}{
		{name: "missing custom", preset: "custom", transport: "udp", wantError: "custom DNS server is required"},
		{name: "invalid custom IP", preset: "custom", customIP: "not-an-ip", transport: "udp", wantError: "IP address is invalid"},
		{name: "invalid custom name", preset: "custom", customName: "https://dns.example", transport: "doh", wantError: "must be a hostname"},
		{name: "unknown resolver", preset: "bogus", transport: "udp", wantError: "unknown DNS resolver"},
		{name: "system DNS encrypted", preset: "system-dns", transport: "doh", wantError: "System DNS does not have a known DNS-over-HTTPS endpoint"},
		{name: "local encrypted", preset: "this-server", local: "127.0.0.1:5353", transport: "doh", wantError: "does not have a known DNS-over-HTTPS endpoint"},
		{name: "OpenDNS encrypted", preset: "opendns", transport: "tcp-tls", wantError: "does not publish a supported DNS-over-TLS endpoint"},
		{name: "root encrypted", preset: "root-a", transport: "doh", wantError: "does not publish a supported DNS-over-HTTPS endpoint"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := resolveDNSClientServer(test.preset, "", test.customName, test.customIP, test.local, test.transport)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("resolveDNSClientServer() error = %v, want containing %q", err, test.wantError)
			}
		})
	}
}

func TestDNSClientQueryMarksValidationErrorAsConsoleFragment(t *testing.T) {
	t.Parallel()

	form := url.Values{
		"name":         {"example.com"},
		"type":         {"A"},
		"resolver":     {"this-server"},
		"local_server": {"127.0.0.1:5353"},
		"transport":    {"doh"},
	}
	request := httptest.NewRequest(http.MethodPost, "/ui/query", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()

	(&Server{}).query(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
	if response.Header().Get(consoleFragmentHeader) != "true" {
		t.Fatalf("%s = %q, want true", consoleFragmentHeader, response.Header().Get(consoleFragmentHeader))
	}
	if body := response.Body.String(); !strings.Contains(body, "Query failed") ||
		!strings.Contains(body, "does not have a known DNS-over-HTTPS endpoint") {
		t.Fatalf("query failure response does not explain the error: %s", body)
	}
}

func TestLocalDoHServerUsesCurrentConsoleHostname(t *testing.T) {
	t.Parallel()

	configuration := config.Defaults()
	configuration.Server.HTTPSListen = "0.0.0.0:443"
	configuration.EncryptedDNS.DoHListen = []string{"0.0.0.0:443"}
	server := &Server{config: testConfiguration{snapshot: config.Snapshot{Config: configuration}}}
	request := httptest.NewRequest(http.MethodGet, "https://sable.example/dns-client", nil)

	got := server.localDoHServer(request)
	if want := (resolvedDNSServer{address: "https://sable.example/dns-query", dialIP: "127.0.0.1"}); got != want {
		t.Fatalf("localDoHServer() = %#v, want %#v", got, want)
	}
}

func TestDNSClientQueriesThisServerOverHTTPS(t *testing.T) {
	t.Parallel()

	dohServer := httptest.NewTLSServer(dnsserver.NewDoHHandler(dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.53"),
		})
		_ = writer.WriteMsg(response)
	})))
	t.Cleanup(dohServer.Close)

	configuration := config.Defaults()
	configuration.EncryptedDNS.DoHListen = []string{strings.TrimPrefix(dohServer.URL, "https://")}
	server := &Server{config: testConfiguration{snapshot: config.Snapshot{Config: configuration}}}
	certificate := dohServer.TLS.Certificates[0]
	server.certificate.Store(&certificate)
	form := url.Values{
		"name":      {"example.com"},
		"type":      {"A"},
		"resolver":  {"this-server"},
		"transport": {"doh"},
	}
	request := httptest.NewRequest(http.MethodPost, dohServer.URL+"/ui/query", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	server.query(response, request)

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "192.0.2.53") {
		t.Fatalf("local DoH query = %d %s", response.Code, response.Body.String())
	}
}
