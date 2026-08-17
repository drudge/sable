package dnsclient

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestQueryReturnsResponseFromUDPServer(t *testing.T) {
	t.Parallel()

	result, err := query(context.Background(), Request{
		Server:    "127.0.0.1:53",
		Name:      "example.com",
		Type:      "A",
		Transport: "udp",
		Timeout:   time.Second,
	}, func(_ context.Context, client *dns.Client, request *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
		if client.Net != "udp" {
			t.Errorf("client network = %q, want udp", client.Net)
		}
		if server != "127.0.0.1:53" {
			t.Errorf("server = %q, want 127.0.0.1:53", server)
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.1"),
		})
		return response, 25 * time.Microsecond, nil
	}, nil, nil)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(result.Response.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(result.Response.Answer))
	}
}

func TestQueryReturnsResponseFromDoHServer(t *testing.T) {
	t.Parallel()

	result, err := query(context.Background(), Request{
		Server: "dns.example:443", DialIP: "192.0.2.53", Name: "example.com", Type: "AAAA", Transport: "doh",
	}, nil, func(_ context.Context, request *dns.Msg, endpoint, dialIP string, timeout time.Duration) (*dns.Msg, time.Duration, error) {
		if endpoint != "https://dns.example:443/dns-query" {
			t.Errorf("endpoint = %q", endpoint)
		}
		if dialIP != "192.0.2.53" {
			t.Errorf("dial IP = %q, want 192.0.2.53", dialIP)
		}
		if timeout != 3*time.Second {
			t.Errorf("timeout = %s, want 3s", timeout)
		}
		response := new(dns.Msg)
		response.SetReply(request)
		return response, 40 * time.Microsecond, nil
	}, nil)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if result.Server != "https://dns.example:443/dns-query" {
		t.Fatalf("Server = %q", result.Server)
	}
}

func TestQueryUsesExplicitTLSNameForPinnedServer(t *testing.T) {
	t.Parallel()

	_, err := query(context.Background(), Request{
		Server: "192.0.2.53:853", TLSName: "dns.example", Name: "example.com", Type: "A", Transport: "tcp-tls",
	}, func(_ context.Context, client *dns.Client, request *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		if client.TLSConfig == nil || client.TLSConfig.ServerName != "dns.example" {
			t.Fatalf("TLS server name = %#v, want dns.example", client.TLSConfig)
		}
		response := new(dns.Msg)
		response.SetReply(request)
		return response, time.Millisecond, nil
	}, nil, nil)
	if err != nil {
		t.Fatalf("query() error = %v", err)
	}
}

func TestNormalizeDoHEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{input: "dns.example:443", want: "https://dns.example:443/dns-query"},
		{input: "https://dns.example/custom", want: "https://dns.example/custom"},
		{input: "https://dns.example", want: "https://dns.example/dns-query"},
	}
	for _, test := range tests {
		got, err := normalizeDoHEndpoint(test.input)
		if err != nil {
			t.Fatalf("normalizeDoHEndpoint(%q) error = %v", test.input, err)
		}
		if got != test.want {
			t.Errorf("normalizeDoHEndpoint(%q) = %q, want %q", test.input, got, test.want)
		}
	}
	if _, err := normalizeDoHEndpoint("http://dns.example/dns-query"); err == nil {
		t.Fatal("normalizeDoHEndpoint() error = nil for HTTP URL")
	}
}

func TestExchangeDoHUsesRFC8484WireFormat(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.Header.Get("Accept") != dohMediaType ||
			request.Header.Get("Content-Type") != dohMediaType {
			t.Errorf("request = %s Accept=%q Content-Type=%q", request.Method, request.Header.Get("Accept"), request.Header.Get("Content-Type"))
		}
		wire, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			return nil, err
		}
		response := new(dns.Msg)
		response.SetReply(query)
		responseWire, _ := response.Pack()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{dohMediaType}},
			Body:       io.NopCloser(bytes.NewReader(responseWire)),
		}, nil
	})}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	response, _, err := exchangeDoHWithClient(context.Background(), query, "https://dns.example/dns-query", client)
	if err != nil {
		t.Fatalf("exchangeDoH() error = %v", err)
	}
	if response.Id != query.Id || !response.Response {
		t.Fatalf("response = %+v, want reply to query %d", response, query.Id)
	}
}

func TestQueryRejectsUnknownRecordType(t *testing.T) {
	t.Parallel()

	_, err := Query(context.Background(), Request{Server: "127.0.0.1:53", Name: "example.com", Type: "NOT-A-TYPE"})
	if err == nil {
		t.Fatal("Query() error = nil, want validation error")
	}
}

func TestQueryRejectsUnknownTransport(t *testing.T) {
	t.Parallel()

	_, err := Query(context.Background(), Request{
		Server: "127.0.0.1:53", Name: "example.com", Type: "A", Transport: "quic-ish",
	})
	if err == nil {
		t.Fatal("Query() error = nil, want transport validation error")
	}
}

func TestQueryAddsDNSSECAndEDNSClientSubnet(t *testing.T) {
	t.Parallel()

	_, err := query(context.Background(), Request{
		Server: "127.0.0.1:53", Name: "example.com", Type: "A", Transport: "udp",
		DNSSEC: true, EDNSSubnet: "192.0.2.129/24",
	}, func(_ context.Context, _ *dns.Client, request *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		opt := request.IsEdns0()
		if opt == nil || !opt.Do() {
			t.Fatal("DNSSEC OK bit is not set")
		}
		if len(opt.Option) != 1 {
			t.Fatalf("EDNS option count = %d, want 1", len(opt.Option))
		}
		subnet, ok := opt.Option[0].(*dns.EDNS0_SUBNET)
		if !ok || subnet.Family != 1 || subnet.SourceNetmask != 24 || subnet.Address.String() != "192.0.2.0" {
			t.Fatalf("EDNS subnet = %+v", opt.Option[0])
		}
		response := new(dns.Msg)
		response.SetReply(request)
		return response, time.Millisecond, nil
	}, nil, nil)
	if err != nil {
		t.Fatalf("query() error = %v", err)
	}
}

func TestQueryRejectsInvalidEDNSClientSubnet(t *testing.T) {
	t.Parallel()

	_, err := Query(context.Background(), Request{
		Server: "127.0.0.1:53", Name: "example.com", Type: "A", EDNSSubnet: "not-a-subnet",
	})
	if err == nil {
		t.Fatal("Query() error = nil, want EDNS subnet validation error")
	}
}
