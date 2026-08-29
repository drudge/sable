package dnsclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Request struct {
	Server       string
	TLSName      string
	DialIP       string
	DoHTLSConfig *tls.Config
	Name         string
	Type         string
	Transport    string
	EDNSSubnet   string
	DNSSEC       bool
	Timeout      time.Duration
}

type Result struct {
	Response *dns.Msg
	Elapsed  time.Duration
	Server   string
}

type exchangeFunc func(context.Context, *dns.Client, *dns.Msg, string) (*dns.Msg, time.Duration, error)
type dohExchangeFunc func(context.Context, *dns.Msg, string, string, time.Duration, *tls.Config) (*dns.Msg, time.Duration, error)
type doqExchangeFunc func(context.Context, *dns.Msg, string, string, time.Duration) (*dns.Msg, time.Duration, error)

const (
	transportUDP = "udp"
	transportTCP = "tcp"
	transportDoT = "tcp-tls"
	transportDoH = "doh"
	transportDoQ = "quic"
	dohMediaType = "application/dns-message"
	dohPath      = "/dns-query"
)

func Query(ctx context.Context, request Request) (Result, error) {
	return query(ctx, request, exchange, exchangeDoH, exchangeDoQ)
}

func query(
	ctx context.Context,
	request Request,
	exchangeMessage exchangeFunc,
	exchangeHTTPS dohExchangeFunc,
	exchangeQUIC doqExchangeFunc,
) (Result, error) {
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" {
		return Result{}, fmt.Errorf("DNS name is required")
	}
	queryType, ok := dns.StringToType[strings.ToUpper(request.Type)]
	if !ok {
		return Result{}, fmt.Errorf("unknown DNS record type %q", request.Type)
	}
	if request.Timeout <= 0 {
		request.Timeout = 3 * time.Second
	}
	if request.Transport == "" {
		request.Transport = transportUDP
	}
	if !validTransport(request.Transport) {
		return Result{}, fmt.Errorf("transport must be udp, tcp, tcp-tls, quic, or doh, got %q", request.Transport)
	}

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(request.Name), queryType)
	message.SetEdns0(dns.DefaultMsgSize, request.DNSSEC)
	if request.Transport == transportDoQ {
		// RFC 9250 section 4.2.1 requires the DNS Message ID to be zero on a
		// QUIC stream because the stream itself correlates the exchange.
		message.Id = 0
	}
	if request.EDNSSubnet != "" {
		subnet, err := parseClientSubnet(request.EDNSSubnet)
		if err != nil {
			return Result{}, err
		}
		message.IsEdns0().Option = append(message.IsEdns0().Option, subnet)
	}

	if request.Transport == transportDoH {
		endpoint, err := normalizeDoHEndpoint(request.Server)
		if err != nil {
			return Result{}, err
		}
		response, elapsed, err := exchangeHTTPS(ctx, message, endpoint, request.DialIP, request.Timeout, request.DoHTLSConfig)
		if err != nil {
			return Result{}, fmt.Errorf("query %s via doh: %w", endpoint, err)
		}
		return Result{Response: response, Elapsed: elapsed, Server: endpoint}, nil
	}
	if _, _, err := net.SplitHostPort(request.Server); err != nil {
		return Result{}, fmt.Errorf("DNS server must be host:port: %w", err)
	}
	if request.Transport == transportDoQ {
		response, elapsed, err := exchangeQUIC(ctx, message, request.Server, request.TLSName, request.Timeout)
		if err != nil {
			return Result{}, fmt.Errorf("query %s via quic: %w", request.Server, err)
		}
		return Result{Response: response, Elapsed: elapsed, Server: request.Server}, nil
	}

	client := &dns.Client{Net: request.Transport, Timeout: request.Timeout}
	if request.Transport == transportDoT {
		host, _, err := net.SplitHostPort(request.Server)
		if err != nil {
			return Result{}, fmt.Errorf("parse TLS server: %w", err)
		}
		serverName := strings.TrimSpace(request.TLSName)
		if serverName == "" {
			serverName = host
		}
		client.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	}

	started := time.Now()
	response, elapsed, err := exchangeMessage(ctx, client, message, request.Server)
	if err != nil {
		return Result{}, fmt.Errorf("query %s via %s: %w", request.Server, request.Transport, err)
	}
	if elapsed <= 0 {
		elapsed = time.Since(started)
	}
	return Result{Response: response, Elapsed: elapsed, Server: request.Server}, nil
}

func parseClientSubnet(value string) (*dns.EDNS0_SUBNET, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("EDNS client subnet is empty")
	}
	if !strings.Contains(value, "/") {
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("invalid EDNS client subnet %q", value)
		}
		if ip.To4() != nil {
			value += "/32"
		} else {
			value += "/128"
		}
	}
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return nil, fmt.Errorf("invalid EDNS client subnet %q: %w", value, err)
	}
	prefix, _ := network.Mask.Size()
	option := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, SourceNetmask: uint8(prefix)}
	if ipv4 := ip.To4(); ipv4 != nil {
		option.Family = 1
		option.Address = ipv4.Mask(network.Mask)
	} else {
		option.Family = 2
		option.Address = ip.Mask(network.Mask)
	}
	return option, nil
}

func validTransport(transport string) bool {
	return transport == transportUDP || transport == transportTCP ||
		transport == transportDoT || transport == transportDoH ||
		transport == transportDoQ
}

func normalizeDoHEndpoint(server string) (string, error) {
	server = strings.TrimSpace(server)
	if !strings.Contains(server, "://") {
		if _, _, err := net.SplitHostPort(server); err != nil {
			return "", fmt.Errorf("DoH server must be an HTTPS URL or host:port: %w", err)
		}
		server = "https://" + server + dohPath
	}
	endpoint, err := url.Parse(server)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return "", errors.New("DoH server must be a valid HTTPS URL")
	}
	if endpoint.User != nil || endpoint.Fragment != "" {
		return "", errors.New("DoH server URL must not contain credentials or a fragment")
	}
	if endpoint.Path == "" || endpoint.Path == "/" {
		endpoint.Path = dohPath
	}
	return endpoint.String(), nil
}

func exchange(ctx context.Context, client *dns.Client, message *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	return client.ExchangeContext(ctx, message, server)
}

func exchangeDoH(
	ctx context.Context,
	message *dns.Msg,
	endpoint string,
	dialIP string,
	timeout time.Duration,
	tlsConfiguration *tls.Config,
) (*dns.Msg, time.Duration, error) {
	client := &http.Client{Timeout: timeout}
	if dialIP != "" || tlsConfiguration != nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if tlsConfiguration != nil {
			transport.TLSClientConfig = tlsConfiguration.Clone()
		}
		if dialIP != "" {
			dialer := &net.Dialer{Timeout: timeout}
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, fmt.Errorf("parse HTTPS target %q: %w", address, err)
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(dialIP, port))
			}
		}
		client.Transport = transport
	}
	return exchangeDoHWithClient(ctx, message, endpoint, client)
}

func exchangeDoHWithClient(
	ctx context.Context,
	message *dns.Msg,
	endpoint string,
	client *http.Client,
) (*dns.Msg, time.Duration, error) {
	wire, err := message.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("pack DNS request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, 0, fmt.Errorf("create HTTPS request: %w", err)
	}
	request.Header.Set("Accept", dohMediaType)
	request.Header.Set("Content-Type", dohMediaType)

	started := time.Now()
	response, err := client.Do(request)
	elapsed := time.Since(started)
	if err != nil {
		return nil, elapsed, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return nil, elapsed, fmt.Errorf("DoH server returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != dohMediaType {
		return nil, elapsed, fmt.Errorf("DoH server returned content type %q", response.Header.Get("Content-Type"))
	}
	responseWire, err := io.ReadAll(io.LimitReader(response.Body, 65_536))
	if err != nil {
		return nil, elapsed, fmt.Errorf("read DNS response: %w", err)
	}
	if len(responseWire) > 65_535 {
		return nil, elapsed, errors.New("DoH server returned an oversized DNS response")
	}
	dnsResponse := new(dns.Msg)
	if err := dnsResponse.Unpack(responseWire); err != nil {
		return nil, elapsed, fmt.Errorf("unpack DNS response: %w", err)
	}
	if dnsResponse.Id != message.Id {
		return nil, elapsed, errors.New("DoH response ID does not match request")
	}
	return dnsResponse, elapsed, nil
}
