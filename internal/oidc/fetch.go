package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// responseLimit caps how much of a provider response is read. Discovery
// documents and key sets are a few kilobytes; a megabyte is generous and stops
// a hostile or broken issuer from feeding this process until it dies.
const responseLimit = 1 << 20

// fetcher performs the two unauthenticated GETs and the one authenticated POST
// this package makes, with the transport rules applied in one place.
type fetcher struct {
	client *http.Client
	agent  string
}

func newFetcher(client *http.Client, agent string) *fetcher {
	if client == nil {
		client = http.DefaultClient
	}
	if agent == "" {
		agent = "sable"
	}
	return &fetcher{client: client, agent: agent}
}

func (fetch *fetcher) getJSON(ctx context.Context, endpoint string, target any) error {
	if err := requireSecureURL(endpoint); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", fetch.agent)
	return fetch.do(request, target)
}

func (fetch *fetcher) postForm(ctx context.Context, endpoint string, values url.Values, header http.Header, target any) error {
	if err := requireSecureURL(endpoint); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", fetch.agent)
	for name, entries := range header {
		for _, entry := range entries {
			request.Header.Add(name, entry)
		}
	}
	return fetch.do(request, target)
}

func (fetch *fetcher) do(request *http.Request, target any) error {
	response, err := fetch.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, responseLimit))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// The provider's own error body is the most useful thing in the server
		// log when a client secret is wrong, so a short prefix of it is kept.
		return fmt.Errorf("provider answered %s: %s", response.Status, summarize(body))
	}
	if target == nil {
		return nil
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode provider response: %w", err)
	}
	return nil
}

// requireSecureURL keeps provider traffic on TLS. Plain HTTP is allowed only
// to a loopback address, which is where a developer or a test harness runs a
// throwaway provider; over a network it would put the tokens that grant
// administrator access on the wire in the clear.
func requireSecureURL(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("%w: %q is not a URL", ErrDiscovery, endpoint)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("%w: %s must use https", ErrDiscovery, parsed.Host)
	default:
		return fmt.Errorf("%w: unsupported scheme %q", ErrDiscovery, parsed.Scheme)
	}
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func summarize(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 200 {
		return text[:200] + "…"
	}
	if text == "" {
		return "(empty body)"
	}
	return text
}
