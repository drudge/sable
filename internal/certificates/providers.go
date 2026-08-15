package certificates

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type dnsProvider interface {
	Present(context.Context, string, string, string) (func(context.Context) error, error)
}

func validateCredentials(provider string, credentials Credentials) error {
	switch provider {
	case "cloudflare":
		if strings.TrimSpace(credentials.APIToken) == "" {
			return errors.New("Cloudflare API token is required")
		}
	case "porkbun":
		if strings.TrimSpace(credentials.APIKey) == "" || strings.TrimSpace(credentials.Secret) == "" {
			return errors.New("Porkbun API key and secret key are required")
		}
	case "namecheap":
		if strings.TrimSpace(credentials.Username) == "" || strings.TrimSpace(credentials.APIKey) == "" || strings.TrimSpace(credentials.ClientIP) == "" {
			return errors.New("Namecheap username, API key, and allow-listed client IP are required")
		}
	case "godaddy":
		if strings.TrimSpace(credentials.APIToken) == "" {
			return errors.New("GoDaddy production API token is required")
		}
	case "digitalocean":
		if strings.TrimSpace(credentials.APIToken) == "" {
			return errors.New("DigitalOcean API token is required")
		}
	case "hetzner":
		if strings.TrimSpace(credentials.APIToken) == "" {
			return errors.New("Hetzner API token is required")
		}
	case "rfc2136":
		if strings.TrimSpace(credentials.Server) == "" || strings.TrimSpace(credentials.TSIGName) == "" || strings.TrimSpace(credentials.TSIGSecret) == "" {
			return errors.New("RFC 2136 server, TSIG key name, and TSIG secret are required")
		}
		if _, err := tsigAlgorithm(credentials.TSIGAlgorithm); err != nil {
			return err
		}
	case "route53":
		if strings.TrimSpace(credentials.AccessKeyID) == "" || strings.TrimSpace(credentials.SecretAccessKey) == "" || strings.TrimSpace(credentials.ZoneID) == "" {
			return errors.New("Route 53 access key ID, secret access key, and hosted zone ID are required")
		}
	case "ovh":
		if strings.TrimSpace(credentials.ApplicationKey) == "" || strings.TrimSpace(credentials.ApplicationSecret) == "" || strings.TrimSpace(credentials.ConsumerKey) == "" {
			return errors.New("OVHcloud application key, application secret, and consumer key are required")
		}
		if _, err := ovhEndpoint(credentials.Endpoint); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported DNS provider %q", provider)
	}
	return nil
}

func newDNSProvider(name string, credentials Credentials) (dnsProvider, error) {
	if err := validateCredentials(name, credentials); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	switch name {
	case "cloudflare":
		return &cloudflareProvider{credentials: credentials, client: client, baseURL: "https://api.cloudflare.com/client/v4"}, nil
	case "porkbun":
		return &porkbunProvider{credentials: credentials, client: client, baseURL: "https://api.porkbun.com/api/json/v3"}, nil
	case "namecheap":
		return &namecheapProvider{credentials: credentials, client: client, baseURL: "https://api.namecheap.com/xml.response"}, nil
	case "godaddy":
		return &godaddyProvider{credentials: credentials, client: client, baseURL: "https://api.godaddy.com/v3"}, nil
	case "digitalocean":
		return &digitalOceanProvider{credentials: credentials, client: client, baseURL: "https://api.digitalocean.com"}, nil
	case "hetzner":
		return &hetznerProvider{credentials: credentials, client: client, baseURL: "https://api.hetzner.cloud/v1"}, nil
	case "rfc2136":
		return &rfc2136Provider{credentials: credentials}, nil
	case "route53":
		return &route53Provider{credentials: credentials, client: client, baseURL: "https://route53.amazonaws.com", now: time.Now}, nil
	case "ovh":
		endpoint, _ := ovhEndpoint(credentials.Endpoint)
		return &ovhProvider{credentials: credentials, client: client, baseURL: endpoint, now: time.Now}, nil
	default:
		return nil, fmt.Errorf("unsupported DNS provider %q", name)
	}
}

type cloudflareProvider struct {
	credentials Credentials
	client      *http.Client
	baseURL     string
}

func (provider *cloudflareProvider) Present(ctx context.Context, zone, name, value string) (func(context.Context) error, error) {
	zoneID := provider.credentials.ZoneID
	if zoneID == "" {
		var listed struct {
			Success bool `json:"success"`
			Result  []struct {
				ID string `json:"id"`
			} `json:"result"`
		}
		if err := provider.request(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(zone), nil, &listed); err != nil {
			return nil, err
		}
		if len(listed.Result) != 1 {
			return nil, fmt.Errorf("Cloudflare zone lookup for %s returned %d zones", zone, len(listed.Result))
		}
		zoneID = listed.Result[0].ID
	}
	var created struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	body := map[string]any{"type": "TXT", "name": name, "content": value, "ttl": 60}
	if err := provider.request(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", body, &created); err != nil {
		return nil, err
	}
	if created.Result.ID == "" {
		return nil, errors.New("Cloudflare did not return the created record ID")
	}
	return func(cleanupContext context.Context) error {
		return provider.request(cleanupContext, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(created.Result.ID), nil, nil)
	}, nil
}

func (provider *cloudflareProvider) request(ctx context.Context, method, path string, body any, output any) error {
	return jsonRequest(ctx, provider.client, method, provider.baseURL+path, "Bearer "+provider.credentials.APIToken, body, output)
}

type porkbunProvider struct {
	credentials Credentials
	client      *http.Client
	baseURL     string
}

func (provider *porkbunProvider) Present(ctx context.Context, zone, name, value string) (func(context.Context) error, error) {
	relative := relativeName(name, zone)
	body := map[string]any{
		"apikey": provider.credentials.APIKey, "secretapikey": provider.credentials.Secret,
		"name": relative, "type": "TXT", "content": value, "ttl": "600",
	}
	var created struct {
		Status string `json:"status"`
		ID     any    `json:"id"`
	}
	if err := jsonRequest(ctx, provider.client, http.MethodPost, provider.baseURL+"/dns/create/"+url.PathEscape(zone), "", body, &created); err != nil {
		return nil, err
	}
	id := fmt.Sprint(created.ID)
	if created.Status != "SUCCESS" || id == "" || id == "<nil>" {
		return nil, errors.New("Porkbun did not return the created record ID")
	}
	return func(cleanupContext context.Context) error {
		cleanupBody := map[string]string{"apikey": provider.credentials.APIKey, "secretapikey": provider.credentials.Secret}
		return jsonRequest(cleanupContext, provider.client, http.MethodPost, provider.baseURL+"/dns/delete/"+url.PathEscape(zone)+"/"+url.PathEscape(id), "", cleanupBody, nil)
	}, nil
}

type godaddyProvider struct {
	credentials Credentials
	client      *http.Client
	baseURL     string
}

func (provider *godaddyProvider) Present(ctx context.Context, zone, name, value string) (func(context.Context) error, error) {
	body := map[string]any{"type": "TXT", "name": relativeName(name, zone), "data": value, "ttl": 600}
	endpoint := provider.baseURL + "/domains/zones/" + url.PathEscape(zone) + "/dns-records"
	request, err := jsonHTTPProviderRequest(ctx, http.MethodPost, endpoint, "Bearer "+provider.credentials.APIToken, body)
	if err != nil {
		return nil, err
	}
	response, err := provider.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("create GoDaddy TXT record: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, responseError("GoDaddy", response)
	}
	var created struct {
		RecordID string `json:"recordId"`
	}
	if response.Body != nil {
		_ = json.NewDecoder(response.Body).Decode(&created)
	}
	recordID := strings.TrimSpace(created.RecordID)
	if recordID == "" {
		location := strings.TrimRight(response.Header.Get("Location"), "/")
		recordID = path.Base(location)
		if recordID == "." || recordID == "/" {
			recordID = ""
		}
	}
	if recordID == "" {
		return nil, errors.New("GoDaddy did not return the created DNS record ID")
	}
	return func(cleanupContext context.Context) error {
		cleanupRequest, err := http.NewRequestWithContext(cleanupContext, http.MethodDelete, endpoint+"/"+url.PathEscape(recordID), nil)
		if err != nil {
			return err
		}
		cleanupRequest.Header.Set("Authorization", "Bearer "+provider.credentials.APIToken)
		cleanupResponse, err := provider.client.Do(cleanupRequest)
		if err != nil {
			return err
		}
		defer cleanupResponse.Body.Close()
		if cleanupResponse.StatusCode < 200 || cleanupResponse.StatusCode >= 300 {
			return responseError("GoDaddy", cleanupResponse)
		}
		return nil
	}, nil
}

type namecheapProvider struct {
	credentials Credentials
	client      *http.Client
	baseURL     string
}

type namecheapHost struct {
	HostID  string `xml:"HostId,attr"`
	Name    string `xml:"Name,attr"`
	Type    string `xml:"Type,attr"`
	Address string `xml:"Address,attr"`
	MXPref  string `xml:"MXPref,attr"`
	TTL     string `xml:"TTL,attr"`
}

func (provider *namecheapProvider) Present(ctx context.Context, zone, name, value string) (func(context.Context) error, error) {
	hosts, err := provider.hosts(ctx, zone)
	if err != nil {
		return nil, err
	}
	challenge := namecheapHost{Name: relativeName(name, zone), Type: "TXT", Address: value, TTL: "600"}
	if err := provider.setHosts(ctx, zone, append(hosts, challenge)); err != nil {
		return nil, err
	}
	return func(cleanupContext context.Context) error {
		current, err := provider.hosts(cleanupContext, zone)
		if err != nil {
			return err
		}
		filtered := current[:0]
		for _, host := range current {
			if strings.EqualFold(host.Name, challenge.Name) && strings.EqualFold(host.Type, "TXT") && host.Address == value {
				continue
			}
			filtered = append(filtered, host)
		}
		return provider.setHosts(cleanupContext, zone, filtered)
	}, nil
}

func (provider *namecheapProvider) hosts(ctx context.Context, zone string) ([]namecheapHost, error) {
	parameters, err := provider.parameters(zone, "namecheap.domains.dns.getHosts")
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.baseURL+"?"+parameters.Encode(), nil)
	if err != nil {
		return nil, err
	}
	response, err := provider.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("get Namecheap hosts: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, responseError("Namecheap", response)
	}
	var envelope struct {
		Status string `xml:"Status,attr"`
		Errors []struct {
			Message string `xml:",chardata"`
		} `xml:"Errors>Error"`
		Hosts []namecheapHost `xml:"CommandResponse>DomainDNSGetHostsResult>host"`
	}
	if err := xml.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode Namecheap hosts: %w", err)
	}
	if !strings.EqualFold(envelope.Status, "OK") {
		return nil, fmt.Errorf("Namecheap rejected DNS request: %s", firstNamecheapError(envelope.Errors))
	}
	return envelope.Hosts, nil
}

func (provider *namecheapProvider) setHosts(ctx context.Context, zone string, hosts []namecheapHost) error {
	parameters, err := provider.parameters(zone, "namecheap.domains.dns.setHosts")
	if err != nil {
		return err
	}
	for index, host := range hosts {
		number := strconv.Itoa(index + 1)
		parameters.Set("HostName"+number, host.Name)
		parameters.Set("RecordType"+number, host.Type)
		parameters.Set("Address"+number, host.Address)
		if host.MXPref != "" {
			parameters.Set("MXPref"+number, host.MXPref)
		}
		if host.TTL != "" {
			parameters.Set("TTL"+number, host.TTL)
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.baseURL, strings.NewReader(parameters.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := provider.client.Do(request)
	if err != nil {
		return fmt.Errorf("set Namecheap hosts: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return responseError("Namecheap", response)
	}
	var envelope struct {
		Status string `xml:"Status,attr"`
		Errors []struct {
			Message string `xml:",chardata"`
		} `xml:"Errors>Error"`
	}
	if err := xml.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("decode Namecheap update: %w", err)
	}
	if !strings.EqualFold(envelope.Status, "OK") {
		return fmt.Errorf("Namecheap rejected DNS update: %s", firstNamecheapError(envelope.Errors))
	}
	return nil
}

func (provider *namecheapProvider) parameters(zone, command string) (url.Values, error) {
	suffix, _ := publicsuffix.PublicSuffix(zone)
	domain := strings.TrimSuffix(zone, "."+suffix)
	if domain == "" || suffix == "" {
		return nil, fmt.Errorf("cannot split Namecheap zone %q into SLD and TLD", zone)
	}
	return url.Values{
		"ApiUser": {provider.credentials.Username}, "ApiKey": {provider.credentials.APIKey},
		"UserName": {provider.credentials.Username}, "ClientIp": {provider.credentials.ClientIP},
		"Command": {command}, "SLD": {domain}, "TLD": {suffix},
	}, nil
}

func jsonRequest(ctx context.Context, client *http.Client, method, endpoint, authorization string, body, output any) error {
	request, err := jsonHTTPProviderRequest(ctx, method, endpoint, authorization, body)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("DNS provider request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError("DNS provider", response)
	}
	if output == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		return fmt.Errorf("decode DNS provider response: %w", err)
	}
	return nil
}

func jsonHTTPProviderRequest(ctx context.Context, method, endpoint, authorization string, body any) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	return request, nil
}

func responseError(provider string, response *http.Response) error {
	contents, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	message := strings.TrimSpace(string(contents))
	if message == "" {
		message = response.Status
	}
	return fmt.Errorf("%s API returned %s: %s", provider, response.Status, message)
}

func relativeName(name, zone string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

func firstNamecheapError(errors []struct {
	Message string `xml:",chardata"`
}) string {
	if len(errors) == 0 {
		return "unknown error"
	}
	return strings.TrimSpace(errors[0].Message)
}
