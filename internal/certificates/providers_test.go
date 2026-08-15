package certificates

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestCloudflareProviderCreatesAndRemovesExactChallengeRecord(t *testing.T) {
	var paths []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		paths = append(paths, request.Method+" "+request.URL.Path)
		if request.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		body := `{"success":true,"result":{"id":"record-1"}}`
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	provider := &cloudflareProvider{
		credentials: Credentials{APIToken: "token", ZoneID: "zone-1"}, client: client, baseURL: "https://cloudflare.test/client/v4",
	}
	cleanup, err := provider.Present(context.Background(), "example.com", "_acme-challenge.example.com", "challenge")
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"POST /client/v4/zones/zone-1/dns_records",
		"DELETE /client/v4/zones/zone-1/dns_records/record-1",
	}
	if strings.Join(paths, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("requests = %#v", paths)
	}
}

func TestGoDaddyProviderUsesV3RecordIdentity(t *testing.T) {
	var paths []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		paths = append(paths, request.Method+" "+request.URL.Path)
		body := `{"recordId":"record-7"}`
		status := http.StatusCreated
		if request.Method == http.MethodDelete {
			body = ""
			status = http.StatusNoContent
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	provider := &godaddyProvider{
		credentials: Credentials{APIToken: "token"}, client: client, baseURL: "https://godaddy.test/v3",
	}
	cleanup, err := provider.Present(context.Background(), "example.com", "_acme-challenge.example.com", "challenge")
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"POST /v3/domains/zones/example.com/dns-records",
		"DELETE /v3/domains/zones/example.com/dns-records/record-7",
	}
	if strings.Join(paths, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("requests = %#v", paths)
	}
}

func TestProviderCredentialValidation(t *testing.T) {
	tests := []struct {
		name        string
		credentials Credentials
	}{
		{"cloudflare", Credentials{APIToken: "token"}},
		{"porkbun", Credentials{APIKey: "key", Secret: "secret"}},
		{"namecheap", Credentials{Username: "user", APIKey: "key", ClientIP: "203.0.113.10"}},
		{"godaddy", Credentials{APIToken: "token"}},
		{"digitalocean", Credentials{APIToken: "token"}},
		{"hetzner", Credentials{APIToken: "token"}},
		{"rfc2136", Credentials{Server: "dns.example.com:53", TSIGName: "acme.", TSIGSecret: "secret", TSIGAlgorithm: "hmac-sha256"}},
		{"route53", Credentials{AccessKeyID: "access", SecretAccessKey: "secret", ZoneID: "zone"}},
		{"ovh", Credentials{ApplicationKey: "application", ApplicationSecret: "secret", ConsumerKey: "consumer", Endpoint: "ovh-eu"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateCredentials(test.name, test.credentials); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := validateCredentials("cloudflare", Credentials{}); err == nil {
		t.Fatal("empty Cloudflare credentials were accepted")
	}
}

func TestDigitalOceanProviderCreatesAndRemovesRecordByID(t *testing.T) {
	var requests []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.Method+" "+request.URL.Path)
		if request.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		status, body := http.StatusCreated, `{"domain_record":{"id":28448433}}`
		if request.Method == http.MethodDelete {
			status, body = http.StatusNoContent, ""
		}
		return httpResponse(status, body), nil
	})}
	provider := &digitalOceanProvider{credentials: Credentials{APIToken: "token"}, client: client, baseURL: "https://digitalocean.test"}
	cleanup, err := provider.Present(context.Background(), "example.com", "_acme-challenge.example.com", "challenge")
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	expected := []string{"POST /v2/domains/example.com/records", "DELETE /v2/domains/example.com/records/28448433"}
	if strings.Join(requests, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("requests = %#v", requests)
	}
}

func TestHetznerProviderAddsAndRemovesOnlyChallengeValue(t *testing.T) {
	var requests []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.Method+" "+request.URL.Path)
		if request.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		return httpResponse(http.StatusCreated, `{}`), nil
	})}
	provider := &hetznerProvider{credentials: Credentials{APIToken: "token", ZoneID: "zone-1"}, client: client, baseURL: "https://hetzner.test/v1"}
	cleanup, err := provider.Present(context.Background(), "example.com", "_acme-challenge.example.com", "challenge")
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"POST /v1/zones/zone-1/rrsets/_acme-challenge/TXT/actions/add_records",
		"POST /v1/zones/zone-1/rrsets/_acme-challenge/TXT/actions/remove_records",
	}
	if strings.Join(requests, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("requests = %#v", requests)
	}
}

func TestRoute53ProviderPreservesOtherTXTValues(t *testing.T) {
	var requests []string
	listCount := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.Method+" "+request.URL.Path)
		if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=access/") {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		if request.Method == http.MethodGet {
			listCount++
			body := `<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets></ResourceRecordSets></ListResourceRecordSetsResponse>`
			if listCount == 2 {
				body = `<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets><ResourceRecordSet><Name>_acme-challenge.example.com.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>"challenge"</Value></ResourceRecord><ResourceRecord><Value>"existing"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>`
			}
			return httpResponse(http.StatusOK, body), nil
		}
		body, _ := io.ReadAll(request.Body)
		if listCount == 2 && (!strings.Contains(string(body), "UPSERT") || !strings.Contains(string(body), "&#34;existing&#34;")) {
			t.Errorf("cleanup body did not preserve existing value: %s", body)
		}
		return httpResponse(http.StatusOK, `<ChangeResourceRecordSetsResponse/>`), nil
	})}
	provider := &route53Provider{
		credentials: Credentials{AccessKeyID: "access", SecretAccessKey: "secret", ZoneID: "/hostedzone/Z123"},
		client:      client, baseURL: "https://route53.test", now: func() time.Time { return time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC) },
	}
	cleanup, err := provider.Present(context.Background(), "example.com", "_acme-challenge.example.com", "challenge")
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 4 {
		t.Fatalf("requests = %#v", requests)
	}
}

func TestOVHProviderRefreshesAfterCreateAndCleanup(t *testing.T) {
	var requests []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.Method+" "+request.URL.Path)
		if !strings.HasPrefix(request.Header.Get("X-Ovh-Signature"), "$1$") {
			t.Errorf("signature = %q", request.Header.Get("X-Ovh-Signature"))
		}
		if strings.HasSuffix(request.URL.Path, "/record") {
			return httpResponse(http.StatusOK, `42`), nil
		}
		return httpResponse(http.StatusOK, `{}`), nil
	})}
	provider := &ovhProvider{
		credentials: Credentials{ApplicationKey: "application", ApplicationSecret: "secret", ConsumerKey: "consumer"},
		client:      client, baseURL: "https://ovh.test/1.0", now: func() time.Time { return time.Unix(1_786_620_000, 0) },
	}
	cleanup, err := provider.Present(context.Background(), "example.com", "_acme-challenge.example.com", "challenge")
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"POST /1.0/domain/zone/example.com/record",
		"POST /1.0/domain/zone/example.com/refresh",
		"DELETE /1.0/domain/zone/example.com/record/42",
		"POST /1.0/domain/zone/example.com/refresh",
	}
	if strings.Join(requests, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("requests = %#v", requests)
	}
}

func httpResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestRelativeDNSName(t *testing.T) {
	if got := relativeName("_acme-challenge.dns.example.com.", "example.com."); got != "_acme-challenge.dns" {
		t.Fatalf("relative name = %q", got)
	}
}
