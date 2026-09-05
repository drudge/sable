package dnsprovider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type digitalOceanProvider struct {
	credentials Credentials
	client      *http.Client
	baseURL     string
}

func (provider *digitalOceanProvider) Present(ctx context.Context, zone, name, value string) (func(context.Context) error, error) {
	endpoint := provider.baseURL + "/v2/domains/" + url.PathEscape(zone) + "/records"
	var created struct {
		Record struct {
			ID int64 `json:"id"`
		} `json:"domain_record"`
	}
	body := map[string]any{"type": "TXT", "name": relativeName(name, zone), "data": value, "ttl": 60}
	if err := jsonRequest(ctx, provider.client, http.MethodPost, endpoint, "Bearer "+provider.credentials.APIToken, body, &created); err != nil {
		return nil, err
	}
	if created.Record.ID == 0 {
		return nil, errors.New("DigitalOcean did not return the created record ID")
	}
	return func(cleanupContext context.Context) error {
		return jsonRequest(cleanupContext, provider.client, http.MethodDelete, endpoint+"/"+strconv.FormatInt(created.Record.ID, 10), "Bearer "+provider.credentials.APIToken, nil, nil)
	}, nil
}

type hetznerProvider struct {
	credentials Credentials
	client      *http.Client
	baseURL     string
}

func (provider *hetznerProvider) Present(ctx context.Context, zone, name, value string) (func(context.Context) error, error) {
	zoneID := strings.TrimSpace(provider.credentials.ZoneID)
	if zoneID == "" {
		zoneID = zone
	}
	recordName := relativeName(name, zone)
	endpoint := provider.baseURL + "/zones/" + url.PathEscape(zoneID) + "/rrsets/" + url.PathEscape(recordName) + "/TXT/actions/"
	body := map[string]any{"records": []map[string]string{{"value": value}}}
	if err := jsonRequest(ctx, provider.client, http.MethodPost, endpoint+"add_records", "Bearer "+provider.credentials.APIToken, body, nil); err != nil {
		return nil, err
	}
	return func(cleanupContext context.Context) error {
		return jsonRequest(cleanupContext, provider.client, http.MethodPost, endpoint+"remove_records", "Bearer "+provider.credentials.APIToken, body, nil)
	}, nil
}

type rfc2136Provider struct {
	credentials Credentials
}

func (provider *rfc2136Provider) Present(ctx context.Context, zone, name, value string) (func(context.Context) error, error) {
	record := &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{value},
	}
	if err := provider.update(ctx, zone, func(message *dns.Msg) { message.Insert([]dns.RR{record}) }); err != nil {
		return nil, err
	}
	return func(cleanupContext context.Context) error {
		return provider.update(cleanupContext, zone, func(message *dns.Msg) { message.Remove([]dns.RR{record}) })
	}, nil
}

func (provider *rfc2136Provider) update(ctx context.Context, zone string, operation func(*dns.Msg)) error {
	algorithm, err := tsigAlgorithm(provider.credentials.TSIGAlgorithm)
	if err != nil {
		return err
	}
	keyName := dns.Fqdn(provider.credentials.TSIGName)
	message := new(dns.Msg)
	message.SetUpdate(dns.Fqdn(zone))
	operation(message)
	message.SetTsig(keyName, algorithm, 300, time.Now().Unix())
	client := &dns.Client{TsigSecret: map[string]string{keyName: provider.credentials.TSIGSecret}}
	response, _, err := client.ExchangeContext(ctx, message, dnsServerAddress(provider.credentials.Server))
	if err != nil {
		return fmt.Errorf("RFC 2136 update: %w", err)
	}
	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("RFC 2136 update returned %s", dns.RcodeToString[response.Rcode])
	}
	return nil
}

func tsigAlgorithm(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "hmac-sha256", "hmac-sha256.":
		return dns.HmacSHA256, nil
	case "hmac-sha384", "hmac-sha384.":
		return dns.HmacSHA384, nil
	case "hmac-sha512", "hmac-sha512.":
		return dns.HmacSHA512, nil
	default:
		return "", errors.New("RFC 2136 TSIG algorithm must be hmac-sha256, hmac-sha384, or hmac-sha512")
	}
}

func dnsServerAddress(value string) string {
	value = strings.TrimSpace(value)
	if _, _, err := net.SplitHostPort(value); err == nil {
		return value
	}
	return net.JoinHostPort(strings.Trim(value, "[]"), "53")
}

type route53Provider struct {
	credentials Credentials
	client      *http.Client
	baseURL     string
	now         func() time.Time
}

type route53RecordSet struct {
	Name    string          `xml:"Name"`
	Type    string          `xml:"Type"`
	TTL     int             `xml:"TTL"`
	Records []route53Record `xml:"ResourceRecords>ResourceRecord"`
}

type route53Record struct {
	Value string `xml:"Value"`
}

type route53ChangeRequest struct {
	XMLName xml.Name `xml:"ChangeResourceRecordSetsRequest"`
	XMLNS   string   `xml:"xmlns,attr"`
	Changes []struct {
		Action string           `xml:"Action"`
		Set    route53RecordSet `xml:"ResourceRecordSet"`
	} `xml:"ChangeBatch>Changes>Change"`
}

func (provider *route53Provider) Present(ctx context.Context, _ string, name, value string) (func(context.Context) error, error) {
	current, err := provider.recordSet(ctx, name)
	if err != nil {
		return nil, err
	}
	encodedValue := strconv.Quote(value)
	current = appendUniqueRoute53Value(current, encodedValue)
	if err := provider.change(ctx, "UPSERT", name, current); err != nil {
		return nil, err
	}
	return func(cleanupContext context.Context) error {
		latest, err := provider.recordSet(cleanupContext, name)
		if err != nil {
			return err
		}
		remaining := make([]string, 0, len(latest))
		for _, candidate := range latest {
			if candidate != encodedValue {
				remaining = append(remaining, candidate)
			}
		}
		if len(remaining) == len(latest) {
			return nil
		}
		if len(remaining) == 0 {
			return provider.change(cleanupContext, "DELETE", name, latest)
		}
		return provider.change(cleanupContext, "UPSERT", name, remaining)
	}, nil
}

func (provider *route53Provider) recordSet(ctx context.Context, name string) ([]string, error) {
	values, _, err := provider.recordSetByType(ctx, name, "TXT")
	return values, err
}

func (provider *route53Provider) change(ctx context.Context, action, name string, values []string) error {
	return provider.changeRecordSet(ctx, action, name, "TXT", 60, values)
}

func (provider *route53Provider) rrsetPath() string {
	zoneID := strings.TrimPrefix(strings.TrimSpace(provider.credentials.ZoneID), "/hostedzone/")
	return "/2013-04-01/hostedzone/" + url.PathEscape(zoneID) + "/rrset"
}

func (provider *route53Provider) request(ctx context.Context, method, requestPath string, query url.Values, body []byte) (*http.Request, error) {
	endpoint := provider.baseURL + requestPath
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	provider.sign(request, body)
	return request, nil
}

func (provider *route53Provider) sign(request *http.Request, body []byte) {
	now := provider.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	payloadHash := sha256Hex(body)
	canonicalHeaders := "host:" + request.URL.Host + "\n" + "x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-date"
	request.Header.Set("X-Amz-Date", amzDate)
	if provider.credentials.SessionToken != "" {
		canonicalHeaders += "x-amz-security-token:" + strings.TrimSpace(provider.credentials.SessionToken) + "\n"
		signedHeaders += ";x-amz-security-token"
		request.Header.Set("X-Amz-Security-Token", provider.credentials.SessionToken)
	}
	canonicalRequest := strings.Join([]string{request.Method, request.URL.EscapedPath(), request.URL.Query().Encode(), canonicalHeaders, signedHeaders, payloadHash}, "\n")
	scope := date + "/us-east-1/route53/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
	dateKey := hmacSHA256([]byte("AWS4"+provider.credentials.SecretAccessKey), date)
	regionKey := hmacSHA256(dateKey, "us-east-1")
	serviceKey := hmacSHA256(regionKey, "route53")
	signingKey := hmacSHA256(serviceKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+provider.credentials.AccessKeyID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func appendUniqueRoute53Value(values []string, value string) []string {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	values = append(values, value)
	sort.Strings(values)
	return values
}

func sha256Hex(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

func hmacSHA256(key []byte, value string) []byte {
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write([]byte(value))
	return hash.Sum(nil)
}

type ovhProvider struct {
	credentials Credentials
	client      *http.Client
	baseURL     string
	now         func() time.Time
}

func (provider *ovhProvider) Present(ctx context.Context, zone, name, value string) (func(context.Context) error, error) {
	var recordID int64
	body := map[string]any{"fieldType": "TXT", "subDomain": relativeName(name, zone), "target": value, "ttl": 60}
	if err := provider.request(ctx, http.MethodPost, "/domain/zone/"+url.PathEscape(zone)+"/record", body, &recordID); err != nil {
		return nil, err
	}
	if recordID == 0 {
		return nil, errors.New("OVHcloud did not return the created record ID")
	}
	if err := provider.refresh(ctx, zone); err != nil {
		return nil, err
	}
	return func(cleanupContext context.Context) error {
		path := "/domain/zone/" + url.PathEscape(zone) + "/record/" + strconv.FormatInt(recordID, 10)
		if err := provider.request(cleanupContext, http.MethodDelete, path, nil, nil); err != nil {
			return err
		}
		return provider.refresh(cleanupContext, zone)
	}, nil
}

func (provider *ovhProvider) refresh(ctx context.Context, zone string) error {
	return provider.request(ctx, http.MethodPost, "/domain/zone/"+url.PathEscape(zone)+"/refresh", struct{}{}, nil)
}

func (provider *ovhProvider) request(ctx context.Context, method, requestPath string, body, output any) error {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	endpoint := provider.baseURL + requestPath
	timestamp := strconv.FormatInt(provider.now().Unix(), 10)
	signatureSource := provider.credentials.ApplicationSecret + "+" + provider.credentials.ConsumerKey + "+" + method + "+" + endpoint + "+" + string(encoded) + "+" + timestamp
	digest := sha1.Sum([]byte(signatureSource))
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Ovh-Application", provider.credentials.ApplicationKey)
	request.Header.Set("X-Ovh-Consumer", provider.credentials.ConsumerKey)
	request.Header.Set("X-Ovh-Timestamp", timestamp)
	request.Header.Set("X-Ovh-Signature", "$1$"+hex.EncodeToString(digest[:]))
	response, err := provider.client.Do(request)
	if err != nil {
		return fmt.Errorf("OVHcloud DNS request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError("OVHcloud", response)
	}
	if output != nil && response.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(response.Body).Decode(output); err != nil && err != io.EOF {
			return fmt.Errorf("decode OVHcloud response: %w", err)
		}
	}
	return nil
}

func ovhEndpoint(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "ovh-eu":
		return "https://eu.api.ovh.com/1.0", nil
	case "ovh-ca":
		return "https://ca.api.ovh.com/1.0", nil
	case "ovh-us":
		return "https://api.us.ovhcloud.com/1.0", nil
	default:
		return "", errors.New("OVHcloud endpoint must be Europe, Canada, or United States")
	}
}
