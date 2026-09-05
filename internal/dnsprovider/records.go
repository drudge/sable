package dnsprovider

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	TypeA    = "A"
	TypeAAAA = "AAAA"

	defaultMinimumRecordTTL = 60
	defaultMaximumRecordTTL = 86400
)

// RecordTTLRange returns the provider's accepted TTL range. The narrower
// ranges prevent a configuration from repeatedly failing at publication time.
func RecordTTLRange(provider string) (uint32, uint32) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "godaddy", "porkbun":
		return 600, defaultMaximumRecordTTL
	case "namecheap":
		return defaultMinimumRecordTTL, 60000
	default:
		return defaultMinimumRecordTTL, defaultMaximumRecordTTL
	}
}

// ValidateRecordTTL checks a TTL against the selected provider's limits.
func ValidateRecordTTL(provider string, ttl uint32) error {
	minimum, maximum := RecordTTLRange(provider)
	if ttl < minimum || ttl > maximum {
		return fmt.Errorf("must be between %d and %d for %s", minimum, maximum, provider)
	}
	return nil
}

// Record is a single-value A or AAAA RRset that Sable owns at an external
// provider. EnsureRecord replaces every value at the same owner and type.
type Record struct {
	Zone  string
	Name  string
	Type  string
	Value string
	TTL   uint32
}

func normalizeRecord(record Record) (Record, error) {
	record.Zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record.Zone)), ".")
	record.Name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record.Name)), ".")
	record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
	record.Value = strings.TrimSpace(record.Value)
	if record.Zone == "" || record.Name == "" || (record.Name != record.Zone && !strings.HasSuffix(record.Name, "."+record.Zone)) {
		return Record{}, errors.New("external DNS record name must belong to its zone")
	}
	address, err := netip.ParseAddr(record.Value)
	if err != nil {
		return Record{}, fmt.Errorf("parse external DNS record address: %w", err)
	}
	switch record.Type {
	case TypeA:
		if !address.Is4() {
			return Record{}, errors.New("external DNS A record requires an IPv4 address")
		}
	case TypeAAAA:
		if !address.Is6() || address.Is4In6() {
			return Record{}, errors.New("external DNS AAAA record requires an IPv6 address")
		}
	default:
		return Record{}, errors.New("external DNS record type must be A or AAAA")
	}
	if record.TTL == 0 {
		return Record{}, errors.New("external DNS record TTL must be positive")
	}
	record.Value = address.String()
	return record, nil
}

func sameSingleRecord(values []string, value string, actualTTL int, wantedTTL uint32) bool {
	return len(values) == 1 && strings.TrimSpace(values[0]) == value && actualTTL == int(wantedTTL)
}

func (provider *cloudflareProvider) EnsureRecord(ctx context.Context, record Record) (bool, error) {
	record, err := normalizeRecord(record)
	if err != nil {
		return false, err
	}
	zoneID, err := provider.cloudflareZoneID(ctx, record.Zone)
	if err != nil {
		return false, err
	}
	endpoint := "/zones/" + url.PathEscape(zoneID) + "/dns_records"
	var listed struct {
		Result []struct {
			ID      string `json:"id"`
			Content string `json:"content"`
			TTL     int    `json:"ttl"`
			Proxied bool   `json:"proxied"`
		} `json:"result"`
	}
	query := "?type=" + url.QueryEscape(record.Type) + "&name=" + url.QueryEscape(record.Name) + "&per_page=5000000"
	if err := provider.request(ctx, http.MethodGet, endpoint+query, nil, &listed); err != nil {
		return false, err
	}
	values := make([]string, 0, len(listed.Result))
	for _, existing := range listed.Result {
		values = append(values, existing.Content)
	}
	actualTTL := 0
	if len(listed.Result) == 1 {
		actualTTL = listed.Result[0].TTL
		if listed.Result[0].Proxied {
			// Cloudflare represents an automatic proxied TTL as 1. Preserve the
			// proxy setting and do not rewrite an otherwise current record.
			actualTTL = int(record.TTL)
		}
	}
	if len(listed.Result) == 1 && sameSingleRecord(values, record.Value, actualTTL, record.TTL) {
		return false, nil
	}
	body := map[string]any{"type": record.Type, "name": record.Name, "content": record.Value, "ttl": record.TTL}
	if len(listed.Result) == 0 {
		if err := provider.request(ctx, http.MethodPost, endpoint, body, nil); err != nil {
			return false, err
		}
		return true, nil
	}
	if listed.Result[0].Proxied {
		body["ttl"] = 1
	}
	if err := provider.request(ctx, http.MethodPatch, endpoint+"/"+url.PathEscape(listed.Result[0].ID), body, nil); err != nil {
		return false, err
	}
	for _, duplicate := range listed.Result[1:] {
		if err := provider.request(ctx, http.MethodDelete, endpoint+"/"+url.PathEscape(duplicate.ID), nil, nil); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (provider *cloudflareProvider) cloudflareZoneID(ctx context.Context, zone string) (string, error) {
	if zoneID := strings.TrimSpace(provider.credentials.ZoneID); zoneID != "" {
		return zoneID, nil
	}
	var listed struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := provider.request(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(zone), nil, &listed); err != nil {
		return "", err
	}
	if len(listed.Result) != 1 {
		return "", fmt.Errorf("Cloudflare zone lookup for %s returned %d zones", zone, len(listed.Result))
	}
	return listed.Result[0].ID, nil
}

func (provider *porkbunProvider) EnsureRecord(ctx context.Context, record Record) (bool, error) {
	record, err := normalizeRecord(record)
	if err != nil {
		return false, err
	}
	relative := relativeName(record.Name, record.Zone)
	if relative == "@" {
		relative = ""
	}
	authentication := map[string]any{"apikey": provider.credentials.APIKey, "secretapikey": provider.credentials.Secret}
	lookupPath := porkbunRecordPath("retrieveByNameType", record.Zone, record.Type, relative)
	var listed struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Records []struct {
			ID      any    `json:"id"`
			Content string `json:"content"`
			TTL     any    `json:"ttl"`
		} `json:"records"`
	}
	if err := jsonRequest(ctx, provider.client, http.MethodPost, provider.baseURL+lookupPath, "", authentication, &listed); err != nil {
		return false, err
	}
	if err := porkbunStatusError(listed.Status, listed.Message); err != nil {
		return false, err
	}
	values := make([]string, 0, len(listed.Records))
	actualTTL := 0
	for _, existing := range listed.Records {
		values = append(values, existing.Content)
		if parsed, parseErr := strconv.Atoi(fmt.Sprint(existing.TTL)); parseErr == nil {
			actualTTL = parsed
		}
	}
	if sameSingleRecord(values, record.Value, actualTTL, record.TTL) {
		return false, nil
	}
	body := map[string]any{
		"apikey": provider.credentials.APIKey, "secretapikey": provider.credentials.Secret,
		"content": record.Value, "ttl": strconv.FormatUint(uint64(record.TTL), 10),
	}
	if len(listed.Records) == 0 {
		body["name"] = relative
		body["type"] = record.Type
		endpoint := provider.baseURL + "/dns/create/" + url.PathEscape(record.Zone)
		if err := provider.porkbunWrite(ctx, endpoint, body); err != nil {
			return false, err
		}
		return true, nil
	}
	firstID := fmt.Sprint(listed.Records[0].ID)
	if firstID == "" || firstID == "<nil>" {
		return false, errors.New("Porkbun did not return the existing record ID")
	}
	endpoint := provider.baseURL + "/dns/edit/" + url.PathEscape(record.Zone) + "/" + url.PathEscape(firstID)
	if err := provider.porkbunWrite(ctx, endpoint, body); err != nil {
		return false, err
	}
	for _, duplicate := range listed.Records[1:] {
		duplicateID := fmt.Sprint(duplicate.ID)
		if duplicateID == "" || duplicateID == "<nil>" {
			return false, errors.New("Porkbun did not return a duplicate record ID")
		}
		deleteEndpoint := provider.baseURL + "/dns/delete/" + url.PathEscape(record.Zone) + "/" + url.PathEscape(duplicateID)
		authentication := map[string]any{"apikey": provider.credentials.APIKey, "secretapikey": provider.credentials.Secret}
		if err := provider.porkbunWrite(ctx, deleteEndpoint, authentication); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (provider *porkbunProvider) porkbunWrite(ctx context.Context, endpoint string, body any) error {
	var changed struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := jsonRequest(ctx, provider.client, http.MethodPost, endpoint, "", body, &changed); err != nil {
		return err
	}
	return porkbunStatusError(changed.Status, changed.Message)
}

func porkbunStatusError(status, message string) error {
	if status == "SUCCESS" {
		return nil
	}
	if strings.TrimSpace(message) == "" {
		message = "request was not successful"
	}
	return fmt.Errorf("Porkbun: %s", message)
}

func porkbunRecordPath(operation, zone, recordType, relative string) string {
	path := "/dns/" + operation + "/" + url.PathEscape(zone) + "/" + url.PathEscape(recordType)
	if relative != "" {
		path += "/" + url.PathEscape(relative)
	}
	return path
}

func (provider *godaddyProvider) EnsureRecord(ctx context.Context, record Record) (bool, error) {
	record, err := normalizeRecord(record)
	if err != nil {
		return false, err
	}
	endpoint := provider.baseURL + "/domains/zones/" + url.PathEscape(record.Zone) + "/dns-records"
	request, err := jsonHTTPProviderRequest(ctx, http.MethodGet, endpoint+"?type="+record.Type+"&name="+url.QueryEscape(relativeName(record.Name, record.Zone)), "Bearer "+provider.credentials.APIToken, nil)
	if err != nil {
		return false, err
	}
	response, err := provider.client.Do(request)
	if err != nil {
		return false, fmt.Errorf("list GoDaddy DNS records: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, responseError("GoDaddy", response)
	}
	var listed struct {
		Items []struct {
			RecordID string `json:"recordId"`
			Data     string `json:"data"`
			TTL      int    `json:"ttl"`
		} `json:"items"`
	}
	if err := json.NewDecoder(response.Body).Decode(&listed); err != nil && err != io.EOF {
		return false, fmt.Errorf("decode GoDaddy DNS records: %w", err)
	}
	values := make([]string, 0, len(listed.Items))
	for _, existing := range listed.Items {
		values = append(values, existing.Data)
	}
	if len(listed.Items) == 1 && sameSingleRecord(values, record.Value, listed.Items[0].TTL, record.TTL) {
		return false, nil
	}
	body := map[string]any{"type": record.Type, "name": relativeName(record.Name, record.Zone), "data": record.Value, "ttl": record.TTL}
	if len(listed.Items) == 0 {
		return true, provider.doGoDaddyRecordRequest(ctx, http.MethodPost, endpoint, body)
	}
	if err := provider.doGoDaddyRecordRequest(ctx, http.MethodPut, endpoint+"/"+url.PathEscape(listed.Items[0].RecordID), body); err != nil {
		return false, err
	}
	for _, duplicate := range listed.Items[1:] {
		if err := provider.doGoDaddyRecordRequest(ctx, http.MethodDelete, endpoint+"/"+url.PathEscape(duplicate.RecordID), nil); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (provider *godaddyProvider) doGoDaddyRecordRequest(ctx context.Context, method, endpoint string, body any) error {
	request, err := jsonHTTPProviderRequest(ctx, method, endpoint, "Bearer "+provider.credentials.APIToken, body)
	if err != nil {
		return err
	}
	response, err := provider.client.Do(request)
	if err != nil {
		return fmt.Errorf("change GoDaddy DNS record: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError("GoDaddy", response)
	}
	return nil
}

func (provider *namecheapProvider) EnsureRecord(ctx context.Context, record Record) (bool, error) {
	record, err := normalizeRecord(record)
	if err != nil {
		return false, err
	}
	hosts, err := provider.hosts(ctx, record.Zone)
	if err != nil {
		return false, err
	}
	relative := relativeName(record.Name, record.Zone)
	matching := make([]namecheapHost, 0)
	retained := make([]namecheapHost, 0, len(hosts)+1)
	for _, host := range hosts {
		if strings.EqualFold(host.Name, relative) && strings.EqualFold(host.Type, record.Type) {
			matching = append(matching, host)
			continue
		}
		retained = append(retained, host)
	}
	actualTTL := 0
	if len(matching) == 1 {
		actualTTL, _ = strconv.Atoi(matching[0].TTL)
	}
	if len(matching) == 1 && sameSingleRecord([]string{matching[0].Address}, record.Value, actualTTL, record.TTL) {
		return false, nil
	}
	retained = append(retained, namecheapHost{
		Name: relative, Type: record.Type, Address: record.Value,
		TTL: strconv.FormatUint(uint64(record.TTL), 10),
	})
	if err := provider.setHosts(ctx, record.Zone, retained); err != nil {
		return false, err
	}
	return true, nil
}

func (provider *digitalOceanProvider) EnsureRecord(ctx context.Context, record Record) (bool, error) {
	record, err := normalizeRecord(record)
	if err != nil {
		return false, err
	}
	endpoint := provider.baseURL + "/v2/domains/" + url.PathEscape(record.Zone) + "/records"
	query := "?type=" + record.Type + "&name=" + url.QueryEscape(record.Name) + "&per_page=200"
	var listed struct {
		Records []struct {
			ID   int64  `json:"id"`
			Data string `json:"data"`
			TTL  int    `json:"ttl"`
		} `json:"domain_records"`
	}
	if err := jsonRequest(ctx, provider.client, http.MethodGet, endpoint+query, "Bearer "+provider.credentials.APIToken, nil, &listed); err != nil {
		return false, err
	}
	values := make([]string, 0, len(listed.Records))
	for _, existing := range listed.Records {
		values = append(values, existing.Data)
	}
	if len(listed.Records) == 1 && sameSingleRecord(values, record.Value, listed.Records[0].TTL, record.TTL) {
		return false, nil
	}
	body := map[string]any{"type": record.Type, "name": relativeName(record.Name, record.Zone), "data": record.Value, "ttl": record.TTL}
	if len(listed.Records) == 0 {
		if err := jsonRequest(ctx, provider.client, http.MethodPost, endpoint, "Bearer "+provider.credentials.APIToken, body, nil); err != nil {
			return false, err
		}
		return true, nil
	}
	first := endpoint + "/" + strconv.FormatInt(listed.Records[0].ID, 10)
	if err := jsonRequest(ctx, provider.client, http.MethodPut, first, "Bearer "+provider.credentials.APIToken, body, nil); err != nil {
		return false, err
	}
	for _, duplicate := range listed.Records[1:] {
		path := endpoint + "/" + strconv.FormatInt(duplicate.ID, 10)
		if err := jsonRequest(ctx, provider.client, http.MethodDelete, path, "Bearer "+provider.credentials.APIToken, nil, nil); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (provider *hetznerProvider) EnsureRecord(ctx context.Context, record Record) (bool, error) {
	record, err := normalizeRecord(record)
	if err != nil {
		return false, err
	}
	zoneID := strings.TrimSpace(provider.credentials.ZoneID)
	if zoneID == "" {
		zoneID = record.Zone
	}
	endpoint := provider.baseURL + "/zones/" + url.PathEscape(zoneID) + "/rrsets/" + url.PathEscape(relativeName(record.Name, record.Zone)) + "/" + record.Type
	request, err := jsonHTTPProviderRequest(ctx, http.MethodGet, endpoint, "Bearer "+provider.credentials.APIToken, nil)
	if err != nil {
		return false, err
	}
	response, err := provider.client.Do(request)
	if err != nil {
		return false, fmt.Errorf("get Hetzner DNS record: %w", err)
	}
	var listed struct {
		RRSet struct {
			TTL     *int `json:"ttl"`
			Records []struct {
				Value string `json:"value"`
			} `json:"records"`
		} `json:"rrset"`
	}
	found := response.StatusCode != http.StatusNotFound
	if found {
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			defer response.Body.Close()
			return false, responseError("Hetzner", response)
		}
		decodeErr := json.NewDecoder(response.Body).Decode(&listed)
		response.Body.Close()
		if decodeErr != nil && decodeErr != io.EOF {
			return false, fmt.Errorf("decode Hetzner DNS record: %w", decodeErr)
		}
	} else {
		response.Body.Close()
	}
	values := make([]string, 0, len(listed.RRSet.Records))
	for _, existing := range listed.RRSet.Records {
		values = append(values, existing.Value)
	}
	actualTTL := 0
	if listed.RRSet.TTL != nil {
		actualTTL = *listed.RRSet.TTL
	}
	if sameSingleRecord(values, record.Value, actualTTL, record.TTL) {
		return false, nil
	}
	authorization := "Bearer " + provider.credentials.APIToken
	records := []map[string]string{{"value": record.Value}}
	if !found {
		body := map[string]any{
			"name": relativeName(record.Name, record.Zone), "type": record.Type,
			"ttl": record.TTL, "records": records,
		}
		collection := provider.baseURL + "/zones/" + url.PathEscape(zoneID) + "/rrsets"
		if err := jsonRequest(ctx, provider.client, http.MethodPost, collection, authorization, body, nil); err != nil {
			return false, err
		}
		return true, nil
	}
	recordMatches := len(values) == 1 && strings.TrimSpace(values[0]) == record.Value
	if !recordMatches {
		body := map[string]any{"records": records}
		if err := jsonRequest(ctx, provider.client, http.MethodPost, endpoint+"/actions/set_records", authorization, body, nil); err != nil {
			return false, err
		}
	}
	if actualTTL != int(record.TTL) {
		body := map[string]any{"ttl": record.TTL}
		if err := jsonRequest(ctx, provider.client, http.MethodPost, endpoint+"/actions/change_ttl", authorization, body, nil); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (provider *rfc2136Provider) EnsureRecord(ctx context.Context, record Record) (bool, error) {
	record, err := normalizeRecord(record)
	if err != nil {
		return false, err
	}
	current, actualTTL, err := provider.rfc2136RecordSet(ctx, record)
	if err != nil {
		return false, err
	}
	if sameSingleRecord(current, record.Value, actualTTL, record.TTL) {
		return false, nil
	}
	rr, err := addressRR(record)
	if err != nil {
		return false, err
	}
	err = provider.update(ctx, record.Zone, func(message *dns.Msg) {
		message.RemoveRRset([]dns.RR{rr})
		message.Insert([]dns.RR{rr})
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (provider *rfc2136Provider) rfc2136RecordSet(ctx context.Context, record Record) ([]string, int, error) {
	recordType := dns.TypeA
	if record.Type == TypeAAAA {
		recordType = dns.TypeAAAA
	}
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(record.Name), uint16(recordType))
	algorithm, err := tsigAlgorithm(provider.credentials.TSIGAlgorithm)
	if err != nil {
		return nil, 0, err
	}
	keyName := dns.Fqdn(provider.credentials.TSIGName)
	message.SetTsig(keyName, algorithm, 300, time.Now().Unix())
	client := &dns.Client{TsigSecret: map[string]string{keyName: provider.credentials.TSIGSecret}}
	response, _, err := client.ExchangeContext(ctx, message, dnsServerAddress(provider.credentials.Server))
	if err != nil {
		return nil, 0, fmt.Errorf("RFC 2136 lookup: %w", err)
	}
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return nil, 0, fmt.Errorf("RFC 2136 lookup returned %s", dns.RcodeToString[response.Rcode])
	}
	values := make([]string, 0, len(response.Answer))
	ttl := 0
	for _, answer := range response.Answer {
		switch value := answer.(type) {
		case *dns.A:
			values = append(values, value.A.String())
			ttl = int(value.Hdr.Ttl)
		case *dns.AAAA:
			values = append(values, value.AAAA.String())
			ttl = int(value.Hdr.Ttl)
		}
	}
	return values, ttl, nil
}

func addressRR(record Record) (dns.RR, error) {
	address, _ := netip.ParseAddr(record.Value)
	header := dns.RR_Header{Name: dns.Fqdn(record.Name), Class: dns.ClassINET, Ttl: record.TTL}
	if record.Type == TypeA {
		header.Rrtype = dns.TypeA
		return &dns.A{Hdr: header, A: address.AsSlice()}, nil
	}
	header.Rrtype = dns.TypeAAAA
	return &dns.AAAA{Hdr: header, AAAA: address.AsSlice()}, nil
}

func (provider *route53Provider) EnsureRecord(ctx context.Context, record Record) (bool, error) {
	record, err := normalizeRecord(record)
	if err != nil {
		return false, err
	}
	values, ttl, err := provider.recordSetByType(ctx, record.Name, record.Type)
	if err != nil {
		return false, err
	}
	if sameSingleRecord(values, record.Value, ttl, record.TTL) {
		return false, nil
	}
	if err := provider.changeRecordSet(ctx, "UPSERT", record.Name, record.Type, record.TTL, []string{record.Value}); err != nil {
		return false, err
	}
	return true, nil
}

func (provider *route53Provider) recordSetByType(ctx context.Context, name, recordType string) ([]string, int, error) {
	query := url.Values{"name": {dns.Fqdn(name)}, "type": {recordType}, "maxitems": {"1"}}
	request, err := provider.request(ctx, http.MethodGet, provider.rrsetPath(), query, nil)
	if err != nil {
		return nil, 0, err
	}
	response, err := provider.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("list Route 53 records: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, 0, responseError("Route 53", response)
	}
	var result struct {
		Sets []route53RecordSet `xml:"ResourceRecordSets>ResourceRecordSet"`
	}
	if err := xml.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("decode Route 53 records: %w", err)
	}
	if len(result.Sets) == 0 || !strings.EqualFold(strings.TrimSuffix(result.Sets[0].Name, "."), strings.TrimSuffix(name, ".")) || result.Sets[0].Type != recordType {
		return nil, 0, nil
	}
	values := make([]string, 0, len(result.Sets[0].Records))
	for _, existing := range result.Sets[0].Records {
		values = append(values, existing.Value)
	}
	return values, result.Sets[0].TTL, nil
}

func (provider *route53Provider) changeRecordSet(ctx context.Context, action, name, recordType string, ttl uint32, values []string) error {
	requestBody := route53ChangeRequest{XMLNS: "https://route53.amazonaws.com/doc/2013-04-01/"}
	change := struct {
		Action string           `xml:"Action"`
		Set    route53RecordSet `xml:"ResourceRecordSet"`
	}{Action: action, Set: route53RecordSet{Name: dns.Fqdn(name), Type: recordType, TTL: int(ttl)}}
	for _, value := range values {
		change.Set.Records = append(change.Set.Records, route53Record{Value: value})
	}
	requestBody.Changes = append(requestBody.Changes, change)
	encoded, err := xml.Marshal(requestBody)
	if err != nil {
		return err
	}
	request, err := provider.request(ctx, http.MethodPost, provider.rrsetPath(), nil, encoded)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/xml")
	response, err := provider.client.Do(request)
	if err != nil {
		return fmt.Errorf("change Route 53 record: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError("Route 53", response)
	}
	return nil
}

func (provider *ovhProvider) EnsureRecord(ctx context.Context, record Record) (bool, error) {
	record, err := normalizeRecord(record)
	if err != nil {
		return false, err
	}
	relative := relativeName(record.Name, record.Zone)
	basePath := "/domain/zone/" + url.PathEscape(record.Zone) + "/record"
	query := "?fieldType=" + record.Type + "&subDomain=" + url.QueryEscape(relative)
	var ids []int64
	if err := provider.request(ctx, http.MethodGet, basePath+query, nil, &ids); err != nil {
		return false, err
	}
	type ovhRecord struct {
		Target string `json:"target"`
		TTL    int    `json:"ttl"`
	}
	if len(ids) == 1 {
		var existing ovhRecord
		if err := provider.request(ctx, http.MethodGet, basePath+"/"+strconv.FormatInt(ids[0], 10), nil, &existing); err != nil {
			return false, err
		}
		if sameSingleRecord([]string{existing.Target}, record.Value, existing.TTL, record.TTL) {
			return false, nil
		}
	}
	body := map[string]any{"fieldType": record.Type, "subDomain": relative, "target": record.Value, "ttl": record.TTL}
	if len(ids) == 0 {
		var created int64
		if err := provider.request(ctx, http.MethodPost, basePath, body, &created); err != nil {
			return false, err
		}
	} else {
		firstPath := basePath + "/" + strconv.FormatInt(ids[0], 10)
		if err := provider.request(ctx, http.MethodPut, firstPath, map[string]any{"target": record.Value, "ttl": record.TTL}, nil); err != nil {
			return false, err
		}
		for _, duplicateID := range ids[1:] {
			duplicatePath := basePath + "/" + strconv.FormatInt(duplicateID, 10)
			if err := provider.request(ctx, http.MethodDelete, duplicatePath, nil, nil); err != nil {
				return false, err
			}
		}
	}
	if err := provider.refresh(ctx, record.Zone); err != nil {
		return false, err
	}
	return true, nil
}
