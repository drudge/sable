package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsprovider"
	"github.com/drudge/sable/internal/durationfmt"
	"github.com/drudge/sable/internal/dynamicdns"
	"github.com/drudge/sable/internal/web/pages"
)

type dynamicDNSController interface {
	Status(context.Context) dynamicdns.Status
	SyncNow()
	PutCredentials(context.Context, string, dnsprovider.Credentials) error
	StoredCredentials(context.Context, string) (dnsprovider.Credentials, bool)
}

func (server *Server) SetDynamicDNSController(controller dynamicDNSController) {
	server.dynamicDNS = controller
}

func (server *Server) dynamicDNSView(request *http.Request, display pages.TimeDisplay) pages.DynamicDNSAppView {
	settings := server.config.Current().Config.DynamicDNS
	publishers := settings.ConfiguredPublishers()
	view := pages.DynamicDNSAppView{
		Available:  server.dynamicDNS != nil,
		Configured: len(publishers) > 0,
		Enabled:    settings.Enabled,
		Interval:   settings.Interval.String(), TTL: dynamicDNSGlobalTTL(publishers), IPv4URL: settings.IPv4URL, IPv6URL: settings.IPv6URL,
	}
	view.CredentialsConfigured = len(publishers) > 0
	for publisherIndex, publisher := range publishers {
		publisherView := pages.DynamicDNSPublisherView{
			Index: publisherIndex, Provider: publisher.Provider,
			Zones: dynamicDNSZoneViews(publisher.Records),
		}
		if server.dynamicDNS != nil {
			credentials, configured := server.dynamicDNS.StoredCredentials(request.Context(), publisher.Provider)
			publisherView.CredentialsConfigured = configured
			publisherView.ProviderEndpoint = credentials.Endpoint
			publisherView.TSIGAlgorithm = credentials.TSIGAlgorithm
			view.CredentialsConfigured = view.CredentialsConfigured && configured
		}
		view.Publishers = append(view.Publishers, publisherView)
	}
	if server.dynamicDNS == nil {
		view.CredentialsConfigured = false
		return view
	}
	provider := ""
	if len(publishers) == 1 {
		provider = publishers[0].Provider
	}
	view.Status = dynamicDNSStatusView(provider, server.dynamicDNS.Status(request.Context()), display)
	return view
}

func dynamicDNSGlobalTTL(publishers []config.DynamicDNSPublisher) uint32 {
	for _, publisher := range publishers {
		for _, record := range publisher.Records {
			if record.TTL > 0 {
				return record.TTL
			}
		}
	}
	return 600
}

func dynamicDNSZoneViews(records []config.DynamicDNSRecord) []pages.DynamicDNSZoneView {
	var zones []pages.DynamicDNSZoneView
	indices := make(map[string]int)
	for _, record := range records {
		index, found := indices[record.Zone]
		if !found {
			index = len(zones)
			indices[record.Zone] = index
			zones = append(zones, pages.DynamicDNSZoneView{
				Index: index, Zone: record.Zone, PublishIPv4: record.IPv4,
				PublishIPv6: record.IPv6, TTL: record.TTL,
			})
		}
		if zones[index].Names != "" {
			zones[index].Names += "\n"
		}
		zones[index].Names += record.Name
	}
	if len(zones) == 0 {
		zones = append(zones, pages.DynamicDNSZoneView{Index: 0, PublishIPv4: true, TTL: 600})
	}
	return zones
}

func dynamicDNSStatusView(provider string, status dynamicdns.Status, display pages.TimeDisplay) pages.DynamicDNSStatusView {
	errorSummary, errorDetail := dynamicDNSErrorDisplay(provider, status.LastError)
	result := pages.DynamicDNSStatusView{
		Running: status.Running, LastError: errorSummary, LastErrorDetail: errorDetail,
		IPv4: status.IPv4, IPv6: status.IPv6,
		Records: status.Records, Changed: status.Changed, Unchanged: status.Unchanged,
	}
	if !status.LastSuccess.IsZero() {
		result.LastSuccess = pages.FormatShortDateTime(status.LastSuccess, display, true)
	}
	if !status.LastPublished.IsZero() {
		result.LastPublished = pages.FormatDateTime(status.LastPublished, display)
	}
	if !status.NextAttempt.IsZero() {
		result.NextAttempt = pages.FormatShortDateTime(status.NextAttempt, display, true)
	}
	if status.Duration > 0 {
		result.Duration = status.Duration.Round(time.Millisecond).String()
	}
	return result
}

var providerSecretPattern = regexp.MustCompile(`(?i)((?:authorization|api[-_ ]?key|access[-_ ]?key|token|secret|password)\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+`)

func dynamicDNSErrorDisplay(provider, raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}

	start := strings.IndexAny(raw, "{[")
	if start < 0 {
		return redactProviderSecrets(raw), ""
	}

	var payload any
	decoder := json.NewDecoder(strings.NewReader(raw[start:]))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return redactProviderSecrets(raw), ""
	}

	messages, codes := providerDiagnostics(payload)
	if len(messages) == 0 {
		return redactProviderSecrets(raw), ""
	}

	summary := dynamicDNSProviderName(provider) + " rejected the request: " + strings.Join(messages, ": ")
	if len(codes) == 1 {
		summary += " (code " + codes[0] + ")"
	} else if len(codes) > 1 {
		summary += " (codes " + strings.Join(codes, ", ") + ")"
	}
	summary += "."

	detail, err := json.MarshalIndent(sanitizeProviderPayload(payload), "", "  ")
	if err != nil {
		return summary, ""
	}
	return summary, string(detail)
}

func providerDiagnostics(payload any) ([]string, []string) {
	var messages []string
	var codes []string
	seenMessages := make(map[string]bool)
	seenCodes := make(map[string]bool)

	var visit func(any)
	visit = func(value any) {
		switch typed := value.(type) {
		case []any:
			for _, item := range typed {
				visit(item)
			}
		case map[string]any:
			if message, ok := typed["message"].(string); ok {
				message = redactProviderSecrets(strings.TrimSpace(message))
				if message != "" && !seenMessages[message] {
					seenMessages[message] = true
					messages = append(messages, message)
				}
			}
			if code, ok := providerErrorCode(typed["code"]); ok && !seenCodes[code] {
				seenCodes[code] = true
				codes = append(codes, code)
			}

			preferred := []string{"errors", "error_chain", "messages"}
			for _, key := range preferred {
				if child, ok := typed[key]; ok {
					visit(child)
				}
			}
			otherKeys := make([]string, 0, len(typed))
			for key := range typed {
				if key != "message" && key != "code" && key != "errors" && key != "error_chain" && key != "messages" {
					otherKeys = append(otherKeys, key)
				}
			}
			sort.Strings(otherKeys)
			for _, key := range otherKeys {
				visit(typed[key])
			}
		}
	}
	visit(payload)
	return messages, codes
}

func providerErrorCode(value any) (string, bool) {
	switch typed := value.(type) {
	case json.Number:
		return typed.String(), true
	case string:
		if code := strings.TrimSpace(typed); code != "" {
			return code, true
		}
	}
	return "", false
}

func sanitizeProviderPayload(value any) any {
	switch typed := value.(type) {
	case []any:
		clean := make([]any, len(typed))
		for index, item := range typed {
			clean[index] = sanitizeProviderPayload(item)
		}
		return clean
	case map[string]any:
		clean := make(map[string]any, len(typed))
		for key, item := range typed {
			if providerFieldIsSecret(key) {
				clean[key] = "[redacted]"
			} else {
				clean[key] = sanitizeProviderPayload(item)
			}
		}
		return clean
	case string:
		return redactProviderSecrets(typed)
	default:
		return value
	}
}

func providerFieldIsSecret(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(key))
	for _, sensitive := range []string{"authorization", "password", "secret", "token", "apikey", "accesskey", "privatekey", "consumerkey"} {
		if strings.Contains(normalized, sensitive) {
			return true
		}
	}
	return false
}

func redactProviderSecrets(value string) string {
	return providerSecretPattern.ReplaceAllString(value, "${1}[redacted]")
}

func dynamicDNSProviderName(provider string) string {
	switch provider {
	case "cloudflare":
		return "Cloudflare"
	case "porkbun":
		return "Porkbun"
	case "namecheap":
		return "Namecheap"
	case "godaddy":
		return "GoDaddy"
	case "digitalocean":
		return "DigitalOcean"
	case "hetzner":
		return "Hetzner"
	case "route53":
		return "Amazon Route 53"
	case "ovh":
		return "OVHcloud"
	case "rfc2136":
		return "RFC 2136 provider"
	default:
		return "DNS provider"
	}
}

func (server *Server) saveDynamicDNS(writer http.ResponseWriter, request *http.Request) {
	if server.dynamicDNS == nil {
		server.renderIntegrationsMutation(writer, request, http.StatusNotImplemented, "", "The dynamic DNS publisher is unavailable.")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusBadRequest, "", "Invalid dynamic DNS settings.")
		return
	}
	settings, credentialInputs, err := dynamicDNSSettingsFromForm(request)
	if err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	if err := settings.Validate(); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	editor, ok := server.config.(settingsEditor)
	if !ok {
		server.renderIntegrationsMutation(writer, request, http.StatusNotImplemented, "", "Settings are read-only.")
		return
	}
	for _, input := range credentialInputs {
		if input.Credentials == (dnsprovider.Credentials{}) {
			continue
		}
		if err := server.dynamicDNS.PutCredentials(request.Context(), input.Provider, input.Credentials); err != nil {
			server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
			return
		}
	}
	for _, provider := range settings.ProviderNames() {
		if _, configured := server.dynamicDNS.StoredCredentials(request.Context(), provider); !configured {
			server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", "Enter credentials for "+dynamicDNSProviderName(provider)+".")
			return
		}
	}
	if err := editor.Update(request.Context(), func(candidate *config.Config) error {
		candidate.DynamicDNS = settings
		return nil
	}); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	server.dynamicDNS.SyncNow()
	server.recordControlPlaneAudit(request, "integrations.dynamic_dns.configure",
		fmt.Sprintf("enabled dynamic DNS publication for %d names across %d providers", len(settings.AllRecords()), len(settings.ProviderNames())))
	writer.Header().Set("HX-Replace-Url", "/integrations")
	server.renderIntegrationsMutation(writer, request, http.StatusOK, "Dynamic DNS is configured. The first publication is running now.", "")
}

type dynamicDNSCredentialInput struct {
	Provider    string
	Credentials dnsprovider.Credentials
}

var dynamicDNSPublisherFormPattern = regexp.MustCompile(`^publisher_(\d+)_provider$`)

func dynamicDNSSettingsFromForm(request *http.Request) (config.DynamicDNS, []dynamicDNSCredentialInput, error) {
	interval, err := durationfmt.Parse(strings.TrimSpace(request.FormValue("interval")))
	if err != nil {
		return config.DynamicDNS{}, nil, errors.New("Dynamic DNS interval is invalid.")
	}
	globalTTLValue := strings.TrimSpace(request.FormValue("ttl"))
	var globalTTL uint64
	if globalTTLValue != "" {
		globalTTL, err = strconv.ParseUint(globalTTLValue, 10, 32)
		if err != nil {
			return config.DynamicDNS{}, nil, errors.New("Dynamic DNS TTL must be a whole number.")
		}
	}
	publisherIndices := dynamicDNSFormIndices(request.Form, dynamicDNSPublisherFormPattern)
	legacy := len(publisherIndices) == 0 && strings.TrimSpace(request.FormValue("provider")) != ""
	if legacy {
		publisherIndices = []int{0}
	}
	settings := config.DynamicDNS{
		Enabled: true, Interval: config.Duration{Duration: interval},
		IPv4URL: strings.TrimSpace(request.FormValue("ipv4_url")),
		IPv6URL: strings.TrimSpace(request.FormValue("ipv6_url")),
	}
	var credentialInputs []dynamicDNSCredentialInput
	for _, publisherIndex := range publisherIndices {
		prefix := fmt.Sprintf("publisher_%d_", publisherIndex)
		providerField := prefix + "provider"
		if legacy {
			prefix, providerField = "", "provider"
		}
		provider := strings.ToLower(strings.TrimSpace(request.FormValue(providerField)))
		publisher := config.DynamicDNSPublisher{Provider: provider}
		zonePattern := regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `zone_(\d+)_zone$`)
		zoneIndices := dynamicDNSFormIndices(request.Form, zonePattern)
		if legacy {
			zoneIndices = []int{0}
		}
		for _, zoneIndex := range zoneIndices {
			zonePrefix := fmt.Sprintf("%szone_%d_", prefix, zoneIndex)
			if legacy {
				zonePrefix = ""
			}
			ttl := globalTTL
			if globalTTLValue == "" {
				var parseErr error
				ttl, parseErr = strconv.ParseUint(strings.TrimSpace(request.FormValue(zonePrefix+"ttl")), 10, 32)
				if parseErr != nil {
					return config.DynamicDNS{}, nil, errors.New("Dynamic DNS TTL must be a whole number.")
				}
			}
			zone := strings.Trim(strings.ToLower(strings.TrimSpace(request.FormValue(zonePrefix+"zone"))), ".")
			for _, name := range formLines(request.FormValue(zonePrefix + "names")) {
				publisher.Records = append(publisher.Records, config.DynamicDNSRecord{
					Zone: zone, Name: strings.Trim(strings.ToLower(name), "."),
					IPv4: request.FormValue(zonePrefix+"publish_ipv4") == "true",
					IPv6: request.FormValue(zonePrefix+"publish_ipv6") == "true",
					TTL:  uint32(ttl),
				})
			}
		}
		settings.Publishers = append(settings.Publishers, publisher)
		credentialInputs = append(credentialInputs, dynamicDNSCredentialInput{
			Provider: provider, Credentials: certificateCredentialsFromFormPrefix(request, provider, prefix),
		})
	}
	return settings, credentialInputs, nil
}

func dynamicDNSFormIndices(form map[string][]string, pattern *regexp.Regexp) []int {
	seen := make(map[int]struct{})
	for field := range form {
		matches := pattern.FindStringSubmatch(field)
		if len(matches) != 2 {
			continue
		}
		index, err := strconv.Atoi(matches[1])
		if err == nil {
			seen[index] = struct{}{}
		}
	}
	indices := make([]int, 0, len(seen))
	for index := range seen {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	return indices
}

func (server *Server) syncDynamicDNSNow(writer http.ResponseWriter, request *http.Request) {
	if server.dynamicDNS == nil || !server.config.Current().Config.DynamicDNS.Runnable() {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", "Finish dynamic DNS setup before publishing.")
		return
	}
	server.dynamicDNS.SyncNow()
	server.recordControlPlaneAudit(request, "integrations.dynamic_dns.sync", "requested an immediate dynamic DNS publication")
	server.renderIntegrationsMutation(writer, request, http.StatusOK, "Dynamic DNS publication started.", "")
}

func (server *Server) setDynamicDNSEnabled(writer http.ResponseWriter, request *http.Request) {
	if server.dynamicDNS == nil {
		server.renderIntegrationsMutation(writer, request, http.StatusNotImplemented, "", "The dynamic DNS publisher is unavailable.")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusBadRequest, "", "Invalid request.")
		return
	}
	enabled := request.FormValue("enabled") == "true"
	editor, ok := server.config.(settingsEditor)
	if !ok {
		server.renderIntegrationsMutation(writer, request, http.StatusNotImplemented, "", "Settings are read-only.")
		return
	}
	if enabled {
		for _, provider := range server.config.Current().Config.DynamicDNS.ProviderNames() {
			if _, configured := server.dynamicDNS.StoredCredentials(request.Context(), provider); !configured {
				server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", dynamicDNSProviderName(provider)+" credentials are not configured.")
				return
			}
		}
	}
	if err := editor.Update(request.Context(), func(candidate *config.Config) error {
		candidate.DynamicDNS.Enabled = enabled
		return nil
	}); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	action, message := "integrations.dynamic_dns.disable", "Dynamic DNS publication paused. Existing external records were left in place."
	if enabled {
		action, message = "integrations.dynamic_dns.enable", "Dynamic DNS publication resumed."
		server.dynamicDNS.SyncNow()
	}
	server.recordControlPlaneAudit(request, action, message)
	server.renderIntegrationsMutation(writer, request, http.StatusOK, message, "")
}

func (server *Server) removeDynamicDNS(writer http.ResponseWriter, request *http.Request) {
	editor, ok := server.config.(settingsEditor)
	if !ok {
		server.renderIntegrationsMutation(writer, request, http.StatusNotImplemented, "", "Settings are read-only.")
		return
	}
	if err := editor.Update(request.Context(), func(candidate *config.Config) error {
		candidate.DynamicDNS = config.DynamicDNS{}
		return nil
	}); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	server.recordControlPlaneAudit(request, "integrations.dynamic_dns.remove", "removed dynamic DNS settings and retained external records")
	server.renderIntegrationsMutation(writer, request, http.StatusOK, "Dynamic DNS was removed. Existing external records and shared provider credentials were retained.", "")
}

func (server *Server) dynamicDNSStatusPanel(writer http.ResponseWriter, request *http.Request) {
	view := server.integrationsView(request, "", "").DynamicDNS
	if err := pages.DynamicDNSStatusPanel(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render dynamic DNS status", "error", err)
		return
	}
	if err := pages.DynamicDNSCardActions(view, true).Render(request.Context(), writer); err != nil {
		server.logger.Error("render dynamic DNS actions", "error", err)
	}
	if err := pages.DynamicDNSFacts(view, true).Render(request.Context(), writer); err != nil {
		server.logger.Error("render dynamic DNS facts", "error", err)
	}
}
