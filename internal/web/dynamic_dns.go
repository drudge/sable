package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
	view := pages.DynamicDNSAppView{
		Available:  server.dynamicDNS != nil,
		Configured: settings.Provider != "" || len(settings.Records) > 0,
		Enabled:    settings.Enabled, Provider: settings.Provider,
		Interval: settings.Interval.String(), IPv4URL: settings.IPv4URL, IPv6URL: settings.IPv6URL,
	}
	if len(settings.Records) > 0 {
		view.Zone = settings.Records[0].Zone
		view.TTL = settings.Records[0].TTL
		view.PublishIPv4 = settings.Records[0].IPv4
		view.PublishIPv6 = settings.Records[0].IPv6
		names := make([]string, 0, len(settings.Records))
		for _, record := range settings.Records {
			names = append(names, record.Name)
		}
		view.Names = strings.Join(names, "\n")
	}
	if view.TTL == 0 {
		view.TTL = 600
	}
	if !view.Configured {
		view.PublishIPv4 = true
	}
	if server.dynamicDNS == nil {
		return view
	}
	credentials, configured := server.dynamicDNS.StoredCredentials(request.Context(), settings.Provider)
	view.CredentialsConfigured = configured
	view.ProviderEndpoint = credentials.Endpoint
	view.TSIGAlgorithm = credentials.TSIGAlgorithm
	view.Status = dynamicDNSStatusView(server.dynamicDNS.Status(request.Context()), display)
	return view
}

func dynamicDNSStatusView(status dynamicdns.Status, display pages.TimeDisplay) pages.DynamicDNSStatusView {
	result := pages.DynamicDNSStatusView{
		Running: status.Running, LastError: status.LastError,
		IPv4: status.IPv4, IPv6: status.IPv6,
		Records: status.Records, Changed: status.Changed, Unchanged: status.Unchanged,
	}
	if !status.LastSuccess.IsZero() {
		result.LastSuccess = pages.FormatShortDateTime(status.LastSuccess, display, true)
	}
	if !status.NextAttempt.IsZero() {
		result.NextAttempt = pages.FormatShortDateTime(status.NextAttempt, display, true)
	}
	if status.Duration > 0 {
		result.Duration = status.Duration.Round(time.Millisecond).String()
	}
	return result
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
	settings, err := dynamicDNSSettingsFromForm(request)
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
	credentials := certificateCredentialsFromForm(request, settings.Provider)
	if credentials != (dnsprovider.Credentials{}) {
		if err := server.dynamicDNS.PutCredentials(request.Context(), settings.Provider, credentials); err != nil {
			server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
			return
		}
	}
	if _, configured := server.dynamicDNS.StoredCredentials(request.Context(), settings.Provider); !configured {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", "Enter credentials for the selected DNS provider.")
		return
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
		fmt.Sprintf("enabled dynamic DNS publication for %d names", len(settings.Records)))
	writer.Header().Set("HX-Replace-Url", "/integrations")
	server.renderIntegrationsMutation(writer, request, http.StatusOK, "Dynamic DNS is configured. The first publication is running now.", "")
}

func dynamicDNSSettingsFromForm(request *http.Request) (config.DynamicDNS, error) {
	interval, err := durationfmt.Parse(strings.TrimSpace(request.FormValue("interval")))
	if err != nil {
		return config.DynamicDNS{}, errors.New("Dynamic DNS interval is invalid.")
	}
	ttl, err := strconv.ParseUint(strings.TrimSpace(request.FormValue("ttl")), 10, 32)
	if err != nil {
		return config.DynamicDNS{}, errors.New("Dynamic DNS TTL must be a whole number.")
	}
	zone := strings.Trim(strings.ToLower(strings.TrimSpace(request.FormValue("zone"))), ".")
	names := formLines(request.FormValue("names"))
	records := make([]config.DynamicDNSRecord, 0, len(names))
	for _, name := range names {
		records = append(records, config.DynamicDNSRecord{
			Zone: zone, Name: strings.Trim(strings.ToLower(name), "."),
			IPv4: request.FormValue("publish_ipv4") == "true",
			IPv6: request.FormValue("publish_ipv6") == "true",
			TTL:  uint32(ttl),
		})
	}
	return config.DynamicDNS{
		Enabled: true, Provider: strings.ToLower(strings.TrimSpace(request.FormValue("provider"))),
		Interval: config.Duration{Duration: interval},
		IPv4URL:  strings.TrimSpace(request.FormValue("ipv4_url")),
		IPv6URL:  strings.TrimSpace(request.FormValue("ipv6_url")),
		Records:  records,
	}, nil
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
		provider := server.config.Current().Config.DynamicDNS.Provider
		if _, configured := server.dynamicDNS.StoredCredentials(request.Context(), provider); !configured {
			server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", "DNS provider credentials are not configured.")
			return
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
}
