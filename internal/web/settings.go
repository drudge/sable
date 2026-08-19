package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/tsig"
	"github.com/drudge/sable/internal/web/pages"
)

type settingsEditor interface {
	Update(context.Context, func(*config.Config) error) error
}

type certificateGenerator interface {
	GenerateSelfSigned(context.Context, certificates.ManualCertificateOptions) (certificates.GeneratedCertificate, error)
	ImportKeyPair(context.Context, certificates.ImportCertificateOptions) (certificates.GeneratedCertificate, error)
	GenerateClusterPKI(context.Context, certificates.ClusterPKIOptions) (certificates.GeneratedCertificate, error)
}

func (server *Server) settingsPage(writer http.ResponseWriter, request *http.Request) {
	view := server.settingsView(request, "", "")
	if err := pages.SettingsPage(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render settings page", "error", err)
	}
}

func (server *Server) updateSettings(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderSettingsMutation(writer, request, http.StatusBadRequest, "", "Invalid settings form.")
		return
	}
	editor, ok := server.config.(settingsEditor)
	if !ok {
		server.renderSettingsMutation(writer, request, http.StatusNotImplemented, "", "Settings are read-only.")
		return
	}
	blockingUpdateHours, err := strconv.Atoi(request.FormValue("blocking_update_hours"))
	if err != nil || blockingUpdateHours < 1 || blockingUpdateHours > 8760 {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", "Block-list update interval must be between 1 and 8760 hours.")
		return
	}
	blockingResponseType := strings.TrimSpace(request.FormValue("blocking_response_type"))
	if blockingResponseType != "zero" && blockingResponseType != "nxdomain" && blockingResponseType != "custom" {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", "Blocking response type is invalid.")
		return
	}
	blockingResponseTTL, err := strconv.ParseUint(request.FormValue("blocking_response_ttl"), 10, 32)
	if err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", "Blocking response TTL must be a non-negative number.")
		return
	}
	cacheMinimumTTL, err := parseUint32Setting(request.FormValue("cache_minimum_ttl"), "minimum cache TTL", true)
	if err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	cacheMaximumTTL, err := parseUint32Setting(request.FormValue("cache_maximum_ttl"), "maximum cache TTL", false)
	if err != nil || cacheMinimumTTL > cacheMaximumTTL {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", "Maximum cache TTL must be positive and no smaller than the minimum cache TTL.")
		return
	}
	cacheNegativeTTL, err := parseUint32Setting(request.FormValue("cache_negative_ttl"), "negative cache TTL", true)
	if err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	cacheFailureTTL, err := parseUint32Setting(request.FormValue("cache_failure_ttl"), "failure cache TTL", true)
	if err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	cacheStaleTTL, err := parseUint32Setting(request.FormValue("cache_stale_ttl"), "maximum stale age", false)
	if err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	cacheStaleAnswerTTL, err := parseUint32Setting(request.FormValue("cache_stale_answer_ttl"), "stale answer TTL", false)
	if err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	cacheStaleResetTTL, err := parseUint32Setting(request.FormValue("cache_stale_reset_ttl"), "stale retry TTL", false)
	if err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	cacheStaleMaxWaitMS, err := strconv.ParseInt(strings.TrimSpace(request.FormValue("cache_stale_max_wait_ms")), 10, 64)
	if err != nil || cacheStaleMaxWaitMS < 1 || cacheStaleMaxWaitMS > 60_000 {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", "Stale max wait must be between 1 and 60000 milliseconds.")
		return
	}
	cachePrefetchMinimumTTL, err := parseUint32Setting(request.FormValue("cache_prefetch_minimum_ttl"), "prefetch eligibility TTL", true)
	if err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	cachePrefetchTriggerTTL, err := parseUint32Setting(request.FormValue("cache_prefetch_trigger_ttl"), "prefetch trigger TTL", true)
	if err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	cachePrefetchSample, err := time.ParseDuration(strings.TrimSpace(request.FormValue("cache_prefetch_sample_interval")))
	if err != nil || cachePrefetchSample <= 0 || cachePrefetchSample > 24*time.Hour {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", "Prefetch sample interval must be a positive Go duration no greater than 24h.")
		return
	}
	cachePrefetchHits, err := parseUint32Setting(request.FormValue("cache_prefetch_hits_per_hour"), "prefetch hits per hour", false)
	if err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	certificateMode := strings.ToLower(strings.TrimSpace(request.FormValue("certificate_mode")))
	if certificateMode == "" {
		certificateMode = "manual"
	}
	if certificateMode != "manual" && certificateMode != "acme" {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", "Certificate mode must be manual or managed ACME.")
		return
	}
	acmeRenewBefore := 30 * 24 * time.Hour
	if certificateMode == "acme" {
		acmeRenewBefore, err = time.ParseDuration(strings.TrimSpace(request.FormValue("acme_renew_before")))
		if err != nil {
			server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", "ACME renewal window is invalid.")
			return
		}
		if server.certificates == nil {
			server.renderSettingsMutation(writer, request, http.StatusServiceUnavailable, "", "Certificate automation service is unavailable.")
			return
		}
		provider := strings.ToLower(strings.TrimSpace(request.FormValue("acme_dns_provider")))
		credentials := certificateCredentialsFromForm(request, provider)
		if credentials != (certificates.Credentials{}) {
			if err := server.certificates.PutCredentials(request.Context(), provider, credentials); err != nil {
				server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
				return
			}
		}
	}
	err = editor.Update(request.Context(), func(candidate *config.Config) error {
		dnsListeners := formLines(request.FormValue("dns_listen"))
		resolverMode := strings.ToLower(strings.TrimSpace(request.FormValue("resolver_mode")))
		if resolverMode == "" {
			resolverMode = candidate.Resolver.Mode
		}
		forwarders := formLines(request.FormValue("forwarders"))
		if resolverMode != "forward" && resolverMode != "recursive" {
			return errors.New("resolution mode must be iterative recursion or forwarding")
		}
		if len(dnsListeners) == 0 || (resolverMode == "forward" && len(forwarders) == 0) {
			return errors.New("DNS listeners are required, and forwarding mode requires at least one forwarder")
		}
		resolverTimeout, err := time.ParseDuration(strings.TrimSpace(request.FormValue("resolver_timeout")))
		if err != nil {
			return errors.New("resolver timeout is invalid")
		}
		cacheSize, err := strconv.Atoi(request.FormValue("cache_size"))
		if err != nil || cacheSize <= 0 {
			return errors.New("cache size must be positive")
		}
		candidate.Server.DNSListen = dnsListeners
		candidate.Server.HTTPSListen = strings.TrimSpace(request.FormValue("https_listen"))
		candidate.Resolver.Mode = resolverMode
		candidate.Resolver.Forwarders = forwarders
		candidate.Resolver.RootHints = formLines(request.FormValue("root_hints"))
		candidate.Resolver.Timeout = config.Duration{Duration: resolverTimeout}
		candidate.Resolver.CacheSize = cacheSize
		candidate.Resolver.CacheMinimumTTL = cacheMinimumTTL
		candidate.Resolver.CacheMaximumTTL = cacheMaximumTTL
		candidate.Resolver.CacheNegativeTTL = cacheNegativeTTL
		candidate.Resolver.CacheFailureTTL = cacheFailureTTL
		candidate.Resolver.SaveCache = request.FormValue("save_cache") == "true"
		candidate.Resolver.ServeStale = request.FormValue("serve_stale") == "true"
		candidate.Resolver.CacheStaleTTL = cacheStaleTTL
		candidate.Resolver.CacheStaleAnswerTTL = cacheStaleAnswerTTL
		candidate.Resolver.CacheStaleResetTTL = cacheStaleResetTTL
		candidate.Resolver.CacheStaleMaxWait.Duration = time.Duration(cacheStaleMaxWaitMS) * time.Millisecond
		candidate.Resolver.CachePrefetchMinimumTTL = cachePrefetchMinimumTTL
		candidate.Resolver.CachePrefetchTriggerTTL = cachePrefetchTriggerTTL
		candidate.Resolver.CachePrefetchSample.Duration = cachePrefetchSample
		candidate.Resolver.CachePrefetchHitsPerHour = cachePrefetchHits
		candidate.Resolver.DNSSECValidation = request.FormValue("dnssec_validation") == "true"
		candidate.Resolver.DNSSECTrustAnchorUpdates = request.FormValue("trust_anchor_updates") == "true"
		candidate.EncryptedDNS.DoTListen = formLines(request.FormValue("dot_listen"))
		candidate.EncryptedDNS.DoHListen = formLines(request.FormValue("doh_listen"))
		candidate.EncryptedDNS.DoQListen = formLines(request.FormValue("doq_listen"))
		candidate.EncryptedDNS.CertificateMode = certificateMode
		candidate.EncryptedDNS.CertificateFile = strings.TrimSpace(request.FormValue("certificate_file"))
		candidate.EncryptedDNS.PrivateKeyFile = strings.TrimSpace(request.FormValue("private_key_file"))
		candidate.EncryptedDNS.MinimumVersion = strings.TrimSpace(request.FormValue("minimum_tls_version"))
		candidate.EncryptedDNS.ACME.Email = strings.TrimSpace(request.FormValue("acme_email"))
		candidate.EncryptedDNS.ACME.Domains = formLines(request.FormValue("acme_domains"))
		candidate.EncryptedDNS.ACME.DirectoryURL = strings.TrimSpace(request.FormValue("acme_directory_url"))
		candidate.EncryptedDNS.ACME.DNSProvider = strings.TrimSpace(request.FormValue("acme_dns_provider"))
		candidate.EncryptedDNS.ACME.DNSZone = strings.TrimSpace(request.FormValue("acme_dns_zone"))
		candidate.EncryptedDNS.ACME.StorageDirectory = strings.TrimSpace(request.FormValue("acme_storage_dir"))
		candidate.EncryptedDNS.ACME.RenewBefore = config.Duration{Duration: acmeRenewBefore}
		candidate.QueryLog.Enabled = request.FormValue("query_log_enabled") == "true"
		candidate.Blocking.UpdateInterval.Duration = time.Duration(blockingUpdateHours) * time.Hour
		candidate.Blocking.ResponseType = blockingResponseType
		candidate.Blocking.ResponseTTL = uint32(blockingResponseTTL)
		candidate.Blocking.CustomAddresses = formLines(request.FormValue("blocking_custom_addresses"))
		candidate.Blocking.BypassClients = formLines(request.FormValue("blocking_bypass_clients"))
		candidate.Blocking.AllowTXTReport = request.FormValue("blocking_allow_txt_report") == "true"
		return nil
	})
	if err != nil {
		server.logger.Warn("settings update failed", "client", requestClientIP(request), "error", err)
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	server.recordControlPlaneAudit(request, "settings.update", "cluster-scoped DNS settings updated")
	server.blockLists.Schedule(time.Now().Add(server.config.Current().Config.Blocking.UpdateInterval.Duration))
	server.logger.Info("settings updated", "client", requestClientIP(request), "revision", server.config.Current().Revision)
	server.renderSettingsMutation(writer, request, http.StatusOK, "Settings saved and applied", "")
}

func certificateCredentialsFromForm(request *http.Request, provider string) certificates.Credentials {
	return certificates.Credentials{
		APIToken: strings.TrimSpace(request.FormValue(provider + "_api_token")), APIKey: strings.TrimSpace(request.FormValue(provider + "_api_key")),
		Secret: strings.TrimSpace(request.FormValue(provider + "_secret")), Username: strings.TrimSpace(request.FormValue(provider + "_username")),
		ClientIP: strings.TrimSpace(request.FormValue(provider + "_client_ip")), ZoneID: strings.TrimSpace(request.FormValue(provider + "_zone_id")),
		Server: strings.TrimSpace(request.FormValue(provider + "_server")), TSIGName: strings.TrimSpace(request.FormValue(provider + "_tsig_name")),
		TSIGSecret: strings.TrimSpace(request.FormValue(provider + "_tsig_secret")), TSIGAlgorithm: strings.TrimSpace(request.FormValue(provider + "_tsig_algorithm")),
		AccessKeyID: strings.TrimSpace(request.FormValue(provider + "_access_key_id")), SecretAccessKey: strings.TrimSpace(request.FormValue(provider + "_secret_access_key")),
		SessionToken: strings.TrimSpace(request.FormValue(provider + "_session_token")), Endpoint: strings.TrimSpace(request.FormValue(provider + "_endpoint")),
		ApplicationKey: strings.TrimSpace(request.FormValue(provider + "_application_key")), ApplicationSecret: strings.TrimSpace(request.FormValue(provider + "_application_secret")),
		ConsumerKey: strings.TrimSpace(request.FormValue(provider + "_consumer_key")),
	}
}

func (server *Server) renewCertificate(writer http.ResponseWriter, request *http.Request) {
	if server.certificates == nil {
		server.renderSettingsMutation(writer, request, http.StatusServiceUnavailable, "", "Certificate automation service is unavailable.")
		return
	}
	configuration := server.config.Current().Config.EncryptedDNS
	if configuration.CertificateMode != "acme" {
		server.renderSettingsMutation(writer, request, http.StatusConflict, "", "Managed ACME mode is not enabled.")
		return
	}
	changed, err := server.certificates.Ensure(request.Context(), configuration, true)
	if err != nil {
		server.logger.Warn("renew public TLS certificate", "client", requestClientIP(request), "error", err)
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	if changed && server.reload != nil {
		if err := server.reload(request.Context()); err != nil {
			server.logger.Error("activate renewed public TLS certificate", "error", err)
			server.renderSettingsMutation(writer, request, http.StatusInternalServerError, "", "The certificate was issued, but activating it failed: "+err.Error())
			return
		}
	}
	server.logger.Info("public TLS certificate renewed", "client", requestClientIP(request), "listeners_reloaded", changed)
	server.recordControlPlaneAudit(request, "certificate.renew", "manually renewed the public TLS certificate")
	server.renderSettingsMutation(writer, request, http.StatusOK, "Certificate issued and activated.", "")
}

func (server *Server) generateManualCertificate(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderCertificateMutation(writer, request, http.StatusBadRequest, "", "Invalid certificate form.")
		return
	}
	generator, editor, ok := server.certificateMutationServices()
	if !ok {
		server.renderCertificateMutation(writer, request, http.StatusNotImplemented, "", "Certificate generation is unavailable.")
		return
	}
	validFor, err := certificateValidity(request.FormValue("manual_certificate_valid_days"), 365)
	if err != nil {
		server.renderCertificateMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	result, err := generator.GenerateSelfSigned(request.Context(), certificates.ManualCertificateOptions{
		Names:            formLines(request.FormValue("manual_certificate_names")),
		StorageDirectory: strings.TrimSpace(request.FormValue("manual_certificate_storage_dir")),
		ValidFor:         validFor,
	})
	if err != nil {
		server.logger.Warn("generate self-signed public certificate", "client", requestClientIP(request), "error", err)
		server.renderCertificateMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	if err := server.useManualCertificate(request.Context(), editor, result); err != nil {
		server.renderCertificateMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	server.logger.Info("self-signed public certificate configured", "client", requestClientIP(request), "certificate", result.CertificateFile, "expires", result.NotAfter)
	server.recordControlPlaneAudit(request, "certificate.generate", "generated and configured a self-signed public TLS certificate")
	server.renderCertificateMutation(writer, request, http.StatusOK, "Self-signed certificate generated and activated.", "")
}

func (server *Server) importManualCertificate(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderCertificateMutation(writer, request, http.StatusBadRequest, "", "Invalid certificate form.")
		return
	}
	generator, editor, ok := server.certificateMutationServices()
	if !ok {
		server.renderCertificateMutation(writer, request, http.StatusNotImplemented, "", "Certificate import is unavailable.")
		return
	}
	result, err := generator.ImportKeyPair(request.Context(), certificates.ImportCertificateOptions{
		CertificatePEM:   []byte(strings.TrimSpace(request.FormValue("manual_certificate_pem")) + "\n"),
		PrivateKeyPEM:    []byte(strings.TrimSpace(request.FormValue("manual_private_key_pem")) + "\n"),
		StorageDirectory: strings.TrimSpace(request.FormValue("manual_import_storage_dir")),
	})
	if err != nil {
		server.logger.Warn("import public certificate", "client", requestClientIP(request), "error", err)
		server.renderCertificateMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	if err := server.useManualCertificate(request.Context(), editor, result); err != nil {
		server.renderCertificateMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	server.logger.Info("public certificate imported and configured", "client", requestClientIP(request), "certificate", result.CertificateFile, "expires", result.NotAfter)
	server.recordControlPlaneAudit(request, "certificate.import", "imported and configured a public TLS certificate")
	server.renderCertificateMutation(writer, request, http.StatusOK, "Certificate and private key imported and activated.", "")
}

func (server *Server) certificateMutationServices() (certificateGenerator, settingsEditor, bool) {
	generator, generated := server.certificates.(certificateGenerator)
	editor, editable := server.config.(settingsEditor)
	return generator, editor, generated && editable
}

func (server *Server) useManualCertificate(ctx context.Context, editor settingsEditor, result certificates.GeneratedCertificate) error {
	return editor.Update(ctx, func(candidate *config.Config) error {
		candidate.EncryptedDNS.CertificateMode = "manual"
		candidate.EncryptedDNS.CertificateFile = result.CertificateFile
		candidate.EncryptedDNS.PrivateKeyFile = result.PrivateKeyFile
		return nil
	})
}

func (server *Server) renderCertificateMutation(writer http.ResponseWriter, request *http.Request, status int, message, errorMessage string) {
	if request.Form == nil {
		request.Form = make(map[string][]string)
	}
	request.Form.Set("settings_tab", "protocols")
	server.renderSettingsMutation(writer, request, status, message, errorMessage)
}

func certificateValidity(value string, defaultDays int) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		value = strconv.Itoa(defaultDays)
	}
	days, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || days < 1 || days > 3650 {
		return 0, errors.New("certificate validity must be between 1 and 3650 days")
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

func (server *Server) renderSettingsMutation(writer http.ResponseWriter, request *http.Request, status int, message, errorMessage string) {
	server.renderSettingsView(writer, request, status, server.settingsView(request, message, errorMessage))
}

// renderSettingsView writes an already-built view. Handlers that have something
// extra to show, such as a freshly generated TSIG secret, fill in the view
// first and render it through here.
func (server *Server) renderSettingsView(writer http.ResponseWriter, request *http.Request, status int, view pages.SettingsPageView) {
	if status != http.StatusOK {
		writer.WriteHeader(status)
	}
	if request.Header.Get("HX-Request") == "true" {
		_ = pages.SettingsContent(view).Render(request.Context(), writer)
		return
	}
	_ = pages.SettingsPage(view).Render(request.Context(), writer)
}

func (server *Server) settingsView(request *http.Request, message, errorMessage string) pages.SettingsPageView {
	snapshot := server.config.Current()
	configuration := snapshot.Config
	activeTab := request.FormValue("settings_tab")
	if activeTab == "" {
		activeTab = request.URL.Query().Get("tab")
	}
	switch activeTab {
	case "general", "web-service", "protocols", "tsig", "recursion", "cache", "blocking", "proxy", "logging", "backup":
	default:
		activeTab = "general"
	}
	view := pages.SettingsPageView{
		Console: server.consoleView(request), Revision: snapshot.Revision,
		TimeFormat: requestTimeFormat(request),
		TimeZone:   requestTimeDisplay(request).Zone(),
		ActiveTab:  activeTab,
		Message:    message, Error: errorMessage,
		Backup:     server.backupView(request, "", ""),
		HTTPListen: configuration.Server.HTTPListen, HTTPSListen: configuration.Server.HTTPSListen, DNSListen: strings.Join(configuration.Server.DNSListen, "\n"),
		DatabaseDriver: configuration.Database.Driver, DatabaseDSN: configuration.Database.DSN,
		ResolverMode: configuration.Resolver.Mode, Forwarders: strings.Join(configuration.Resolver.Forwarders, "\n"),
		RootHints: strings.Join(configuration.Resolver.RootHints, "\n"), ResolverTimeout: configuration.Resolver.Timeout.String(),
		CacheSize: configuration.Resolver.CacheSize, DNSSECValidation: configuration.Resolver.DNSSECValidation,
		CacheMinimumTTL: configuration.Resolver.CacheMinimumTTL, CacheMaximumTTL: configuration.Resolver.CacheMaximumTTL,
		CacheNegativeTTL: configuration.Resolver.CacheNegativeTTL, CacheFailureTTL: configuration.Resolver.CacheFailureTTL,
		SaveCache:  configuration.Resolver.SaveCache,
		ServeStale: configuration.Resolver.ServeStale, CacheStaleTTL: configuration.Resolver.CacheStaleTTL,
		CacheStaleAnswerTTL:      configuration.Resolver.CacheStaleAnswerTTL,
		CacheStaleResetTTL:       configuration.Resolver.CacheStaleResetTTL,
		CacheStaleMaxWaitMS:      configuration.Resolver.CacheStaleMaxWait.Milliseconds(),
		CachePrefetchMinimumTTL:  configuration.Resolver.CachePrefetchMinimumTTL,
		CachePrefetchTriggerTTL:  configuration.Resolver.CachePrefetchTriggerTTL,
		CachePrefetchSample:      configuration.Resolver.CachePrefetchSample.String(),
		CachePrefetchHitsPerHour: configuration.Resolver.CachePrefetchHitsPerHour,
		TrustAnchorUpdates:       configuration.Resolver.DNSSECTrustAnchorUpdates,
		DoTListen:                strings.Join(configuration.EncryptedDNS.DoTListen, "\n"), DoHListen: strings.Join(configuration.EncryptedDNS.DoHListen, "\n"),
		DoQListen:       strings.Join(configuration.EncryptedDNS.DoQListen, "\n"),
		CertificateFile: configuration.EncryptedDNS.CertificateFile, PrivateKeyFile: configuration.EncryptedDNS.PrivateKeyFile,
		CertificateMode: configuration.EncryptedDNS.CertificateMode,
		ACMEEmail:       configuration.EncryptedDNS.ACME.Email, ACMEDomains: strings.Join(configuration.EncryptedDNS.ACME.Domains, "\n"),
		ACMEDirectoryURL: configuration.EncryptedDNS.ACME.DirectoryURL, ACMEDNSProvider: configuration.EncryptedDNS.ACME.DNSProvider,
		ACMEDNSZone: configuration.EncryptedDNS.ACME.DNSZone, ACMEStorageDirectory: configuration.EncryptedDNS.ACME.StorageDirectory,
		ACMERenewBefore:   configuration.EncryptedDNS.ACME.RenewBefore.String(),
		MinimumTLSVersion: configuration.EncryptedDNS.MinimumVersion, QueryLogEnabled: configuration.QueryLog.Enabled,
		QueryLogRetention: configuration.QueryLog.Retention.String(), SessionTTL: configuration.Security.SessionTTL.String(),
		APITokenTTL: configuration.Security.APITokenTTL.String(), ConfigWatch: configuration.Reload.Watch,
		BlockingUpdateHours:  max(1, int(configuration.Blocking.UpdateInterval.Duration/time.Hour)),
		BlockingResponseType: configuration.Blocking.ResponseType, BlockingResponseTTL: configuration.Blocking.ResponseTTL,
		BlockingCustomAddresses: strings.Join(configuration.Blocking.CustomAddresses, "\n"),
		BlockingBypassClients:   strings.Join(configuration.Blocking.BypassClients, "\n"), BlockingAllowTXTReport: configuration.Blocking.AllowTXTReport,
		TSIGKeys:       server.tsigKeyViews(request.Context()),
		TSIGAlgorithms: tsig.Algorithms(),
	}
	if server.certificates != nil {
		status := server.certificates.Status(request.Context(), configuration.EncryptedDNS)
		view.ACMECredentialsConfigured = status.CredentialsConfigured
		view.ACMEIssuer = status.Issuer
		if !status.NotAfter.IsZero() {
			view.ACMEExpires = status.NotAfter.Format("Jan 2, 2006")
		}
		if !status.NotBefore.IsZero() {
			view.ACMEIssuedOn = status.NotBefore.Format("Jan 2, 2006")
		}
		if !status.LastSuccess.IsZero() {
			view.ACMELastRenewal = status.LastSuccess.Format("Jan 2, 2006 15:04 MST")
		}
		view.ACMESubject = status.Subject
		view.ACMESerialNumber = status.SerialNumber
		view.ACMEFingerprint = status.Fingerprint
		view.ACMECoveredNames = status.CoveredNames
		view.ACMEPendingNames = pendingCertificateNames(status.Domains, status.CoveredNames)
		view.ACMELastError = status.LastError
		view.ACMERenewing = status.Renewing
		view.ACMEProviderEndpoint = status.ProviderEndpoint
		view.ACMETSIGAlgorithm = status.TSIGAlgorithm
	}
	return view
}

// pendingCertificateNames returns the configured names the installed
// certificate does not cover yet. Adding a name to the settings does not put it
// on the certificate until the next issuance succeeds, and a client dialing an
// uncovered name sees a TLS error rather than anything the console would
// otherwise surface.
func pendingCertificateNames(configured, covered []string) []string {
	if len(configured) == 0 || len(covered) == 0 {
		return nil
	}
	present := make(map[string]struct{}, len(covered))
	for _, name := range covered {
		present[strings.ToLower(strings.TrimSuffix(name, "."))] = struct{}{}
	}
	pending := make([]string, 0, len(configured))
	for _, name := range configured {
		normalized := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if normalized == "" {
			continue
		}
		if _, ok := present[normalized]; !ok {
			pending = append(pending, normalized)
		}
	}
	slices.Sort(pending)
	return slices.Compact(pending)
}

func parseUint32Setting(value, label string, allowZero bool) (uint32, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil || (!allowZero && parsed == 0) {
		return 0, fmt.Errorf("%s must be %s", label, ifThenString(allowZero, "a non-negative number", "a positive number"))
	}
	return uint32(parsed), nil
}

func ifThenString(condition bool, yes, no string) string {
	if condition {
		return yes
	}
	return no
}

func formLines(value string) []string {
	lines := strings.FieldsFunc(value, func(character rune) bool { return character == '\n' || character == '\r' || character == ',' })
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func (server *Server) recordControlPlaneAudit(request *http.Request, action, details string) {
	recorder, ok := server.queries.(interface {
		RecordAuditEvent(context.Context, auth.AuditEvent) error
	})
	if !ok {
		return
	}
	event := auth.AuditEvent{
		OccurredAt: time.Now(), Action: action, ClientIP: requestClientIP(request),
		UserAgent: request.UserAgent(), Details: details,
	}
	if principal, ok := request.Context().Value(principalContextKey{}).(auth.Principal); ok && principal.UserID != 0 {
		event.UserID = &principal.UserID
	}
	if err := recorder.RecordAuditEvent(request.Context(), event); err != nil {
		server.logger.Warn("record control-plane audit event", "action", action, "error", err)
	}
}
