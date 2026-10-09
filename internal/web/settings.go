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

	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/durationfmt"
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
	server.render(writer, request, pages.SettingsPage(view))
}

func (server *Server) updateSettings(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		server.renderSettingsMutation(writer, request, http.StatusBadRequest, "", "Invalid settings form.")
		return
	}
	editor, ok := server.config.(settingsEditor)
	if !ok {
		server.renderSettingsMutation(writer, request, http.StatusNotImplemented, "", "Settings are read-only.")
		return
	}
	form, err := parseSettingsForm(request)
	if err != nil {
		server.renderSettingsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	if form.certificateMode == "acme" {
		if status, err := server.saveACMECredentials(request); err != nil {
			server.renderSettingsMutation(writer, request, status, "", err.Error())
			return
		}
	}
	err = editor.Update(request.Context(), func(candidate *config.Config) error {
		if request.PostForm.Has("update_preferences_present") {
			if err := server.applyUpdatePreferences(request, candidate); err != nil {
				return err
			}
		}
		if err := server.applyPasskeySetting(request, candidate); err != nil {
			return err
		}
		if err := applyResolverSettings(request, candidate, form); err != nil {
			return err
		}
		applyEncryptedDNSSettings(request, &candidate.EncryptedDNS, form)
		applyLogAndBlockingSettings(request, candidate, form)
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

// settingsForm holds the Settings fields that are checked before the
// configuration is edited.
type settingsForm struct {
	queryLogRetention       time.Duration
	serverLogRetention      time.Duration
	statisticsRetention     time.Duration
	blockingUpdateHours     int
	blockingResponseType    string
	blockingResponseTTL     uint32
	cacheMinimumTTL         uint32
	cacheMaximumTTL         uint32
	cacheNegativeTTL        uint32
	cacheFailureTTL         uint32
	cacheStaleTTL           uint32
	cacheStaleAnswerTTL     uint32
	cacheStaleResetTTL      uint32
	cacheStaleMaxWait       time.Duration
	cachePrefetchMinimumTTL uint32
	cachePrefetchTriggerTTL uint32
	cachePrefetchSample     time.Duration
	cachePrefetchHits       uint32
	certificateMode         string
	acmeRenewBefore         time.Duration
}

// parseSettingsForm reads the Settings fields in form order and returns the
// first problem as a message for the person editing them.
func parseSettingsForm(request *http.Request) (settingsForm, error) {
	var form settingsForm
	var err error
	if form.queryLogRetention, err = parsePositiveDurationSetting(request.FormValue("query_log_retention"), "query log retention"); err != nil {
		return form, err
	}
	if form.serverLogRetention, err = parsePositiveDurationSetting(request.FormValue("server_log_retention"), "server log retention"); err != nil {
		return form, err
	}
	if form.statisticsRetention, err = parsePositiveDurationSetting(request.FormValue("statistics_retention"), "statistics retention"); err != nil {
		return form, err
	}
	form.blockingUpdateHours, err = strconv.Atoi(request.FormValue("blocking_update_hours"))
	if err != nil || form.blockingUpdateHours < 1 || form.blockingUpdateHours > 8760 {
		return form, errors.New("Block-list update interval must be between 1 and 8760 hours.")
	}
	form.blockingResponseType = strings.TrimSpace(request.FormValue("blocking_response_type"))
	if form.blockingResponseType != "zero" && form.blockingResponseType != "nxdomain" && form.blockingResponseType != "custom" {
		return form, errors.New("Blocking response type is invalid.")
	}
	blockingResponseTTL, err := strconv.ParseUint(request.FormValue("blocking_response_ttl"), 10, 32)
	if err != nil {
		return form, errors.New("Blocking response TTL must be a non-negative number.")
	}
	form.blockingResponseTTL = uint32(blockingResponseTTL)
	if err := form.parseCache(request); err != nil {
		return form, err
	}
	form.certificateMode = strings.ToLower(strings.TrimSpace(request.FormValue("certificate_mode")))
	if form.certificateMode == "" {
		form.certificateMode = "manual"
	}
	if form.certificateMode != "manual" && form.certificateMode != "acme" {
		return form, errors.New("Certificate mode must be manual or managed ACME.")
	}
	form.acmeRenewBefore = 30 * 24 * time.Hour
	if form.certificateMode == "acme" {
		if form.acmeRenewBefore, err = durationfmt.Parse(request.FormValue("acme_renew_before")); err != nil {
			return form, errors.New("ACME renewal window is invalid.")
		}
	}
	return form, nil
}

func (form *settingsForm) parseCache(request *http.Request) error {
	var err error
	if form.cacheMinimumTTL, err = parseUint32Setting(request.FormValue("cache_minimum_ttl"), "minimum cache TTL", true); err != nil {
		return err
	}
	form.cacheMaximumTTL, err = parseUint32Setting(request.FormValue("cache_maximum_ttl"), "maximum cache TTL", false)
	if err != nil || form.cacheMinimumTTL > form.cacheMaximumTTL {
		return errors.New("Maximum cache TTL must be positive and no smaller than the minimum cache TTL.")
	}
	if form.cacheNegativeTTL, err = parseUint32Setting(request.FormValue("cache_negative_ttl"), "negative cache TTL", true); err != nil {
		return err
	}
	if form.cacheFailureTTL, err = parseUint32Setting(request.FormValue("cache_failure_ttl"), "failure cache TTL", true); err != nil {
		return err
	}
	if form.cacheStaleTTL, err = parseUint32Setting(request.FormValue("cache_stale_ttl"), "maximum stale age", false); err != nil {
		return err
	}
	if form.cacheStaleAnswerTTL, err = parseUint32Setting(request.FormValue("cache_stale_answer_ttl"), "stale answer TTL", false); err != nil {
		return err
	}
	if form.cacheStaleResetTTL, err = parseUint32Setting(request.FormValue("cache_stale_reset_ttl"), "stale retry TTL", false); err != nil {
		return err
	}
	staleMaxWaitMS, err := strconv.ParseInt(strings.TrimSpace(request.FormValue("cache_stale_max_wait_ms")), 10, 64)
	if err != nil || staleMaxWaitMS < 1 || staleMaxWaitMS > 60_000 {
		return errors.New("Stale max wait must be between 1 and 60000 milliseconds.")
	}
	form.cacheStaleMaxWait = time.Duration(staleMaxWaitMS) * time.Millisecond
	if form.cachePrefetchMinimumTTL, err = parseUint32Setting(request.FormValue("cache_prefetch_minimum_ttl"), "prefetch eligibility TTL", true); err != nil {
		return err
	}
	if form.cachePrefetchTriggerTTL, err = parseUint32Setting(request.FormValue("cache_prefetch_trigger_ttl"), "prefetch trigger TTL", true); err != nil {
		return err
	}
	form.cachePrefetchSample, err = durationfmt.Parse(request.FormValue("cache_prefetch_sample_interval"))
	if err != nil || form.cachePrefetchSample <= 0 || form.cachePrefetchSample > 24*time.Hour {
		return errors.New("Prefetch sample interval must be a positive duration no greater than 24h.")
	}
	if form.cachePrefetchHits, err = parseUint32Setting(request.FormValue("cache_prefetch_hits_per_hour"), "prefetch hits per hour", false); err != nil {
		return err
	}
	return nil
}

// saveACMECredentials stores the DNS provider credentials typed into the
// managed-certificate fields, if any, before the settings that use them are
// saved. The status is the response code for a returned error.
func (server *Server) saveACMECredentials(request *http.Request) (int, error) {
	if server.certificates == nil {
		return http.StatusServiceUnavailable, errors.New("Certificate automation service is unavailable.")
	}
	provider := strings.ToLower(strings.TrimSpace(request.FormValue("acme_dns_provider")))
	credentials := certificateCredentialsFromForm(request, provider)
	if credentials != (certificates.Credentials{}) {
		if err := server.certificates.PutCredentials(request.Context(), provider, credentials); err != nil {
			return http.StatusUnprocessableEntity, err
		}
	}
	return http.StatusOK, nil
}

func (server *Server) applyPasskeySetting(request *http.Request, candidate *config.Config) error {
	if !request.PostForm.Has("passkeys_present") {
		return nil
	}
	disabled := request.FormValue("passkeys_enabled") != "true"
	if disabled {
		validator, ok := server.auth.(interface {
			ValidatePasskeyDisable(context.Context, string) error
		})
		if !ok {
			return errors.New("passkey settings are unavailable")
		}
		issuer := ""
		if candidate.OIDC.Enabled {
			issuer = candidate.OIDC.Issuer
		}
		if err := validator.ValidatePasskeyDisable(request.Context(), issuer); err != nil {
			return err
		}
	}
	candidate.Security.PasskeysDisabled = disabled
	return nil
}

func applyResolverSettings(request *http.Request, candidate *config.Config, form settingsForm) error {
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
	resolverTimeout, err := durationfmt.Parse(request.FormValue("resolver_timeout"))
	if err != nil {
		return errors.New("resolver timeout is invalid")
	}
	resolverRetries, err := strconv.Atoi(strings.TrimSpace(request.FormValue("resolver_retries")))
	if err != nil || resolverRetries < 1 || resolverRetries > 10 {
		return errors.New("resolver retries must be a whole number between 1 and 10")
	}
	resolverRetryTimeout, err := durationfmt.Parse(request.FormValue("resolver_retry_timeout"))
	if err != nil || resolverRetryTimeout <= 0 {
		return errors.New("resolver retry timeout is invalid")
	}
	cacheSize, err := strconv.Atoi(request.FormValue("cache_size"))
	if err != nil || cacheSize <= 0 {
		return errors.New("cache size must be positive")
	}
	candidate.Server.DNSListen = dnsListeners
	candidate.Server.HTTPSListen = strings.TrimSpace(request.FormValue("https_listen"))
	resolver := &candidate.Resolver
	resolver.Mode = resolverMode
	if request.Form.Has("max_concurrent") {
		total, err := strconv.Atoi(request.FormValue("max_concurrent"))
		if err != nil || total < 1 || total > 65536 {
			return errors.New("maximum concurrent resolutions must be between 1 and 65536")
		}
		perClient, err := strconv.Atoi(request.FormValue("max_concurrent_per_client"))
		if err != nil || perClient < 1 || perClient > total {
			return errors.New("per-client concurrent resolutions must be between 1 and the total limit")
		}
		resolver.MaxConcurrent = total
		resolver.MaxConcurrentPerClient = perClient
	}
	if request.Form.Has("recursion") {
		resolver.Recursion = request.FormValue("recursion")
		resolver.RecursionClients = formLines(request.FormValue("recursion_clients"))
	}
	resolver.Forwarders = forwarders
	resolver.RootHints = formLines(request.FormValue("root_hints"))
	resolver.Timeout = config.Duration{Duration: resolverTimeout}
	resolver.Retries = resolverRetries
	resolver.RetryTimeout = config.Duration{Duration: resolverRetryTimeout}
	resolver.CacheSize = cacheSize
	applyCacheSettings(request, resolver, form)
	resolver.DNSSECValidation = request.FormValue("dnssec_validation") == "true"
	resolver.QNAMEMinimization = request.FormValue("qname_minimization") == "true"
	resolver.DNSSECTrustAnchorUpdates = request.FormValue("trust_anchor_updates") == "true"
	return nil
}

func applyCacheSettings(request *http.Request, resolver *config.Resolver, form settingsForm) {
	resolver.CacheMinimumTTL = form.cacheMinimumTTL
	resolver.CacheMaximumTTL = form.cacheMaximumTTL
	resolver.CacheNegativeTTL = form.cacheNegativeTTL
	resolver.CacheFailureTTL = form.cacheFailureTTL
	resolver.SaveCache = request.FormValue("save_cache") == "true"
	resolver.ServeStale = request.FormValue("serve_stale") == "true"
	resolver.CacheStaleTTL = form.cacheStaleTTL
	resolver.CacheStaleAnswerTTL = form.cacheStaleAnswerTTL
	resolver.CacheStaleResetTTL = form.cacheStaleResetTTL
	resolver.CacheStaleMaxWait.Duration = form.cacheStaleMaxWait
	resolver.CachePrefetchMinimumTTL = form.cachePrefetchMinimumTTL
	resolver.CachePrefetchTriggerTTL = form.cachePrefetchTriggerTTL
	resolver.CachePrefetchSample.Duration = form.cachePrefetchSample
	resolver.CachePrefetchHitsPerHour = form.cachePrefetchHits
}

func applyEncryptedDNSSettings(request *http.Request, encrypted *config.EncryptedDNS, form settingsForm) {
	encrypted.DoTListen = formLines(request.FormValue("dot_listen"))
	encrypted.DoHListen = formLines(request.FormValue("doh_listen"))
	encrypted.DoQListen = formLines(request.FormValue("doq_listen"))
	encrypted.CertificateMode = form.certificateMode
	encrypted.CertificateFile = strings.TrimSpace(request.FormValue("certificate_file"))
	encrypted.PrivateKeyFile = strings.TrimSpace(request.FormValue("private_key_file"))
	encrypted.MinimumVersion = strings.TrimSpace(request.FormValue("minimum_tls_version"))
	encrypted.ACME.Email = strings.TrimSpace(request.FormValue("acme_email"))
	encrypted.ACME.Domains = formLines(request.FormValue("acme_domains"))
	encrypted.ACME.DirectoryURL = strings.TrimSpace(request.FormValue("acme_directory_url"))
	encrypted.ACME.DNSProvider = strings.TrimSpace(request.FormValue("acme_dns_provider"))
	encrypted.ACME.DNSZone = strings.TrimSpace(request.FormValue("acme_dns_zone"))
	encrypted.ACME.StorageDirectory = strings.TrimSpace(request.FormValue("acme_storage_dir"))
	encrypted.ACME.RenewBefore = config.Duration{Duration: form.acmeRenewBefore}
}

func applyLogAndBlockingSettings(request *http.Request, candidate *config.Config, form settingsForm) {
	candidate.QueryLog.Enabled = request.FormValue("query_log_enabled") == "true"
	candidate.QueryLog.Retention = config.Duration{Duration: form.queryLogRetention}
	candidate.ServerLog.Enabled = request.FormValue("server_log_enabled") == "true"
	candidate.ServerLog.Level = strings.ToLower(strings.TrimSpace(request.FormValue("server_log_level")))
	candidate.ServerLog.Retention = config.Duration{Duration: form.serverLogRetention}
	candidate.Statistics.Retention = config.Duration{Duration: form.statisticsRetention}
	candidate.Blocking.UpdateInterval.Duration = time.Duration(form.blockingUpdateHours) * time.Hour
	candidate.Blocking.ResponseType = form.blockingResponseType
	candidate.Blocking.ResponseTTL = form.blockingResponseTTL
	candidate.Blocking.CustomAddresses = formLines(request.FormValue("blocking_custom_addresses"))
	candidate.Blocking.AllowTXTReport = request.FormValue("blocking_allow_txt_report") == "true"
}

func certificateCredentialsFromForm(request *http.Request, provider string) certificates.Credentials {
	return certificateCredentialsFromFormPrefix(request, provider, "")
}

func certificateCredentialsFromFormPrefix(request *http.Request, provider, prefix string) certificates.Credentials {
	field := func(name string) string { return prefix + provider + "_" + name }
	return certificates.Credentials{
		APIToken: strings.TrimSpace(request.FormValue(field("api_token"))), APIKey: strings.TrimSpace(request.FormValue(field("api_key"))),
		Secret: strings.TrimSpace(request.FormValue(field("secret"))), Username: strings.TrimSpace(request.FormValue(field("username"))),
		ClientIP: strings.TrimSpace(request.FormValue(field("client_ip"))), ZoneID: strings.TrimSpace(request.FormValue(field("zone_id"))),
		Server: strings.TrimSpace(request.FormValue(field("server"))), TSIGName: strings.TrimSpace(request.FormValue(field("tsig_name"))),
		TSIGSecret: strings.TrimSpace(request.FormValue(field("tsig_secret"))), TSIGAlgorithm: strings.TrimSpace(request.FormValue(field("tsig_algorithm"))),
		AccessKeyID: strings.TrimSpace(request.FormValue(field("access_key_id"))), SecretAccessKey: strings.TrimSpace(request.FormValue(field("secret_access_key"))),
		SessionToken: strings.TrimSpace(request.FormValue(field("session_token"))), Endpoint: strings.TrimSpace(request.FormValue(field("endpoint"))),
		ApplicationKey: strings.TrimSpace(request.FormValue(field("application_key"))), ApplicationSecret: strings.TrimSpace(request.FormValue(field("application_secret"))),
		ConsumerKey: strings.TrimSpace(request.FormValue(field("consumer_key"))),
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
	writeFragmentStatus(writer, status)
	if request.Header.Get("HX-Request") == "true" {
		server.render(writer, request, pages.SettingsContent(view))
		return
	}
	server.render(writer, request, pages.SettingsPage(view))
}

func (server *Server) settingsView(request *http.Request, message, errorMessage string) pages.SettingsPageView {
	snapshot := server.config.Current()
	configuration := snapshot.Config
	activeTab := request.FormValue("settings_tab")
	if activeTab == "" {
		activeTab = request.URL.Query().Get("tab")
	}
	switch activeTab {
	// Forwarders moved in with the resolver, so a link saved to the old Proxy
	// tab lands where its settings live now.
	case "proxy":
		activeTab = "recursion"
	case "general", "web-service", "protocols", "tsig", "recursion", "cache", "blocking", "logging", "alerts", "backup":
	default:
		activeTab = "general"
	}
	view := pages.SettingsPageView{
		Console: server.consoleView(request), Revision: snapshot.Revision,
		TimeFormat:        requestTimeFormat(request),
		TimeZone:          requestTimeDisplay(request).Zone(),
		ActiveTab:         activeTab,
		UpdatePreferences: server.settingsUpdatePreferencesView(request),
		Message:           message, Error: errorMessage,
		Backup:     server.backupView(request, "", ""),
		HTTPListen: configuration.Server.HTTPListen, HTTPSListen: configuration.Server.HTTPSListen, DNSListen: strings.Join(configuration.Server.DNSListen, "\n"),
		DatabaseDriver: configuration.Database.Driver, DatabaseDSN: configuration.Database.DSN,
		Recursion: configuration.Resolver.Recursion, RecursionClients: strings.Join(configuration.Resolver.RecursionClients, "\n"),
		AttachedNetworks: server.attachedNetworkViews(), MaxConcurrent: configuration.Resolver.MaxConcurrent, MaxConcurrentPerClient: configuration.Resolver.MaxConcurrentPerClient,
		ResolverMode: configuration.Resolver.Mode, Forwarders: strings.Join(configuration.Resolver.Forwarders, "\n"),
		RootHints: strings.Join(configuration.Resolver.RootHints, "\n"), ResolverTimeout: configuration.Resolver.Timeout.String(),
		ResolverRetries: configuration.Resolver.Retries, ResolverRetryTimeout: configuration.Resolver.RetryTimeout.String(),
		CacheSize: configuration.Resolver.CacheSize, DNSSECValidation: configuration.Resolver.DNSSECValidation,
		QNAMEMinimization: configuration.Resolver.QNAMEMinimization,
		CacheMinimumTTL:   configuration.Resolver.CacheMinimumTTL, CacheMaximumTTL: configuration.Resolver.CacheMaximumTTL,
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
		QueryLogRetention: retentionInputValue(configuration.QueryLog.Retention.Duration),
		ServerLogEnabled:  configuration.ServerLog.Enabled, ServerLogLevel: configuration.ServerLog.Level,
		ServerLogRetention:  retentionInputValue(configuration.ServerLog.Retention.Duration),
		StatisticsRetention: retentionInputValue(configuration.Statistics.Retention.Duration),
		PasskeysEnabled:     !configuration.Security.PasskeysDisabled,
		SessionTTL:          configuration.Security.SessionTTL.String(),
		APITokenTTL:         configuration.Security.APITokenTTL.String(), ConfigWatch: configuration.Reload.Watch,
		BlockingUpdateHours:  max(1, int(configuration.Blocking.UpdateInterval.Duration/time.Hour)),
		BlockingResponseType: configuration.Blocking.ResponseType, BlockingResponseTTL: configuration.Blocking.ResponseTTL,
		BlockingCustomAddresses: strings.Join(configuration.Blocking.CustomAddresses, "\n"),
		BlockingAllowTXTReport:  configuration.Blocking.AllowTXTReport,
		TSIGKeys:                server.tsigKeyViews(request.Context()),
		TSIGAlgorithms:          tsig.Algorithms(),
	}
	view.Alerts = server.alertsView(request.Context(), view.Console)
	if view.Alerts.Available && view.Alerts.CanEdit {
		view.Alerts.OpenWatch = alertWatchOpenURL(request.URL.Query())
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
	view.Insights = server.settingsInsightsView(request.Context(), view.Console, "", "")
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

func parsePositiveDurationSetting(value, label string) (time.Duration, error) {
	parsed, err := durationfmt.Parse(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration such as 30d", label)
	}
	return parsed, nil
}

func retentionInputValue(retention time.Duration) string {
	return durationfmt.Format(retention)
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
	server.audit(request.Context(), requestActor(request, ""), action, details)
}
