package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/secrets"
	"github.com/drudge/sable/internal/serverlog"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/trustanchor"
	"github.com/drudge/sable/internal/tsig"
	"github.com/drudge/sable/internal/update"
	"github.com/drudge/sable/internal/version"
	"github.com/drudge/sable/internal/web"
	"github.com/drudge/sable/internal/zone"
)

var ErrRestartRequested = errors.New("controlled restart requested")

func Run(ctx context.Context, configurationPath string, logger *slog.Logger) error {
	runtimeContext, stopRuntime := context.WithCancel(ctx)
	defer stopRuntime()
	startedAt := time.Now()
	runtimeLogs := serverlog.New(serverlog.DefaultCapacity)
	// baseLogger stays unwrapped so the server log recorder can report its own
	// failures without feeding them back into the buffer it drains.
	baseLogger := logger
	logger = slog.New(serverlog.NewHandler(logger.Handler(), runtimeLogs))
	absolutePath, initial, err := loadConfiguration(configurationPath)
	if err != nil {
		return err
	}
	configurationDirectory := filepath.Dir(absolutePath)

	database, err := store.Open(ctx, initial.Database.Driver, initial.Database.DSN)
	if err != nil {
		return err
	}
	defer database.Close()
	// The recorder attaches here rather than alongside the other services so
	// the startup that follows is persisted too, and it is closed by defer so
	// every path out of Run flushes it, including the startup failures that
	// are the most valuable thing to still have after a restart. Deferred
	// after database.Close, so it runs before it.
	serverLogRecorder, err := serverlog.NewRecorder(database, serverlog.Options{
		Enabled:       initial.ServerLog.Enabled,
		BufferSize:    initial.ServerLog.BufferSize,
		BatchSize:     initial.ServerLog.BatchSize,
		FlushInterval: initial.ServerLog.FlushInterval.Duration,
		Retention:     initial.ServerLog.Retention.Duration,
	}, baseLogger)
	if err != nil {
		return fmt.Errorf("start server log recorder: %w", err)
	}
	defer closeServerLogRecorder(serverLogRecorder, initial)
	runtimeLogs.Attach(serverLogRecorder)
	secretVault, err := secrets.Open(initial.SecuritySecretKeyPath(configurationDirectory), database)
	if err != nil {
		return fmt.Errorf("initialize secret vault: %w", err)
	}

	var authentication *auth.Service
	setupRequired := false
	if initial.Security.Enabled {
		if err := database.PruneExpiredAuthentication(ctx, time.Now()); err != nil {
			return err
		}
		authentication, err = auth.NewService(database, auth.Options{
			SessionTTL: initial.Security.SessionTTL.Duration,
			TokenTTL:   initial.Security.APITokenTTL.Duration,
		})
		if err != nil {
			return fmt.Errorf("initialize authentication: %w", err)
		}
		setupRequired, err = authentication.SetupRequired(ctx)
		if err != nil {
			return fmt.Errorf("check administrator setup: %w", err)
		}
	}

	tsigSecrets := tsig.NewStore(secretVault)
	dnssec := newDNSSECSigner(secretVault)
	var configurationManager *config.Manager
	var webServer *web.Server
	var handler *dnsserver.Handler
	zoneManager, err := zone.NewManager(
		ctx,
		database,
		// Catalog membership is applied first so a zone a catalog just
		// provisioned exists before aliases and signing look at the set. Alias
		// zones then mirror their source before signing runs, so a mirrored
		// record set is covered by the alias zone's own signatures rather than
		// the stale ones the source was signed with.
		func(ctx context.Context, zones *[]zone.Zone) error {
			logCatalogEvents(logger, zone.ReconcileCatalogs(zones))
			if err := zone.MaterializeAliases(zones, time.Now()); err != nil {
				return err
			}
			if err := zone.MaterializeCatalogs(zones, time.Now()); err != nil {
				return err
			}
			return dnssec.Prepare(ctx, zones)
		},
		func(zones []zone.Zone) error {
			configuration := initial
			if configurationManager != nil {
				configuration = configurationManager.Current().Config
			}
			return zone.ValidateAll(zones, tsigKeyNames(configuration))
		},
		func(activateContext context.Context, _, zones []zone.Zone) error {
			if handler == nil {
				return nil
			}
			configuration := configurationManager.Current().Config
			keys := hydrateTSIGKeys(activateContext, tsigSecrets, configuration, logger).TSIGKeys
			return handler.ActivateZones(authoritativeZones(zones), runtimeTSIGKeys(keys))
		},
	)
	if err != nil {
		return err
	}
	runtime, err := compileRuntime(
		hydrateTSIGKeys(ctx, tsigSecrets, initial, logger),
		zoneManager.Current().Zones,
		configurationDirectory,
	)
	if err != nil {
		return err
	}
	handler = dnsserver.NewHandler(runtime)
	handler.SetLogger(logger)
	handler.StartMaintenance()
	if initial.Resolver.SaveCache {
		restored, restoreErr := restoreDNSCache(ctx, database, handler)
		if restoreErr != nil {
			logger.Warn("restore persisted DNS cache", "error", restoreErr, "restored", restored)
		} else {
			logger.Info("restored persisted DNS cache", "entries", restored)
		}
	}
	trustAnchorManager, err := trustanchor.New(ctx, database, handler.DNSSECTrustAnchorQuery, trustanchor.Options{
		Enabled:  handler.DNSSECTrustAnchorUpdatesEnabled,
		OnChange: handler.ApplyManagedTrustAnchors,
	})
	if err != nil {
		return fmt.Errorf("initialize RFC 5011 trust-anchor manager: %w", err)
	}
	handler.SetTrustAnchorManager(trustAnchorManager)
	queryRecorder, err := querylog.NewRecorder(database, querylog.Options{
		Enabled:       initial.QueryLog.Enabled,
		BufferSize:    initial.QueryLog.BufferSize,
		BatchSize:     initial.QueryLog.BatchSize,
		FlushInterval: initial.QueryLog.FlushInterval.Duration,
		Retention:     initial.QueryLog.Retention.Duration,
	}, logger)
	if err != nil {
		return fmt.Errorf("start query recorder: %w", err)
	}
	handler.SetQueryObserver(queryRecorder)
	listeners := dnsserver.NewListenerGroup(handler, logger)
	certificateManager := certificates.New(secretVault, logger, configurationDirectory)

	apply := func(reloadContext context.Context, active, candidate config.Config) error {
		if err := store.IsBackendChange(
			active.Database.Driver,
			active.Database.DSN,
			candidate.Database.Driver,
			candidate.Database.DSN,
		); err != nil {
			return err
		}
		if active.Server.HTTPListen != candidate.Server.HTTPListen {
			return errors.New("server.http_listen changes require a controlled restart")
		}
		webRestartRequired := active.Server.HTTPSListen != candidate.Server.HTTPSListen
		if err := queryLogWorkerChange(active.QueryLog, candidate.QueryLog); err != nil {
			return err
		}
		if err := serverLogWorkerChange(active.ServerLog, candidate.ServerLog); err != nil {
			return err
		}
		if active.Security != candidate.Security {
			return errors.New("security settings require a controlled restart")
		}
		clusterRestartRequired := active.Cluster != candidate.Cluster
		zones := zoneManager.Current().Zones
		if err := zone.ValidateAll(zones, tsigKeyNames(candidate)); err != nil {
			return fmt.Errorf("validate zones with reloaded configuration: %w", err)
		}
		candidateRuntime, err := compileRuntime(
			hydrateTSIGKeys(reloadContext, tsigSecrets, candidate, logger),
			zones,
			configurationDirectory,
		)
		if err != nil {
			return err
		}
		if _, err := certificateManager.Ensure(reloadContext, candidate.EncryptedDNS, false); err != nil {
			return fmt.Errorf("prepare public TLS certificate: %w", err)
		}
		if err := listeners.Replace(reloadContext, listenerConfiguration(candidate, configurationDirectory)); err != nil {
			return err
		}
		if webServer != nil && candidate.Server.HTTPSListen != "" {
			certificate, privateKey := candidate.EncryptedDNSCertificatePaths(configurationDirectory)
			if err := webServer.ReplaceCertificate(certificate, privateKey); err != nil {
				return err
			}
		}
		handler.Activate(candidateRuntime)
		queryRecorder.SetEnabled(candidate.QueryLog.Enabled)
		serverLogRecorder.SetEnabled(candidate.ServerLog.Enabled)
		if clusterRestartRequired {
			logger.Info("cluster bootstrap settings staged", "restart_required", true)
		}
		if webRestartRequired {
			logger.Info("HTTPS web listener settings staged", "restart_required", true)
		}
		return nil
	}
	configurationManager = config.NewManager(absolutePath, initial, apply)
	if _, err := certificateManager.Ensure(ctx, initial.EncryptedDNS, false); err != nil {
		return errors.Join(fmt.Errorf("prepare public TLS certificate: %w", err), closeQueryRecorderAfterStartupFailure(queryRecorder, initial))
	}
	if err := listeners.Replace(ctx, listenerConfiguration(initial, configurationDirectory)); err != nil {
		return errors.Join(err, closeQueryRecorderAfterStartupFailure(queryRecorder, initial))
	}
	migrateTSIGSecrets(ctx, configurationManager, tsigSecrets, logger)
	dynamicUpdater := newDynamicZoneUpdater(ctx, zoneManager, handler, database, logger)
	handler.SetZoneUpdater(dynamicUpdater.Update)
	handler.SetZoneUpdateAuditor(dynamicUpdater.Audit)
	zoneRefreshContext, stopZoneRefresh := context.WithCancel(runtimeContext)
	defer stopZoneRefresh()
	go newZoneRefresher(zoneManager, handler, logger).Run(zoneRefreshContext)
	go runDNSSECRefresher(zoneRefreshContext, zoneManager, dnssec, handler, logger)
	go trustAnchorManager.Run(zoneRefreshContext, logger)

	unifiCredentials := newUniFiCredentialStore(secretVault)
	oidcSecrets := newOIDCSecretStore(secretVault)
	clusterService, err := cluster.Open(cluster.Options{
		DataDirectory:   initial.ClusterDataPath(configurationDirectory),
		NodeName:        clusterNodeName(initial.Cluster.NodeName),
		AdvertiseURL:    clusterAdvertiseURL(initial),
		HTTPSListen:     initial.Server.HTTPSListen,
		DNSListeners:    initial.Server.DNSListen,
		TrustAnchorFile: initial.ClusterTrustAnchorPath(configurationDirectory),
		Logger:          logger,
		Replicator:      newClusterStateReplicator(configurationManager, zoneManager, database, tsigSecrets, unifiCredentials, oidcSecrets),
		Version:         version.Current().Release,
		StartedAt:       startedAt,
	})
	if err != nil {
		return errors.Join(
			fmt.Errorf("initialize cluster identity: %w", err),
			closeListenersAfterStartupFailure(listeners, initial),
			closeQueryRecorderAfterStartupFailure(queryRecorder, initial),
		)
	}
	handler.SetZoneUpdater(func(updateContext context.Context, request dnsserver.ZoneUpdateRequest) dnsserver.ZoneUpdateResult {
		state := clusterService.Snapshot()
		if state.Initialized && state.LocalRole == cluster.RoleReplica {
			return dnsserver.ZoneUpdateResult{Rcode: dns.RcodeRefused}
		}
		return dynamicUpdater.Update(updateContext, request)
	})

	unifiSync := newUniFiSyncer(
		configurationManager,
		zoneManager,
		unifiCredentials,
		func() bool {
			state := clusterService.Snapshot()
			return !state.Initialized || state.LocalRole != cluster.RoleReplica
		},
		logger,
	)
	go unifiSync.Run(zoneRefreshContext)

	var webAuthentication web.Authenticator
	if authentication != nil {
		webAuthentication = authentication
	}
	webServer, err = web.New(
		logger,
		handler,
		configurationManager,
		zoneManager,
		database.Driver(),
		queryRecorder,
		database,
		configurationManager.Reload,
		webAuthentication,
		initial.Security.Enabled,
		setupRequired,
		initial.Security.SecureCookies,
	)
	if err != nil {
		return errors.Join(
			err,
			clusterService.Close(context.Background()),
			closeListenersAfterStartupFailure(listeners, initial),
			closeQueryRecorderAfterStartupFailure(queryRecorder, initial),
		)
	}
	webServer.SetDNSSECController(dnssec)
	webServer.SetClusterController(clusterService)
	webServer.SetCertificateController(certificateManager)
	webServer.SetUniFiController(unifiSync)
	webServer.SetTSIGController(tsig.NewManager(configurationManager, tsigSecrets))
	if authentication != nil {
		// Single sign-on rides on the authentication service, so a deployment
		// with security switched off has no provider and no sign-in button.
		singleSignOn := newSSOService(configurationManager, oidcSecrets, authentication, logger)
		webServer.SetSSO(singleSignOn)
		webServer.SetSSOAdministration(singleSignOn)
	}
	webServer.SetRuntimeLogs(runtimeLogs)
	if err := webServer.SetStatsStore(ctx, database); err != nil {
		logger.Warn("restore query statistics", "error", err)
	}
	webServer.SetUpdateController(update.NewManager(update.Options{PreRelease: initial.Updates.PreRelease}))
	webServer.SetBackupController(&consoleBackups{configurationPath: absolutePath})
	restartRequests := make(chan struct{}, 1)
	webServer.SetRestartController(func() {
		select {
		case restartRequests <- struct{}{}:
		default:
		}
	})
	if err := webServer.Start(initial.Server.HTTPListen); err != nil {
		return errors.Join(
			err,
			clusterService.Close(context.Background()),
			closeListenersAfterStartupFailure(listeners, initial),
			closeQueryRecorderAfterStartupFailure(queryRecorder, initial),
		)
	}
	if initial.Server.HTTPSListen != "" {
		certificate, privateKey := initial.EncryptedDNSCertificatePaths(configurationDirectory)
		if err := webServer.StartTLS(initial.Server.HTTPSListen, certificate, privateKey, initial.EncryptedDNS.MinimumTLSVersion()); err != nil {
			return errors.Join(
				err,
				webServer.Close(context.Background()),
				clusterService.Close(context.Background()),
				closeListenersAfterStartupFailure(listeners, initial),
				closeQueryRecorderAfterStartupFailure(queryRecorder, initial),
			)
		}
	}
	clusterService.StartMonitoring(runtimeContext)
	go runCertificateRenewal(runtimeContext, certificateManager, configurationManager, listeners, webServer, configurationDirectory, logger)

	releaseInfo := version.Current()
	clusterState := clusterService.Snapshot()
	logger.Info(
		"Sable started",
		"version", releaseInfo.Release,
		"commit", releaseInfo.Commit,
		"go", releaseInfo.Go,
		"dns", initial.Server.DNSListen,
		"dot", initial.EncryptedDNS.DoTListen,
		"doh", initial.EncryptedDNS.DoHListen,
		"doq", initial.EncryptedDNS.DoQListen,
		"http", initial.Server.HTTPListen,
		"https", initial.Server.HTTPSListen,
		"database", initial.Database.Driver,
		"security", initial.Security.Enabled,
		"setup_required", setupRequired,
		"node_id", clusterState.NodeID,
		"cluster_initialized", clusterState.Initialized,
		"cluster_id", clusterState.ClusterID,
		"cluster_network_ready", clusterState.NetworkReady,
		"cluster_role", clusterState.LocalRole,
		"cluster_generation", clusterState.Generation,
	)

	var watchErrors chan error
	if initial.Reload.Watch {
		watchErrors = make(chan error, 1)
		go func() {
			watchErrors <- config.Watch(
				runtimeContext,
				absolutePath,
				initial.Reload.Debounce.Duration,
				logger,
				configurationManager.Reload,
				func() []string {
					return configurationManager.Current().Config.ReloadDependencyPaths(configurationDirectory)
				},
			)
		}()
	}

	restartRequested := false
	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
		case <-restartRequests:
			restartRequested = true
			running = false
		case watchError := <-watchErrors:
			if watchError != nil {
				logger.Error("configuration watcher stopped", "error", watchError)
			}
			watchErrors = nil
		}
	}

	shutdownTimeout := configurationManager.Current().Config.Server.ShutdownTimeout.Duration
	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if restartRequested {
		logger.Info("Sable restarting")
	} else {
		logger.Info("Sable stopping")
	}
	stopRuntime()
	webError := webServer.Close(shutdownContext)
	listenerError := listeners.Close(shutdownContext)
	// Stop background cache refreshes before snapshotting, so what gets persisted
	// is a settled cache rather than one being written to as it is read.
	handler.Close()
	cacheError := persistDNSCache(
		shutdownContext,
		database,
		handler,
		configurationManager.Current().Config.Resolver.SaveCache,
	)
	queryLogError := queryRecorder.Close(shutdownContext)
	clusterError := clusterService.Close(shutdownContext)
	shutdownError := errors.Join(webError, listenerError, cacheError, queryLogError, clusterError)
	if restartRequested {
		if shutdownError != nil {
			logger.Error("controlled restart shutdown failed", "error", shutdownError)
		}
		return errors.Join(ErrRestartRequested, shutdownError)
	}
	return shutdownError
}

func clusterNodeName(configured string) string {
	if configured != "" {
		return configured
	}
	hostname, err := os.Hostname()
	if err == nil && hostname != "" {
		return hostname
	}
	return "sable-node"
}

func clusterAdvertiseURL(configuration config.Config) string {
	if configuration.Cluster.AdvertiseURL != "" {
		return configuration.Cluster.AdvertiseURL
	}
	if configuration.Server.HTTPSListen != "" {
		return "https://" + configuration.Server.HTTPSListen
	}
	return "http://" + configuration.Server.HTTPListen
}

func restoreDNSCache(ctx context.Context, database *store.Store, handler *dnsserver.Handler) (int, error) {
	stored, err := database.CachedResponses(ctx)
	if err != nil {
		return 0, err
	}
	entries := make([]dnsserver.PersistedResponse, 0, len(stored))
	for _, entry := range stored {
		entries = append(entries, dnsserver.PersistedResponse{
			RequestWire: entry.RequestWire, ResponseWire: entry.ResponseWire,
			StoredAt: entry.StoredAt, ExpiresAt: entry.ExpiresAt, StaleUntil: entry.StaleUntil,
		})
	}
	return handler.RestoreCache(entries)
}

func persistDNSCache(ctx context.Context, database *store.Store, handler *dnsserver.Handler, enabled bool) error {
	var entries []dnsserver.PersistedResponse
	if enabled {
		var err error
		entries, err = handler.ExportCache()
		if err != nil {
			return err
		}
	}
	stored := make([]store.CachedResponse, 0, len(entries))
	for _, entry := range entries {
		stored = append(stored, store.CachedResponse{
			RequestWire: entry.RequestWire, ResponseWire: entry.ResponseWire,
			StoredAt: entry.StoredAt, ExpiresAt: entry.ExpiresAt, StaleUntil: entry.StaleUntil,
		})
	}
	return database.ReplaceCachedResponses(ctx, stored)
}

func listenerConfiguration(configuration config.Config, baseDirectory string) dnsserver.ListenerConfig {
	certificate, privateKey := configuration.EncryptedDNSCertificatePaths(baseDirectory)
	return dnsserver.ListenerConfig{
		PlainDNS:    configuration.Server.DNSListen,
		DoT:         configuration.EncryptedDNS.DoTListen,
		DoH:         configuration.DedicatedDoHListeners(),
		DoQ:         configuration.EncryptedDNS.DoQListen,
		Certificate: certificate,
		PrivateKey:  privateKey,
		MinimumTLS:  configuration.EncryptedDNS.MinimumTLSVersion(),
	}
}

func runCertificateRenewal(
	ctx context.Context,
	manager *certificates.Manager,
	configuration *config.Manager,
	listeners *dnsserver.ListenerGroup,
	webServer *web.Server,
	baseDirectory string,
	logger *slog.Logger,
) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := configuration.Current().Config
			changed, err := manager.Ensure(ctx, current.EncryptedDNS, false)
			if err != nil {
				logger.Error("automatic public TLS certificate renewal", "error", err)
				continue
			}
			if changed {
				if err := listeners.Replace(ctx, listenerConfiguration(current, baseDirectory)); err != nil {
					logger.Error("activate renewed public TLS certificate", "error", err)
					continue
				}
				if current.Server.HTTPSListen != "" {
					certificate, privateKey := current.EncryptedDNSCertificatePaths(baseDirectory)
					if err := webServer.ReplaceCertificate(certificate, privateKey); err != nil {
						logger.Error("activate renewed HTTPS web certificate", "error", err)
						continue
					}
				}
				logger.Info("renewed public TLS certificate activated")
			}
		}
	}
}

func CheckConfiguration(configurationPath string) (config.Config, error) {
	absolutePath, configuration, err := loadConfiguration(configurationPath)
	if err == nil {
		_, err = compileRuntime(configuration, nil, filepath.Dir(absolutePath))
	}
	if err == nil {
		err = dnsserver.ValidateListenerConfig(listenerConfiguration(configuration, filepath.Dir(absolutePath)))
	}
	return configuration, err
}

func loadConfiguration(configurationPath string) (string, config.Config, error) {
	absolutePath, err := config.AbsolutePath(configurationPath)
	if err != nil {
		return "", config.Config{}, err
	}
	configuration, err := config.Load(absolutePath)
	if err != nil {
		return "", config.Config{}, err
	}
	if err := ensureRemoteBlockLists(context.Background(), configuration, filepath.Dir(absolutePath)); err != nil {
		return "", config.Config{}, err
	}
	return absolutePath, configuration, nil
}

func closeListenersAfterStartupFailure(listeners *dnsserver.ListenerGroup, configuration config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), configuration.Server.ShutdownTimeout.Duration)
	defer cancel()
	return listeners.Close(ctx)
}

func closeQueryRecorderAfterStartupFailure(recorder *querylog.Recorder, configuration config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), configuration.Server.ShutdownTimeout.Duration)
	defer cancel()
	return recorder.Close(ctx)
}

// closeServerLogRecorder flushes on the way out. It takes no error return
// because it runs from a defer: a failure to persist the last few lines is
// reported on stderr by the recorder itself, and there is no caller left to
// hand it to.
func closeServerLogRecorder(recorder *serverlog.Recorder, configuration config.Config) {
	ctx, cancel := context.WithTimeout(context.Background(), configuration.Server.ShutdownTimeout.Duration)
	defer cancel()
	_ = recorder.Close(ctx)
}

func serverLogWorkerChange(active, candidate config.ServerLog) error {
	if active.BufferSize == candidate.BufferSize &&
		active.BatchSize == candidate.BatchSize &&
		active.FlushInterval == candidate.FlushInterval &&
		active.Retention == candidate.Retention {
		return nil
	}
	return errors.New("server_log buffer, batch, flush, and retention settings require a controlled restart")
}

func queryLogWorkerChange(active, candidate config.QueryLog) error {
	if active.BufferSize == candidate.BufferSize &&
		active.BatchSize == candidate.BatchSize &&
		active.FlushInterval == candidate.FlushInterval &&
		active.Retention == candidate.Retention {
		return nil
	}
	return errors.New("query_log buffer, batch, flush, and retention settings require a controlled restart")
}

func tsigKeyNames(configuration config.Config) []string {
	names := make([]string, 0, len(configuration.TSIGKeys))
	for _, key := range configuration.TSIGKeys {
		names = append(names, key.Name)
	}
	return names
}

func compileRuntime(configuration config.Config, configuredZones []zone.Zone, baseDirectory string) (*dnsserver.Runtime, error) {
	sources := make([]blockcompiler.Source, 0, len(configuration.Blocking.Lists))
	for _, list := range configuration.Blocking.Lists {
		sources = append(sources, blockcompiler.Source{
			Name: list.Name, Path: list.Path, Format: blockcompiler.Format(list.Format),
		})
	}
	compiledBlocking, err := blockcompiler.Compile(baseDirectory, configuration.Blocking.Domains, sources)
	if err != nil {
		return nil, fmt.Errorf("compile blocking policy: %w", err)
	}
	blockListStats := make([]dnsserver.BlockListStats, 0, len(compiledBlocking.Sources))
	for _, source := range compiledBlocking.Sources {
		blockListStats = append(blockListStats, dnsserver.BlockListStats{
			Name: source.Name, Path: source.Path, Lines: source.Lines,
			Accepted: source.Accepted, Invalid: source.Invalid,
		})
	}
	routes := make([]dnsserver.ForwardingRoute, 0, len(configuration.Resolver.Routes))
	for _, route := range configuration.Resolver.Routes {
		routes = append(routes, dnsserver.ForwardingRoute{Domain: route.Domain, Forwarders: route.Forwarders})
	}
	hosts := make([]dnsserver.HostOverride, 0, len(configuration.Resolver.Hosts))
	for _, host := range configuration.Resolver.Hosts {
		hosts = append(hosts, dnsserver.HostOverride{
			Name: host.Name, Addresses: host.Addresses, TTL: host.TTL,
		})
	}
	zones := authoritativeZones(configuredZones)
	tsigKeys := runtimeTSIGKeys(configuration.TSIGKeys)
	runtime, err := dnsserver.Compile(dnsserver.RuntimeConfig{
		Mode:                       configuration.Resolver.Mode,
		Forwarders:                 configuration.Resolver.Forwarders,
		RootHints:                  configuration.Resolver.RootHints,
		Routes:                     routes,
		Timeout:                    configuration.Resolver.Timeout.Duration,
		Retries:                    configuration.Resolver.Retries,
		RetryTimeout:               configuration.Resolver.RetryTimeout.Duration,
		CacheSize:                  configuration.Resolver.CacheSize,
		CacheMinimumTTL:            configuration.Resolver.CacheMinimumTTL,
		CacheMaximumTTL:            configuration.Resolver.CacheMaximumTTL,
		CacheNegativeTTL:           configuration.Resolver.CacheNegativeTTL,
		CacheFailureTTL:            configuration.Resolver.CacheFailureTTL,
		ServeStale:                 configuration.Resolver.ServeStale,
		CacheStaleTTL:              configuration.Resolver.CacheStaleTTL,
		CacheStaleAnswerTTL:        configuration.Resolver.CacheStaleAnswerTTL,
		CacheStaleResetTTL:         configuration.Resolver.CacheStaleResetTTL,
		CacheStaleMaxWait:          configuration.Resolver.CacheStaleMaxWait.Duration,
		CachePrefetchMinimumTTL:    configuration.Resolver.CachePrefetchMinimumTTL,
		CachePrefetchTriggerTTL:    configuration.Resolver.CachePrefetchTriggerTTL,
		CachePrefetchSample:        configuration.Resolver.CachePrefetchSample.Duration,
		CachePrefetchHitsPerHour:   configuration.Resolver.CachePrefetchHitsPerHour,
		Blocking:                   configuration.Blocking.Enabled,
		BlockedDomains:             compiledBlocking.Domains,
		AllowedDomains:             configuration.Blocking.AllowedDomains,
		BlockLists:                 blockListStats,
		BlockingType:               configuration.Blocking.ResponseType,
		BlockingTTL:                configuration.Blocking.ResponseTTL,
		BlockingAddrs:              configuration.Blocking.CustomAddresses,
		BypassClients:              configuration.Blocking.BypassClients,
		AllowTXTReport:             configuration.Blocking.AllowTXTReport,
		Hosts:                      hosts,
		Zones:                      zones,
		TSIGKeys:                   tsigKeys,
		DNSSECValidation:           configuration.Resolver.DNSSECValidation,
		DNSSECTrustAnchorUpdates:   configuration.Resolver.DNSSECTrustAnchorUpdates,
		DNSSECTrustAnchors:         configuration.Resolver.DNSSECTrustAnchors,
		DNSSECNegativeTrustAnchors: configuration.Resolver.DNSSECNegativeTrustAnchors,
	})
	if err != nil {
		return nil, fmt.Errorf("compile DNS runtime: %w", err)
	}
	return runtime, nil
}

// logCatalogEvents reports what catalog reconciliation changed. Provisioning
// and withdrawing zones happens without an operator in the loop, so every
// outcome is written to the log, and the ones the RFC makes Sable refuse are
// warnings rather than notices.
func logCatalogEvents(logger *slog.Logger, events []zone.CatalogEvent) {
	if logger == nil {
		return
	}
	for _, event := range events {
		switch event.Kind {
		case zone.CatalogBroken:
			logger.Warn("catalog zone left unprocessed",
				"catalog", event.Catalog, "error", event.Detail)
		case zone.CatalogMemberConflict:
			logger.Warn("catalog member not adopted",
				"catalog", event.Catalog, "zone", event.Zone, "reason", event.Detail)
		case zone.CatalogMemberAdded:
			logger.Info("catalog provisioned zone",
				"catalog", event.Catalog, "zone", event.Zone, "group", event.Detail)
		case zone.CatalogMemberRemoved:
			logger.Info("catalog withdrew zone", "catalog", event.Catalog, "zone", event.Zone)
		case zone.CatalogMemberHandedOver:
			logger.Info("catalog took over zone",
				"catalog", event.Catalog, "zone", event.Zone, "detail", event.Detail)
		}
	}
}

func authoritativeZones(configuredZones []zone.Zone) []dnsserver.AuthoritativeZone {
	zones := make([]dnsserver.AuthoritativeZone, 0, len(configuredZones))
	for _, configuredZone := range configuredZones {
		zone := dnsserver.AuthoritativeZone{
			Name: configuredZone.Name, Type: configuredZone.Type, Disabled: configuredZone.Disabled,
			AwaitingTransfer: zone.AwaitingFirstTransfer(configuredZone),
			ZoneTransfer:     configuredZone.ZoneTransfer, TransferACL: configuredZone.TransferACL,
			PrimaryServers: configuredZone.PrimaryServers, PrimaryProtocol: configuredZone.PrimaryProtocol,
			TSIGKey: configuredZone.TSIGKey, DynamicUpdates: configuredZone.DynamicUpdates,
			DNSSECValidationDisabled: configuredZone.DNSSECValidationDisabled,
			Records:                  make([]dnsserver.ZoneRecord, 0, len(configuredZone.Records)),
		}
		for _, record := range configuredZone.Records {
			zone.Records = append(zone.Records, dnsserver.ZoneRecord{
				Name: record.Name, Type: record.Type, Value: record.Value, TTL: record.TTL,
				Disabled: record.Disabled, ExpiresAt: record.ExpiresAt,
			})
		}
		zones = append(zones, zone)
	}
	return zones
}

func runtimeTSIGKeys(keys []config.TSIGKey) []dnsserver.TSIGKey {
	tsigKeys := make([]dnsserver.TSIGKey, 0, len(keys))
	for _, key := range keys {
		tsigKeys = append(tsigKeys, dnsserver.TSIGKey{Name: key.Name, Algorithm: key.Algorithm, Secret: key.Secret})
	}
	return tsigKeys
}

// migrateTSIGSecrets moves secrets still written in sable.toml into the vault
// on the first boot after an upgrade, then rewrites the file without them. A
// failure is logged rather than fatal: the secrets are already loaded, so the
// node keeps serving and tries again on the next start.
func migrateTSIGSecrets(
	ctx context.Context,
	configuration *config.Manager,
	secrets *tsig.Store,
	logger *slog.Logger,
) {
	if !tsig.Pending(configuration.Current().Config) {
		return
	}
	migrated := 0
	if err := configuration.Update(ctx, func(candidate *config.Config) error {
		moved, err := secrets.Migrate(ctx, candidate)
		migrated = moved
		return err
	}); err != nil {
		logger.Warn("move TSIG secrets into the encrypted vault", "error", err)
		return
	}
	logger.Info("moved TSIG secrets into the encrypted vault", "keys", migrated)
}

// hydrateTSIGKeys returns the configuration with every TSIG secret read back
// out of the vault. A key the vault cannot answer for is left blank rather than
// dropped: every message it guards then fails verification, which refuses
// transfers and updates instead of quietly accepting unsigned ones.
func hydrateTSIGKeys(
	ctx context.Context,
	secrets *tsig.Store,
	configuration config.Config,
	logger *slog.Logger,
) config.Config {
	hydrated, missing := secrets.Hydrate(ctx, configuration.TSIGKeys)
	if len(missing) > 0 && logger != nil {
		logger.Warn("TSIG keys have no stored secret", "keys", strings.Join(missing, ", "))
	}
	configuration.TSIGKeys = hydrated
	return configuration
}

func ensureRemoteBlockLists(ctx context.Context, configuration config.Config, baseDirectory string) error {
	updater := blockcompiler.NewUpdater(baseDirectory)
	for _, list := range configuration.Blocking.Lists {
		if list.URL == "" {
			continue
		}
		path := list.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDirectory, path)
		}
		if _, err := os.Stat(path); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect cached block list %q: %w", list.Name, err)
		}
		if err := updater.Download(ctx, blockcompiler.RemoteSource{Name: list.Name, URL: list.URL, Path: list.Path}); err != nil {
			return fmt.Errorf("prepare remote block list: %w", err)
		}
	}
	return nil
}
