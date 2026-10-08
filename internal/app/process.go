package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsprovider"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/dynamicdns"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/localnet"
	"github.com/drudge/sable/internal/neighbors"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/secrets"
	"github.com/drudge/sable/internal/serverlog"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/trustanchor"
	"github.com/drudge/sable/internal/tsig"
	"github.com/drudge/sable/internal/update"
	"github.com/drudge/sable/internal/version"
	"github.com/drudge/sable/internal/web"
	webassets "github.com/drudge/sable/internal/web/assets"
	"github.com/drudge/sable/internal/zone"
)

// process holds everything Run starts, so each startup and shutdown step is a
// method over the services the steps before it built. A field stays nil until
// its step runs, and the cleanup after a failed startup closes only what exists.
type process struct {
	// runtimeContext ends when Run begins shutting down; every runtime worker
	// runs under it.
	runtimeContext     context.Context
	stopRuntime        context.CancelFunc
	runtimeWorkers     sync.WaitGroup
	zoneRefreshContext context.Context
	startedAt          time.Time
	startupComplete    bool
	// storesSafe is cleared when a worker may still be using the database, so
	// Run leaves it open rather than close it underneath that worker.
	storesSafe bool

	runtimeLogs     *serverlog.Buffer
	minimumLogLevel slog.LevelVar
	baseLogger      *slog.Logger
	logger          *slog.Logger

	absolutePath           string
	configurationDirectory string
	initial                config.Config
	configurationManager   *config.Manager

	database          *store.Store
	serverLogRecorder *serverlog.Recorder
	queryRecorder     *querylog.Recorder
	secretVault       *secrets.Vault
	authentication    *auth.Service
	setupRequired     bool

	tsigSecrets            *tsig.Store
	alertSecrets           *alerts.SecretStore
	unifiCredentials       *unifiCredentialStore
	oidcSecrets            *oidcSecretStore
	dnsProviderCredentials *dnsprovider.Store

	dnssec             *dnssecSigner
	zoneManager        *zone.Manager
	handler            *dnsserver.Handler
	deviceRuleSets     *deviceRuleSets
	listeners          *dnsserver.ListenerGroup
	readInterfaces     func() ([]localnet.Interface, error)
	attachedNetworks   *localnet.Watcher
	trustAnchorManager *trustanchor.Manager
	certificateManager *certificates.Manager
	dynamicUpdater     *dynamicZoneUpdater
	zoneRefresher      *zoneRefresher

	clusterService   *cluster.Service
	stateReplicator  *clusterStateReplicator
	scheduledBackups *scheduledBackupService
	unifiSync        *unifiSyncer
	dynamicDNS       *dynamicdns.Manager
	updateManager    *update.Manager
	webServer        *web.Server
	alertDispatcher  *alerts.Dispatcher
	restartRequests  chan struct{}
}

func newProcess(ctx context.Context, logger *slog.Logger) *process {
	process := &process{startedAt: time.Now(), runtimeLogs: serverlog.New(serverlog.DefaultCapacity)}
	process.runtimeContext, process.stopRuntime = context.WithCancel(ctx)
	process.minimumLogLevel.Set(slog.LevelInfo)
	// baseLogger stays unwrapped so the server log recorder can report its own
	// failures without feeding them back into the buffer it drains.
	process.baseLogger = slog.New(serverlog.NewLevelHandler(logger.Handler(), &process.minimumLogLevel))
	process.logger = slog.New(serverlog.NewHandler(process.baseLogger.Handler(), process.runtimeLogs))
	return process
}

func (process *process) runWorker(run func(context.Context)) {
	process.runtimeWorkers.Add(1)
	go func() {
		defer process.runtimeWorkers.Done()
		run(process.runtimeContext)
	}()
}

// leading reports whether this node runs the cluster-wide jobs: it is not
// clustered, or it is the primary.
func (process *process) leading() bool {
	state := process.clusterService.Snapshot()
	return !state.Initialized || state.LocalRole != cluster.RoleReplica
}

func (process *process) current() config.Config {
	return process.configurationManager.Current().Config
}

// loadConfiguration finishes any restore a previous run left behind, then
// reads the configuration the rest of startup uses.
func (process *process) loadConfiguration(ctx context.Context, configurationPath string) error {
	absoluteConfigurationPath, err := config.AbsolutePath(configurationPath)
	if err != nil {
		return err
	}
	if recovered, recoverErr := recoverInterruptedRestore(ctx, absoluteConfigurationPath); recoverErr != nil {
		return fmt.Errorf("recover interrupted restore: %w", recoverErr)
	} else if recovered {
		process.logger.Warn("recovered deployment after an interrupted restore")
	}
	if applied, applyErr := applyStagedRestore(ctx, absoluteConfigurationPath); applyErr != nil {
		return fmt.Errorf("apply staged restore: %w", applyErr)
	} else if applied {
		process.logger.Warn("applied staged deployment restore")
	}
	process.absolutePath, process.initial, err = loadConfiguration(configurationPath)
	if err != nil {
		return err
	}
	process.minimumLogLevel.Set(serverLogLevel(process.initial.ServerLog.Level))
	process.configurationDirectory = filepath.Dir(process.absolutePath)
	return nil
}

func (process *process) openDatabase(ctx context.Context) error {
	database, err := store.Open(ctx, process.initial.Database.Driver, process.initial.Database.DSN)
	if err != nil {
		return err
	}
	process.database = database
	// Before the query log writer and the device workers start, so none of
	// them keeps a sighting while Insights is off.
	return switchInsights(ctx, database, true, process.initial.Insights.Enabled, time.Now())
}

func (process *process) startServerLog() error {
	serverLogRecorder, err := serverlog.NewRecorder(process.database, serverlog.Options{
		Enabled:       process.initial.ServerLog.Enabled,
		BufferSize:    process.initial.ServerLog.BufferSize,
		BatchSize:     process.initial.ServerLog.BatchSize,
		FlushInterval: process.initial.ServerLog.FlushInterval.Duration,
		Retention:     process.initial.ServerLog.Retention.Duration,
	}, process.baseLogger)
	if err != nil {
		return fmt.Errorf("start server log recorder: %w", err)
	}
	process.serverLogRecorder = serverLogRecorder
	process.runtimeLogs.Attach(serverLogRecorder)
	return nil
}

// openSecurity opens the secret vault and, when security is on, the
// authentication service.
func (process *process) openSecurity(ctx context.Context) error {
	secretVault, err := secrets.Open(process.initial.SecuritySecretKeyPath(process.configurationDirectory), process.database)
	if err != nil {
		return fmt.Errorf("initialize secret vault: %w", err)
	}
	process.secretVault = secretVault
	if !process.initial.Security.Enabled {
		return nil
	}
	if err := process.database.PruneExpiredAuthentication(ctx, time.Now()); err != nil {
		return err
	}
	process.authentication, err = auth.NewService(process.database, auth.Options{
		SessionTTL: process.initial.Security.SessionTTL.Duration,
		TokenTTL:   process.initial.Security.APITokenTTL.Duration,
	})
	if err != nil {
		return fmt.Errorf("initialize authentication: %w", err)
	}
	process.setupRequired, err = process.authentication.SetupRequired(ctx)
	if err != nil {
		return fmt.Errorf("check administrator setup: %w", err)
	}
	return nil
}

// startDNS loads the zones and builds the DNS handler from them.
func (process *process) startDNS(ctx context.Context) error {
	process.tsigSecrets = tsig.NewStore(process.secretVault)
	process.dnssec = newDNSSECSigner(process.secretVault)
	zoneManager, err := zone.NewManager(ctx, process.database, process.prepareZones, process.validateZones, process.activateZones)
	if err != nil {
		return err
	}
	process.zoneManager = zoneManager
	warnCNAMEConflicts(process.logger, zoneManager.Current().Zones)
	runtime, err := compileRuntime(
		hydrateTSIGKeys(ctx, process.tsigSecrets, process.initial, process.logger),
		zoneManager.Current().Zones,
		process.configurationDirectory,
	)
	if err != nil {
		return err
	}
	process.handler = dnsserver.NewHandler(runtime)
	process.handler.SetLogger(process.logger)
	process.handler.StartMaintenance()
	// Private recursion admits the IPv6 networks this node is attached to.
	// They are read once before any listener opens, then kept current.
	process.readInterfaces = attachedInterfaceReader()
	process.attachedNetworks = localnet.NewWatcher(process.handler.SetAttachedNetworks)
	_ = process.attachedNetworks.Refresh(process.readInterfaces)
	// Devices named by hardware address join their rule sets as Sable ties
	// addresses to them.
	process.deviceRuleSets = newDeviceRuleSets(process.database.ClientIdentities, process.database.ClientTracking,
		process.handler.SetDeviceAddresses, process.logger)
	process.deviceRuleSets.SetClients(process.initial.Clients)
	process.runWorker(process.deviceRuleSets.Run)
	return nil
}

// prepareZones applies catalog membership first so a zone a catalog just
// provisioned exists before aliases and signing look at the set. Alias zones
// then mirror their source before signing runs, so a mirrored record set is
// covered by the alias zone's own signatures rather than the stale ones the
// source was signed with.
func (process *process) prepareZones(ctx context.Context, zones *[]zone.Zone) error {
	logCatalogEvents(process.logger, zone.ReconcileCatalogs(zones))
	if err := zone.MaterializeAliases(zones, time.Now()); err != nil {
		return err
	}
	if err := zone.MaterializeCatalogs(zones, time.Now()); err != nil {
		return err
	}
	return process.dnssec.Prepare(ctx, zones)
}

func (process *process) validateZones(zones []zone.Zone) error {
	configuration := process.initial
	if process.configurationManager != nil {
		configuration = process.current()
	}
	return zone.ValidateAll(zones, tsigKeyNames(configuration))
}

func (process *process) activateZones(activateContext context.Context, _, zones []zone.Zone) error {
	if process.handler == nil {
		return nil
	}
	keys := hydrateTSIGKeys(activateContext, process.tsigSecrets, process.current(), process.logger).TSIGKeys
	return process.handler.ActivateZones(authoritativeZones(zones), runtimeTSIGKeys(keys))
}

// abortStartup stops whatever a failed startup had already started, and
// returns the worker and cleanup errors to join with the startup error.
func (process *process) abortStartup() (error, error) {
	cleanupContext, cancel := context.WithTimeout(context.Background(), process.initial.Server.ShutdownTimeout.Duration)
	defer cancel()
	process.stopRuntime()
	workerError := waitRuntimeWorkers(cleanupContext, &process.runtimeWorkers)
	if workerError != nil {
		process.storesSafe = false
	}
	var cleanupError error
	if process.webServer != nil {
		cleanupError = errors.Join(cleanupError, process.webServer.Close(cleanupContext))
	}
	if process.clusterService != nil {
		cleanupError = errors.Join(cleanupError, process.clusterService.Close(cleanupContext))
	}
	if process.listeners != nil {
		cleanupError = errors.Join(cleanupError, process.listeners.Close(cleanupContext))
	}
	if process.handler != nil {
		cleanupError = errors.Join(cleanupError, process.handler.Shutdown(cleanupContext))
	}
	if process.queryRecorder != nil {
		recorderContext, recorderCancel := recorderContextForShutdown(cleanupContext, process.initial.Server.ShutdownTimeout.Duration)
		cleanupError = errors.Join(cleanupError, process.queryRecorder.Close(recorderContext))
		recorderCancel()
	}
	if workerError != nil || cleanupError != nil {
		process.storesSafe = false
	}
	return workerError, cleanupError
}

// startResolverServices restores the DNS cache and starts the trust-anchor
// manager, the query log, and the listener group the handler serves through.
func (process *process) startResolverServices(ctx context.Context) error {
	handler := process.handler
	if process.initial.Resolver.SaveCache {
		restored, restoreErr := restoreDNSCache(ctx, process.database, handler)
		if restoreErr != nil {
			process.logger.Warn("restore persisted DNS cache", "error", restoreErr, "restored", restored)
		} else {
			process.logger.Info("restored persisted DNS cache", "entries", restored)
		}
	}
	trustAnchorManager, err := trustanchor.New(ctx, process.database, handler.DNSSECTrustAnchorQuery, trustanchor.Options{
		Enabled:  handler.DNSSECTrustAnchorUpdatesEnabled,
		OnChange: handler.ApplyManagedTrustAnchors,
	})
	if err != nil {
		return fmt.Errorf("initialize RFC 5011 trust-anchor manager: %w", err)
	}
	process.trustAnchorManager = trustAnchorManager
	handler.SetTrustAnchorManager(trustAnchorManager)
	process.queryRecorder, err = querylog.NewRecorder(process.database, querylog.Options{
		Enabled:       process.initial.QueryLog.Enabled,
		BufferSize:    process.initial.QueryLog.BufferSize,
		BatchSize:     process.initial.QueryLog.BatchSize,
		FlushInterval: process.initial.QueryLog.FlushInterval.Duration,
		Retention:     process.initial.QueryLog.Retention.Duration,
	}, process.logger)
	if err != nil {
		return fmt.Errorf("start query recorder: %w", err)
	}
	handler.SetQueryObserver(process.queryRecorder)
	process.listeners = dnsserver.NewListenerGroup(handler, process.logger)
	process.certificateManager = certificates.New(process.secretVault, process.logger, process.configurationDirectory)
	return nil
}

// startConfiguration starts the configuration manager and scheduled backups,
// opens the listeners, and routes dynamic updates to the zone manager.
func (process *process) startConfiguration(ctx context.Context) error {
	process.configurationManager = config.NewManager(process.absolutePath, process.initial, process.applyConfiguration)
	var err error
	process.scheduledBackups, err = newScheduledBackupService(process.absolutePath, process.configurationManager, process.secretVault, process.logger, process.initial.Backup)
	if err != nil {
		return fmt.Errorf("initialize scheduled backups: %w", err)
	}
	if _, err := process.certificateManager.Ensure(ctx, process.initial.EncryptedDNS, false); err != nil {
		return fmt.Errorf("prepare public TLS certificate: %w", err)
	}
	if err := process.listeners.Replace(ctx, listenerConfiguration(process.initial, process.configurationDirectory)); err != nil {
		return err
	}
	migrateTSIGSecrets(ctx, process.configurationManager, process.tsigSecrets, process.logger)
	process.alertSecrets = alerts.NewSecretStore(process.secretVault)
	migrateAlertSecrets(ctx, process.configurationManager, process.alertSecrets, process.logger)
	process.dynamicUpdater = newDynamicZoneUpdater(ctx, process.zoneManager, process.handler, process.database, process.logger)
	process.handler.SetZoneUpdater(process.dynamicUpdater.Update)
	process.handler.SetZoneUpdateAuditor(process.dynamicUpdater.Audit)
	return nil
}

// applyConfiguration is the configuration manager's apply step: it refuses
// changes that need a restart, then moves every running service to candidate.
func (process *process) applyConfiguration(reloadContext context.Context, active, candidate config.Config) error {
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
	if process.scheduledBackups != nil {
		if err := process.scheduledBackups.Prepare(candidate.Backup); err != nil {
			return err
		}
	}
	clusterRestartRequired := active.Cluster != candidate.Cluster
	if err := process.activateConfiguration(reloadContext, candidate); err != nil {
		return err
	}
	if err := process.applyRecorderSettings(reloadContext, active, candidate); err != nil {
		return err
	}
	// After the recorder settings, so turning Insights off empties the table.
	process.deviceRuleSets.SetClients(candidate.Clients)
	if clusterRestartRequired {
		process.logger.Info("cluster bootstrap settings staged", "restart_required", true)
	}
	if webRestartRequired {
		process.logger.Info("HTTPS web listener settings staged", "restart_required", true)
	}
	if process.scheduledBackups != nil {
		process.scheduledBackups.Apply(candidate.Backup)
	}
	return nil
}

// activateConfiguration compiles the candidate runtime against the current
// zones, then moves the certificates, listeners, and handler over to it.
func (process *process) activateConfiguration(reloadContext context.Context, candidate config.Config) error {
	zones := process.zoneManager.Current().Zones
	if err := zone.ValidateAll(zones, tsigKeyNames(candidate)); err != nil {
		return fmt.Errorf("validate zones with reloaded configuration: %w", err)
	}
	candidateRuntime, err := compileRuntime(
		hydrateTSIGKeys(reloadContext, process.tsigSecrets, candidate, process.logger),
		zones,
		process.configurationDirectory,
	)
	if err != nil {
		return err
	}
	if _, err := process.certificateManager.Ensure(reloadContext, candidate.EncryptedDNS, false); err != nil {
		return fmt.Errorf("prepare public TLS certificate: %w", err)
	}
	if err := process.listeners.Replace(reloadContext, listenerConfiguration(candidate, process.configurationDirectory)); err != nil {
		return err
	}
	if process.webServer != nil && candidate.Server.HTTPSListen != "" {
		certificate, privateKey := candidate.EncryptedDNSCertificatePaths(process.configurationDirectory)
		if err := process.webServer.ReplaceCertificate(certificate, privateKey); err != nil {
			return err
		}
	}
	return process.handler.Activate(candidateRuntime)
}

// applyRecorderSettings moves the query log, Insights, server log, and
// statistics settings over to candidate.
func (process *process) applyRecorderSettings(reloadContext context.Context, active, candidate config.Config) error {
	process.queryRecorder.SetEnabled(candidate.QueryLog.Enabled)
	if err := switchInsights(reloadContext, process.database, active.Insights.Enabled, candidate.Insights.Enabled, time.Now()); err != nil {
		return err
	}
	if err := process.queryRecorder.SetRetention(candidate.QueryLog.Retention.Duration); err != nil {
		return err
	}
	process.serverLogRecorder.SetEnabled(candidate.ServerLog.Enabled)
	if err := process.serverLogRecorder.SetRetention(candidate.ServerLog.Retention.Duration); err != nil {
		return err
	}
	process.minimumLogLevel.Set(serverLogLevel(candidate.ServerLog.Level))
	if process.webServer != nil {
		process.webServer.SetStatsRetention(candidate.Statistics.Retention.Duration)
	}
	return nil
}

// startZoneWorkers starts zone refresh, DNSSEC re-signing, and trust-anchor
// tracking under the zone refresh context.
func (process *process) startZoneWorkers() {
	process.zoneRefresher = newZoneRefresher(process.zoneManager, process.handler, process.logger)
	process.runWorker(func(context.Context) { process.zoneRefresher.Run(process.zoneRefreshContext) })
	process.runWorker(func(context.Context) {
		runDNSSECRefresher(process.zoneRefreshContext, process.zoneManager, process.dnssec, process.handler, process.logger)
	})
	process.runWorker(func(context.Context) { process.trustAnchorManager.Run(process.zoneRefreshContext, process.logger) })
}

// openCluster opens this node's cluster identity, with the replicator that
// carries state between members, and refuses dynamic updates on a replica.
func (process *process) openCluster() error {
	process.unifiCredentials = newUniFiCredentialStore(process.secretVault)
	process.oidcSecrets = newOIDCSecretStore(process.secretVault)
	process.dnsProviderCredentials = dnsprovider.NewStore(process.secretVault)
	process.stateReplicator = newClusterStateReplicator(process.configurationManager, process.zoneManager, process.database, process.tsigSecrets, process.unifiCredentials, process.oidcSecrets)
	process.stateReplicator.setDNSProviderCredentials(process.dnsProviderCredentials)
	process.stateReplicator.setInsightData(process.database)
	initial := process.initial
	clusterCertificateFile, _ := initial.EncryptedDNSCertificatePaths(process.configurationDirectory)
	clusterService, err := cluster.Open(cluster.Options{
		HTTPSCertificateFile: clusterCertificateFile,
		DataDirectory:        initial.ClusterDataPath(process.configurationDirectory),
		NodeName:             clusterNodeName(initial.Cluster.NodeName),
		AdvertiseURL:         clusterAdvertiseURL(initial),
		HTTPSListen:          initial.Server.HTTPSListen,
		DNSListeners:         initial.Server.DNSListen,
		TrustAnchorFile:      initial.ClusterTrustAnchorPath(process.configurationDirectory),
		Logger:               process.logger,
		Replicator:           process.stateReplicator,
		Version:              version.Current().Release,
		StartedAt:            process.startedAt,
	})
	if err != nil {
		return fmt.Errorf("initialize cluster identity: %w", err)
	}
	process.clusterService = clusterService
	process.handler.SetZoneUpdater(func(updateContext context.Context, request dnsserver.ZoneUpdateRequest) dnsserver.ZoneUpdateResult {
		state := clusterService.Snapshot()
		if state.Initialized && state.LocalRole == cluster.RoleReplica {
			return dnsserver.ZoneUpdateResult{Rcode: dns.RcodeRefused}
		}
		return process.dynamicUpdater.Update(updateContext, request)
	})
	return nil
}

func (process *process) insightsEnabled() bool { return process.current().Insights.Enabled }

// startIntegrations starts UniFi sync, the Insights workers, dynamic DNS, and
// the scheduled update check.
func (process *process) startIntegrations() {
	database := process.database
	process.unifiSync = newUniFiSyncer(process.configurationManager, process.zoneManager, process.unifiCredentials, process.leading, process.logger)
	process.unifiSync.identities = process.deviceRuleSets.Record(database.RecordClientIdentities)
	process.unifiSync.reading = database.RecordUniFiReading
	process.runWorker(func(context.Context) { process.unifiSync.Run(process.zoneRefreshContext) })
	process.runWorker(func(context.Context) {
		runNeighborSampler(process.runtimeContext, process.insightsEnabled, neighbors.Read,
			process.deviceRuleSets.Record(database.RecordClientIdentities), process.logger)
	})
	process.runWorker(func(context.Context) {
		process.attachedNetworks.Run(process.runtimeContext, process.readInterfaces, process.logger)
	})
	process.runWorker(func(context.Context) {
		maintainQueryLogSearch(process.runtimeContext, database.BuildQueryLogSearch, queryLogSearchInterval, process.logger)
	})
	process.runWorker(func(context.Context) {
		// One after the other: each reads through the whole query history.
		backfillClientSightings(process.runtimeContext, database.BackfillClientSightings, process.logger)
		backfillBlockedClientRollups(process.runtimeContext, database.BackfillBlockedClientRollups, process.logger)
		backfillAppRollups(process.runtimeContext, database.BackfillAppRollups, process.logger)
		compactQueryLogRollups(process.runtimeContext, database.CompactQueryLogRollups, rollupCompactionInterval, process.logger)
	})
	process.dynamicDNS = dynamicdns.New(process.configurationManager, process.dnsProviderCredentials, database, process.leading, process.logger)
	process.runWorker(func(context.Context) { process.dynamicDNS.Run(process.zoneRefreshContext) })
	process.updateManager = newUpdateManager(update.Options{
		ReleaseStore:   database,
		Resolver:       process.handler,
		Logger:         process.logger,
		BinaryPath:     os.Getenv(update.BinaryPathEnvironment),
		RestartManaged: process.initial.Updates.RestartManaged,
		PreRelease:     process.initial.Updates.PreRelease,
	})
	process.runWorker(newScheduledUpdateCheck(process.updateManager, process.configurationManager, process.leading, process.logger).Run)
}

// startWeb builds the web console with its controllers and alerts, then
// starts serving HTTP and, when configured, HTTPS.
func (process *process) startWeb(ctx context.Context) error {
	if err := process.newWebServer(); err != nil {
		return err
	}
	process.startAlerts()
	webServer := process.webServer
	if process.authentication != nil {
		// Single sign-on rides on the authentication service, so a deployment
		// with security switched off has no provider and no sign-in button.
		singleSignOn := newSSOService(process.configurationManager, process.oidcSecrets, process.authentication, process.logger)
		webServer.SetSSO(singleSignOn)
		webServer.SetSSOAdministration(singleSignOn)
	}
	webServer.SetRuntimeLogs(process.runtimeLogs)
	if err := webServer.SetStatsStore(ctx, process.database); err != nil {
		process.logger.Warn("restore query statistics", "error", err)
	}
	webServer.SetUpdateController(process.updateManager)
	webServer.SetBackupController(process.scheduledBackups)
	process.restartRequests = make(chan struct{}, 1)
	requestRestart := func() {
		select {
		case process.restartRequests <- struct{}{}:
		default:
		}
	}
	webServer.SetRestartController(requestRestart)
	if err := process.clusterService.SetUpdateController(process.updateManager, requestRestart); err != nil {
		process.logger.Error("restore cluster update progress", "error", err)
	}
	initial := process.initial
	if err := webServer.Start(initial.Server.HTTPListen); err != nil {
		return err
	}
	if initial.Server.HTTPSListen != "" {
		certificate, privateKey := initial.EncryptedDNSCertificatePaths(process.configurationDirectory)
		if err := webServer.StartTLS(initial.Server.HTTPSListen, certificate, privateKey, initial.EncryptedDNS.MinimumTLSVersion()); err != nil {
			return err
		}
	}
	return nil
}

func (process *process) newWebServer() error {
	var webAuthentication web.Authenticator
	if process.authentication != nil {
		webAuthentication = process.authentication
	}
	webServer, err := web.New(
		process.logger,
		process.handler,
		process.configurationManager,
		process.zoneManager,
		process.database.Driver(),
		process.queryRecorder,
		process.database,
		process.configurationManager.Reload,
		webAuthentication,
		process.initial.Security.Enabled,
		process.setupRequired,
		process.initial.Security.SecureCookies,
	)
	if err != nil {
		return err
	}
	process.webServer = webServer
	webServer.SetDNSSECController(process.dnssec)
	webServer.SetClusterController(process.clusterService)
	webServer.SetCertificateController(process.certificateManager)
	webServer.SetDynamicDNSController(process.dynamicDNS)
	webServer.SetUniFiController(process.unifiSync)
	webServer.SetTSIGController(tsig.NewManager(process.configurationManager, process.tsigSecrets))
	return nil
}

// startAlerts builds the alert dispatcher from every alert source and shares
// this node's alerts, lookups, client identities, and networks with the cluster.
func (process *process) startAlerts() {
	webServer, clusterService, database := process.webServer, process.clusterService, process.database
	configurationManager := process.configurationManager
	pushKeys := newPushKeyStore(process.secretVault)
	webServer.SetPushKeys(pushKeys)
	process.stateReplicator.setAlerts(process.alertSecrets, pushKeys, database)
	alertDispatcher := &alerts.Dispatcher{
		Config:   process.current,
		Secrets:  process.alertSecrets,
		Sent:     database,
		Browsers: &alerts.Browsers{Keys: pushKeys, Store: database, Logger: process.logger},
		Icon:     webassets.URL("sable-icon-180.png"),
		Logger:   process.logger,
	}
	process.alertDispatcher = alertDispatcher
	alertDispatcher.Add(webServer.InsightAlerts())
	alertDispatcher.Add(newUniFiAlertSource(process.unifiSync, configurationManager), newDynamicDNSAlertSource(process.dynamicDNS, configurationManager))
	alertDispatcher.Add(newUpdateAlertSource(process.updateManager))
	alertDispatcher.Add(nodeHealth{
		node: clusterAlertNode(clusterService, configurationManager), configuration: configurationManager,
		certificates: process.certificateManager, zones: process.zoneRefresher, backups: process.scheduledBackups,
		trustAnchors: process.trustAnchorManager, trustAnchorUpdates: process.handler.DNSSECTrustAnchorUpdatesEnabled,
		auditLog: database, signIns: process.authentication != nil,
	}.alertSources()...)
	alertDispatcher.Add(clusterAlertSources(clusterService)...)
	watches := newWatchSource(database, process.current,
		clusterAlertNode(clusterService, configurationManager), process.leading, clusterService.ReportedAlerts)
	alertDispatcher.Add(watches.alertSources()...)
	clusterService.SetLocalAlerts(alertDispatcher.Local)
	clusterService.SetLocalLookups(database.ClientLastLookups)
	// The lead hands replicas the addresses it has tied to hardware, since a
	// replica may not see the network's hardware addresses itself.
	clusterService.SetClientIdentities(cluster.ClientIdentities{
		Read: database.ClientIdentities, Record: process.deviceRuleSets.Record(database.RecordClientIdentities), Lookback: devices.Lookback,
		Enabled: process.insightsEnabled,
	})
	// A replica in a container can't see the LAN it serves, so the lead hands
	// it the networks private recursion should admit.
	clusterService.SetAttachedNetworks(cluster.AttachedNetworks{Own: process.attachedNetworks.Own, Lead: process.attachedNetworks.SetLead})
	webServer.SetAttachedNetworks(process.attachedNetworks)
	webServer.SetAlerts(alertDispatcher, process.alertSecrets)
	webServer.SetWatchStatus(watches.LastAlert)
}

// startBackgroundServices starts cluster monitoring, scheduled backups, alert
// delivery, and certificate renewal once everything they use is serving.
func (process *process) startBackgroundServices() {
	process.clusterService.StartMonitoring(process.runtimeContext)
	process.runWorker(func(context.Context) { process.scheduledBackups.Run(process.runtimeContext) })
	process.runWorker(func(context.Context) {
		process.alertDispatcher.Run(process.runtimeContext, process.leading)
	})
	process.runWorker(func(context.Context) {
		runCertificateRenewal(process.runtimeContext, process.certificateManager, process.configurationManager, process.listeners, process.webServer, process.configurationDirectory, process.logger)
	})
}

func (process *process) logStarted() {
	initial := process.initial
	releaseInfo := version.Current()
	clusterState := process.clusterService.Snapshot()
	process.logger.Info(
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
		"setup_required", process.setupRequired,
		"node_id", clusterState.NodeID,
		"cluster_initialized", clusterState.Initialized,
		"cluster_id", clusterState.ClusterID,
		"cluster_network_ready", clusterState.NetworkReady,
		"cluster_role", clusterState.LocalRole,
		"cluster_generation", clusterState.Generation,
	)
}

// wait watches the configuration file when asked to, and blocks until ctx
// ends or a restart is requested. It reports whether a restart was.
func (process *process) wait(ctx context.Context) bool {
	var watchErrors chan error
	if process.initial.Reload.Watch {
		watchErrors = make(chan error, 1)
		process.runWorker(func(runtimeContext context.Context) {
			watchErrors <- config.Watch(
				runtimeContext,
				process.absolutePath,
				process.initial.Reload.Debounce.Duration,
				process.logger,
				process.configurationManager.Reload,
				func() []string {
					return process.current().ReloadDependencyPaths(process.configurationDirectory)
				},
			)
		})
	}
	for {
		select {
		case <-ctx.Done():
			return false
		case <-process.restartRequests:
			return true
		case watchError := <-watchErrors:
			if watchError != nil {
				process.logger.Error("configuration watcher stopped", "error", watchError)
			}
			watchErrors = nil
		}
	}
}

// shutdown stops serving, drains the runtime, persists the DNS cache when the
// runtime drained cleanly, and closes the query log.
func (process *process) shutdown(restartRequested bool) error {
	logger := process.logger
	shutdownTimeout := process.current().Server.ShutdownTimeout.Duration
	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if restartRequested {
		logger.Info("Sable restarting")
	} else {
		logger.Info("Sable stopping")
	}
	process.stopRuntime()
	webError := process.webServer.Close(shutdownContext)
	listenerError := process.listeners.Close(shutdownContext)
	workerError := waitRuntimeWorkers(shutdownContext, &process.runtimeWorkers)
	clusterError := process.clusterService.Close(shutdownContext)
	// Stop background cache refreshes before snapshotting, so what gets persisted
	// is a settled cache rather than one being written to as it is read.
	handlerError := process.handler.Shutdown(shutdownContext)
	cacheError := error(nil)
	runtimeDrained := workerError == nil && webError == nil && listenerError == nil && clusterError == nil && handlerError == nil
	if runtimeDrained {
		cacheError = persistDNSCache(
			shutdownContext,
			process.database,
			process.handler,
			process.current().Resolver.SaveCache,
		)
	} else {
		cacheError = errors.Join(
			errors.New("skip DNS cache persistence because runtime shutdown was incomplete"),
			workerError, webError, listenerError, handlerError,
		)
	}
	queryContext, queryCancel := recorderContextForShutdown(shutdownContext, shutdownTimeout)
	queryLogError := process.queryRecorder.Close(queryContext)
	queryCancel()
	if !runtimeDrained || queryLogError != nil {
		process.storesSafe = false
	}
	shutdownError := errors.Join(webError, listenerError, workerError, clusterError, handlerError, cacheError, queryLogError)
	if restartRequested {
		if shutdownError != nil {
			logger.Error("controlled restart shutdown failed", "error", shutdownError)
		}
		return errors.Join(ErrRestartRequested, shutdownError)
	}
	return shutdownError
}
