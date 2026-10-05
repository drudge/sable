package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/alerts"
	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/certificates"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/serverlog"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/tsig"
	"github.com/drudge/sable/internal/web"
	"github.com/drudge/sable/internal/zone"
)

var ErrRestartRequested = errors.New("controlled restart requested")

func Run(ctx context.Context, configurationPath string, logger *slog.Logger) (runError error) {
	process := newProcess(ctx, logger)
	defer process.stopRuntime()
	if err := process.loadConfiguration(ctx, configurationPath); err != nil {
		return err
	}
	if err := process.openDatabase(ctx); err != nil {
		return err
	}
	// Run is the process lifecycle boundary. If a worker outlives its shutdown
	// deadline, leave its database open until process exit rather than close a
	// dependency it may still be using. Incomplete shutdown is returned as an error.
	process.storesSafe = true
	defer func() {
		if process.storesSafe {
			process.database.Close()
		}
	}()
	// The recorder attaches here rather than alongside the other services so
	// the startup that follows is persisted too, and it is closed by defer so
	// every path out of Run flushes it, including the startup failures that
	// are the most valuable thing to still have after a restart. Deferred
	// after database.Close, so it runs before it.
	if err := process.startServerLog(); err != nil {
		return err
	}
	defer func() {
		if err := closeServerLogRecorder(process.serverLogRecorder, process.initial); err != nil {
			process.storesSafe = false
			runError = errors.Join(runError, fmt.Errorf("close server log recorder: %w", err))
		}
	}()
	if err := process.openSecurity(ctx); err != nil {
		return err
	}
	if err := process.startDNS(ctx); err != nil {
		return err
	}
	defer func() {
		if process.startupComplete {
			return
		}
		workerError, cleanupError := process.abortStartup()
		runError = errors.Join(runError, workerError, cleanupError)
	}()
	if err := process.startResolverServices(ctx); err != nil {
		return err
	}
	if err := process.startConfiguration(ctx); err != nil {
		return err
	}
	zoneRefreshContext, stopZoneRefresh := context.WithCancel(process.runtimeContext)
	defer stopZoneRefresh()
	process.zoneRefreshContext = zoneRefreshContext
	process.startZoneWorkers()
	if err := process.openCluster(); err != nil {
		return err
	}
	process.startIntegrations()
	if err := process.startWeb(ctx); err != nil {
		return err
	}
	process.startBackgroundServices()
	process.startupComplete = true
	process.logStarted()
	restartRequested := process.wait(ctx)
	return process.shutdown(restartRequested)
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

func waitRuntimeWorkers(ctx context.Context, workers *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("runtime workers did not stop before shutdown deadline: %w", ctx.Err())
	}
}

// recorderContextForShutdown gives recorder.Close a fresh bounded context when
// the shared shutdown deadline has already expired. Recorder.Close checks the
// context before signaling its worker, while the other components signal their
// own cancellation before waiting and can safely use the shared deadline.
func recorderContextForShutdown(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx.Err() == nil {
		return ctx, func() {}
	}
	return context.WithTimeout(context.Background(), timeout)
}

// closeServerLogRecorder flushes startup and shutdown logs before the database
// closes. A timeout leaves the database available until the process exits.
func closeServerLogRecorder(recorder *serverlog.Recorder, configuration config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), configuration.Server.ShutdownTimeout.Duration)
	defer cancel()
	return recorder.Close(ctx)
}

func serverLogWorkerChange(active, candidate config.ServerLog) error {
	if active.BufferSize == candidate.BufferSize &&
		active.BatchSize == candidate.BatchSize &&
		active.FlushInterval == candidate.FlushInterval {
		return nil
	}
	return errors.New("server_log buffer, batch, and flush settings require a controlled restart")
}

func queryLogWorkerChange(active, candidate config.QueryLog) error {
	if active.BufferSize == candidate.BufferSize &&
		active.BatchSize == candidate.BatchSize &&
		active.FlushInterval == candidate.FlushInterval {
		return nil
	}
	return errors.New("query_log buffer, batch, and flush settings require a controlled restart")
}

func serverLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
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
		Mode:          configuration.Resolver.Mode,
		MaxConcurrent: configuration.Resolver.MaxConcurrent, MaxConcurrentPerClient: configuration.Resolver.MaxConcurrentPerClient,
		Forwarders:                 configuration.Resolver.Forwarders,
		Recursion:                  configuration.Resolver.Recursion,
		RecursionClients:           configuration.Resolver.RecursionClients,
		RootHints:                  configuration.Resolver.RootHints,
		DisableQNAMEMinimization:   !configuration.Resolver.QNAMEMinimization,
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
		BlockedDomainOwners:        compiledBlocking.Owners,
		BlockedDomainOwnerSets:     compiledBlocking.OwnerSets,
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

// warnCNAMEConflicts surfaces names where a CNAME coexists with other records.
// Such data predates the write-time exclusivity check (or arrived over a zone
// transfer), so it is loaded and served as-is rather than refused, but until a
// record is removed resolvers see different answers depending on query type.
func warnCNAMEConflicts(logger *slog.Logger, configuredZones []zone.Zone) {
	now := time.Now()
	for _, current := range configuredZones {
		for _, name := range zone.CNAMEConflicts(current, now) {
			logger.Warn("CNAME record shares its name with other records; answers differ by query type until one is removed",
				"zone", current.Name, "name", name)
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

// migrateAlertSecrets moves alert destination URLs, keys, and header values
// still written in sable.toml into the vault on the first boot after an
// upgrade, then rewrites the file without them. Like the TSIG move, a failure
// is logged rather than fatal: the secrets are already loaded, so alerts keep
// working and the move is tried again on the next start.
func migrateAlertSecrets(
	ctx context.Context,
	configuration *config.Manager,
	secrets *alerts.SecretStore,
	logger *slog.Logger,
) {
	if !alerts.Pending(configuration.Current().Config) {
		return
	}
	migrated := 0
	if err := configuration.Update(ctx, func(candidate *config.Config) error {
		moved, err := secrets.Migrate(ctx, candidate)
		migrated = moved
		return err
	}); err != nil {
		logger.Warn("move alert secrets into the encrypted vault", "error", err)
		return
	}
	logger.Info("moved alert secrets into the encrypted vault", "destinations", migrated)
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
