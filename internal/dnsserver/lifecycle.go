package dnsserver

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/trustanchor"
)

// StartMaintenance begins background cache upkeep. It is separate from the
// constructor so that building a handler stays free of background work, and
// callers that only resolve a query decide for themselves whether a ticker
// should be running behind them.
func (handler *Handler) StartMaintenance() {
	if handler.maintenanceStarted.Swap(true) {
		return
	}
	go handler.maintainCache()
}

// maintainCache runs the cache upkeep that no client request can do on its own:
// reaping entries whose fresh and stale windows have both closed, closing
// forwarder sockets that sat idle past their deadline, and renewing popular
// entries before they expire. Refreshing on a client hit only reaches
// entries that happen to be queried inside the trigger window, so without this
// the hottest records still go cold and make somebody wait for the upstream.
func (handler *Handler) maintainCache() {
	defer close(handler.maintenanceDone)
	sweep := time.NewTicker(cacheSweepInterval)
	defer sweep.Stop()
	refresh := time.NewTicker(cacheRefreshInterval)
	defer refresh.Stop()
	for {
		select {
		case <-handler.maintenanceStop:
			return
		case now := <-sweep.C:
			handler.runtime.Load().cache.SweepExpired()
			if handler.forwarderConnections != nil {
				handler.forwarderConnections.reapIdle(now)
			}
		case <-refresh.C:
			runtime := handler.runtime.Load()
			for _, request := range runtime.cache.PrefetchCandidates(maximumPrefetchBatch) {
				handler.prefetch(request, runtime)
			}
		}
	}
}

// Close stops cache maintenance and waits for all detached cache work. It is
// retained as the unbounded compatibility form of Shutdown.
func (handler *Handler) Close() {
	_ = handler.Shutdown(context.Background())
}

// Shutdown stops cache maintenance, cancels detached cache work, and waits for
// it to leave the shared cache. A deadline returns an error while leaving the
// forwarder pool open for work that is still unwinding.
func (handler *Handler) Shutdown(ctx context.Context) error {
	handler.maintenanceOnce.Do(func() {
		close(handler.maintenanceStop)
		if !handler.maintenanceStarted.Swap(true) {
			close(handler.maintenanceDone)
		}
	})
	handler.backgroundMu.Lock()
	if !handler.backgroundClosed {
		handler.backgroundClosed = true
		handler.backgroundCancel()
	}
	handler.backgroundMu.Unlock()
	handler.backgroundWaitOnce.Do(func() {
		go func() {
			handler.backgroundWG.Wait()
			close(handler.backgroundDone)
		}()
	})
	var shutdownError error
	select {
	case <-handler.maintenanceDone:
	case <-ctx.Done():
		shutdownError = ctx.Err()
	}
	if shutdownError == nil {
		select {
		case <-handler.backgroundDone:
		case <-ctx.Done():
			shutdownError = ctx.Err()
		}
	}
	if shutdownError != nil {
		return shutdownError
	}
	if handler.forwarderConnections != nil {
		handler.forwarderConnections.Close()
	}
	return nil
}

func (handler *Handler) ExportCache() ([]PersistedResponse, error) {
	return handler.runtime.Load().cache.Export()
}

func (handler *Handler) RestoreCache(entries []PersistedResponse) (int, error) {
	return handler.runtime.Load().cache.Restore(entries)
}

// Activate swaps in a runtime compiled from configuration. A configuration
// reload compiles zones it read before the swap, so when ActivateZones has run
// since the handler started, the active zones are recompiled onto the new
// runtime instead. Otherwise a reload that raced a zone change would put the
// replaced zones back. The zone manager follows every change it commits with
// ActivateZones, so a change still on its way lands after this one.
func (handler *Handler) Activate(runtime *Runtime) error {
	handler.activationMu.Lock()
	defer handler.activationMu.Unlock()
	active := handler.runtime.Load()
	if active.zoneGeneration != 0 {
		rebuilt, err := withZones(runtime, active.zoneSource, runtime.keySource)
		if err != nil {
			return fmt.Errorf("apply active zones to new runtime: %w", err)
		}
		rebuilt.zoneGeneration = active.zoneGeneration
		runtime = rebuilt
	}
	if active.upstreams == runtime.upstreams && active.cache.Compatible(runtime.cache) {
		runtime.cache = active.cache
		runtime.delegations = active.delegations
		runtime.zoneCuts = active.zoneCuts
		runtime.nameServers = active.nameServers
	}
	// runtime came from Compile or withZones, so its validator is not yet
	// visible to any query and is safe to change in place.
	if manager := handler.trustAnchorManager.Load(); manager != nil && runtime.managedTrustAnchors && runtime.dnssec != nil {
		if anchors, initialized := manager.ActiveAnchors(); initialized {
			runtime.dnssec.replaceManagedTrustPoint(".", anchors, len(anchors) == 0)
		}
	}
	handler.swapRuntime(active, runtime)
	return nil
}

// ActivateZones compiles only authoritative data and atomically swaps it into
// the active runtime. Blocking tables, hosts, and DNSSEC validation state are
// reused, as is the response cache when recursive routes and validation policy
// are unchanged, so a zone mutation does not rebuild large policy lists or put
// SQL on the DNS request path.
func (handler *Handler) ActivateZones(zones []AuthoritativeZone, keys []TSIGKey) error {
	handler.activationMu.Lock()
	defer handler.activationMu.Unlock()
	active := handler.runtime.Load()
	candidate, err := withZones(active, zones, keys)
	if err != nil {
		return err
	}
	candidate.zoneGeneration = active.zoneGeneration + 1
	handler.swapRuntime(active, candidate)
	return nil
}

// swapRuntime publishes next in place of active. The caller holds
// activationMu.
func (handler *Handler) swapRuntime(active, next *Runtime) {
	handler.recordRuntimeChanges(active, next, time.Now())
	handler.runtime.Store(next)
}

func (handler *Handler) SetTrustAnchorManager(manager *trustanchor.Manager) {
	handler.trustAnchorManager.Store(manager)
	if manager == nil {
		return
	}
	if anchors, initialized := manager.ActiveAnchors(); initialized {
		handler.ApplyManagedTrustAnchors(anchors, len(anchors) == 0)
	}
}

func (handler *Handler) DNSSECTrustAnchorUpdatesEnabled() bool {
	runtime := handler.runtime.Load()
	return runtime != nil && runtime.managedTrustAnchors
}

func (handler *Handler) ApplyManagedTrustAnchors(anchors []string, deleted bool) {
	handler.activationMu.Lock()
	defer handler.activationMu.Unlock()
	active := handler.runtime.Load()
	if active == nil || !active.managedTrustAnchors || active.dnssec == nil {
		return
	}
	if active.dnssec.managedTrustPointEqual(".", anchors, deleted) {
		return
	}
	validator, err := newDNSSECValidator(anchors, active.dnssec.negativeAnchors)
	if err != nil {
		return
	}
	validator.setZoneInsecure(active.dnssec.zoneInsecureDomains())
	if deleted {
		validator.replaceManagedTrustPoint(".", nil, true)
	}
	candidate := *active
	candidate.dnssec = validator
	candidate.cache = NewResponseCacheWithOptions(active.cache.Capacity(), active.cache.options)
	handler.runtime.Store(&candidate)
}

func (handler *Handler) SetQueryObserver(observer querylog.Observer) {
	if observer == nil {
		handler.observer.Store(nil)
		return
	}
	handler.observer.Store(&observerHolder{observer: observer})
}

// SetAttachedNetworks replaces the IPv6 networks private recursion admits
// besides the fixed private ranges.
func (handler *Handler) SetAttachedNetworks(networks []netip.Prefix) {
	networks = slices.Clone(networks)
	handler.attached.Store(&networks)
}

// startBackground closes the admission race with Shutdown: once the lifecycle
// gate is closed, no new detached work may be added after Shutdown begins
// waiting. Callers that succeed must pair this with backgroundWG.Done when the
// work has actually exited.
func (handler *Handler) startBackground() bool {
	handler.backgroundMu.Lock()
	defer handler.backgroundMu.Unlock()
	if handler.backgroundClosed {
		return false
	}
	handler.backgroundWG.Add(1)
	return true
}

func (handler *Handler) PurgeCache() int {
	return handler.runtime.Load().cache.Clear()
}

// PurgeCacheName forgets every cached answer for one name on this node, so the
// next lookup asks upstream again.
func (handler *Handler) PurgeCacheName(name string) int {
	return handler.runtime.Load().cache.RemoveName(name)
}
