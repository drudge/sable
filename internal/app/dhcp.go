package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dhcp"
	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/version"
)

// dhcpLeaseStore is the part of the store the DHCP server uses.
type dhcpLeaseStore interface {
	SaveDHCPLeases(context.Context, []store.DHCPLease) ([]store.DHCPLease, error)
	DHCPLeases(context.Context) ([]store.DHCPLease, error)
}

// dhcpService runs the DHCPv4 server for the process and moves it to each
// new [dhcp] configuration. Its counters outlive restarts of the server.
type dhcpService struct {
	leases dhcpLeaseStore
	node   func() string
	// role is this node's cluster role for DHCP (dhcpClusterRole): empty
	// when it isn't in a cluster.
	role func() string
	// cluster is this node's cluster state, for the members a range may name
	// and their releases. Nil is outside a cluster.
	cluster func() cluster.State
	listen  func(context.Context, int) (dhcpConn, error)
	link    func(int) (dhcp.Meta, error)
	probe   dhcpProbe
	// links and seek look for other DHCP servers every othersEvery while
	// this one runs.
	links func() ([]dhcpProbeLink, error)
	seek  dhcpSeek
	// gateways maps each interface to its default route, for the router
	// setup suggests.
	gateways    func() map[string]netip.Addr
	othersEvery time.Duration
	port        int
	// retry is the first wait before binding again after a failure.
	retry  time.Duration
	logger *slog.Logger
	stats  dhcpStats
	// changed is told when a lease or the settings change, so the names
	// follow. Nil skips it.
	changed func()

	// current is the server that last bound port 67, for removals.
	current atomic.Pointer[dhcpServer]
	// serving is the settings the running server rebuilds from when it has
	// to bind again, kept up to date by changes applied in place.
	serving atomic.Pointer[config.DHCP]
	// rebinding is held while supervise builds and binds the next server,
	// and while a change is applied in place, so the change reaches the
	// server that ends up on port 67 and not one about to be replaced.
	rebinding sync.Mutex

	mutex   sync.Mutex
	active  config.DHCP
	running *dhcpRunning

	othersMutex sync.Mutex
	others      []dhcpOtherServer
	ownProbes   dhcpOwnProbes
}

// dhcpRunning is one started server and how to stop it.
type dhcpRunning struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// dhcpRetryMax caps the wait between attempts to bring the server back.
const dhcpRetryMax = 30 * time.Second

func newDHCPService(leases dhcpLeaseStore, node func() string, role func() string, logger *slog.Logger) *dhcpService {
	logger = logger.With("component", "dhcp")
	return &dhcpService{
		leases: leases, node: node, role: role,
		listen: func(ctx context.Context, port int) (dhcpConn, error) { return listenDHCP(ctx, port) },
		link:   dhcpLink, probe: newDHCPProber(logger).probe, port: dhcpServerPort, retry: time.Second, logger: logger,
		links: dhcpProbeLinks, seek: dhcpDefaultSeek, gateways: dhcpDefaultGateways, othersEvery: dhcpOthersInterval,
	}
}

// Check refuses a configuration the service can't run (checkDHCPCluster). A
// replica takes [dhcp] from its primary, so refusing it there would stop
// every later synchronization (F29); the refusal belongs to the node whose
// sable.toml is edited.
func (service *dhcpService) Check(settings config.DHCP) error {
	role := service.role()
	if !settings.Enabled || role == cluster.RoleReplica || role == dhcpRoleJoining {
		return nil
	}
	return checkDHCPCluster(settings, service.clusterState(), version.Release)
}

// checkServable refuses settings this node can't serve whatever the other
// members are: on a cluster's primary, a range without a node. Apply asks only
// this. A member that was removed or runs an older release is refused where
// [dhcp] is edited (Check), not at start, when nothing was edited and the
// node's own ranges would go unserved.
func (service *dhcpService) checkServable(settings config.DHCP) error {
	role := service.role()
	if !settings.Enabled || role == "" || role == cluster.RoleReplica || role == dhcpRoleJoining {
		return nil
	}
	return dhcpRangesPinned(settings)
}

// clusterState is this node's cluster state; zero outside a cluster.
func (service *dhcpService) clusterState() cluster.State {
	if service.cluster == nil {
		return cluster.State{}
	}
	return service.cluster()
}

// newEngine compiles what this node serves of settings (dhcpNodeSettings).
func (service *dhcpService) newEngine(settings config.DHCP) (*dhcp.Engine, error) {
	clustered := service.role != nil && service.role() != ""
	engine, err := dhcp.New(dhcpNodeSettings(settings, clustered), service.node())
	if err != nil {
		return nil, fmt.Errorf("start DHCP engine: %w", err)
	}
	return engine, nil
}

// Apply moves the server to settings: unchanged settings keep it running,
// disabled ones stop it, and anything else replaces it. Only settings the
// engine refuses, or an unpinned range on a cluster (checkServable), reject
// the change. The rest of what a cluster can't serve safely is refused where
// [dhcp] is edited (Check, through checkDHCP): at start a node serves what is
// pinned to it, whatever became of the other members since (D63). Port 67 or
// the store being unavailable is a condition of the host, not of the
// configuration, so it is logged and retried and never holds back a change
// elsewhere in sable.toml.
func (service *dhcpService) Apply(ctx context.Context, runtime context.Context, settings config.DHCP) error {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if reflect.DeepEqual(service.active, settings) && (service.running != nil) == settings.Enabled {
		return nil
	}
	if err := service.checkServable(settings); err != nil {
		return err
	}
	if applied, err := service.applyInPlace(settings); applied || err != nil {
		return err
	}
	var server *dhcpServer
	switch {
	case settings.Enabled && service.role() == dhcpRoleJoining:
		service.logger.Info("DHCP settings kept until this node finishes joining the cluster")
	case settings.Enabled && service.role() != "" && !dhcpServesAnything(dhcpNodeSettings(settings, true), service.node()):
		service.logger.Info("DHCP settings kept; no range is pinned to this node and no scope has reservations")
	case settings.Enabled:
		prepared, err := service.prepare(settings)
		if err != nil {
			return err
		}
		server = prepared
	}
	service.stopLocked()
	if server != nil {
		service.startLocked(runtime, settings, server)
	}
	service.active = settings
	service.notifyChanged()
	return nil
}

// applyInPlace moves a running server to settings that differ from the
// active ones only in reservations, without closing port 67: a restart
// drops every client mid-exchange and every pending offer (D48). It
// reports false when the change needs a new server.
func (service *dhcpService) applyInPlace(settings config.DHCP) (bool, error) {
	server := service.current.Load()
	if service.running == nil || server == nil || service.role() == dhcpRoleJoining || !dhcpReservationsOnly(service.active, settings) {
		return false, nil
	}
	engine, err := service.newEngine(settings)
	if err != nil {
		return false, err
	}
	service.rebinding.Lock()
	service.current.Load().engine.Rescope(engine)
	service.serving.Store(&settings)
	service.rebinding.Unlock()
	service.active = settings
	service.logger.Info("DHCP reservations applied")
	service.notifyChanged()
	return true, nil
}

// dhcpReservationsOnly reports whether two enabled configurations differ
// only in their scopes' reservations.
func dhcpReservationsOnly(active, next config.DHCP) bool {
	if !active.Enabled || !next.Enabled || len(active.Scopes) != len(next.Scopes) {
		return false
	}
	active.Scopes, next.Scopes = slices.Clone(active.Scopes), slices.Clone(next.Scopes)
	for index := range active.Scopes {
		active.Scopes[index].Reservations = nil
		next.Scopes[index].Reservations = nil
	}
	return reflect.DeepEqual(active, next)
}

func (service *dhcpService) notifyChanged() {
	if service.changed != nil {
		service.changed()
	}
}

// prepare builds a server with an engine for settings. Its leases are read
// once the old server has stopped, so none it acknowledges are missed.
func (service *dhcpService) prepare(settings config.DHCP) (*dhcpServer, error) {
	engine, err := service.newEngine(settings)
	if err != nil {
		return nil, err
	}
	engine.SetLabeler(dhcpLabel)
	return &dhcpServer{
		engine: engine, save: service.save, load: service.load, link: service.link, probe: service.probe,
		ownProbes: &service.ownProbes, now: time.Now, logger: service.logger, stats: &service.stats,
	}, nil
}

// startLocked binds port 67 and reads the store's leases now, so the old
// server has stopped and nothing it acknowledged is missed, then leaves the
// server to supervise and the probe for other servers to run beside it.
func (service *dhcpService) startLocked(runtime context.Context, settings config.DHCP, server *dhcpServer) {
	ctx, cancel := context.WithCancel(runtime)
	running := &dhcpRunning{cancel: cancel, done: make(chan struct{})}
	service.serving.Store(&settings)
	err := service.bind(ctx, server)
	var group sync.WaitGroup
	group.Go(func() { service.supervise(ctx, server, err) })
	group.Go(func() { service.watchOthers(ctx, settings) })
	go func() {
		group.Wait()
		close(running.done)
	}()
	service.running = running
}

// supervise serves until ctx ends. A bind that failed (err) or a socket that
// stops is tried again, waiting service.retry at first and twice as long
// each time after, up to dhcpRetryMax, from the settings it serves now.
func (service *dhcpService) supervise(ctx context.Context, server *dhcpServer, err error) {
	wait := service.retry
	for {
		if err == nil {
			wait = service.retry
			if err = server.run(ctx); err == nil {
				err = errors.New("DHCP socket closed")
			}
		}
		if ctx.Err() != nil {
			return
		}
		service.logger.Error("DHCP server not running; trying again", "error", err, "in", wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, dhcpRetryMax)
		// The engine was built from these settings before, so it builds again.
		service.rebinding.Lock()
		if server, err = service.prepare(*service.serving.Load()); err != nil {
			service.rebinding.Unlock()
			service.logger.Error("DHCP server not restarted", "error", err)
			return
		}
		err = service.bind(ctx, server)
		service.rebinding.Unlock()
	}
}

// bind gives server its socket and the store's leases. A failed read leaves
// it silent until a reload works, as after a failed save (D27).
func (service *dhcpService) bind(ctx context.Context, server *dhcpServer) error {
	conn, err := service.listen(ctx, service.port)
	if err != nil {
		return fmt.Errorf("listen for DHCP on port %d: %w", service.port, err)
	}
	server.conn = conn
	if !server.reload(ctx) {
		server.stale = true
	}
	// Status reads current, so it must find a queue there: a server it
	// can see is one that takes requests, not one still starting.
	server.openQueue()
	service.current.Store(server)
	service.logger.Info("DHCP server started", "port", service.port)
	return nil
}

// Stop stops the server and waits until its socket is closed.
func (service *dhcpService) Stop() {
	if service == nil {
		return
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	service.stopLocked()
	service.active = config.DHCP{}
}

func (service *dhcpService) stopLocked() {
	if service.running == nil {
		return
	}
	service.running.cancel()
	<-service.running.done
	service.running = nil
	service.setOthers(nil)
	service.current.Store(nil)
}

func (service *dhcpService) save(ctx context.Context, leases []dhcp.Lease) error {
	rows := make([]store.DHCPLease, len(leases))
	for index, lease := range leases {
		rows[index] = dhcpLeaseToStore(lease)
	}
	if _, err := service.leases.SaveDHCPLeases(ctx, rows); err != nil {
		return err
	}
	service.notifyChanged()
	return nil
}

func (service *dhcpService) load(ctx context.Context) ([]dhcp.Lease, error) {
	rows, err := service.leases.DHCPLeases(ctx)
	if err != nil {
		return nil, err
	}
	leases := make([]dhcp.Lease, len(rows))
	for index, row := range rows {
		leases[index] = dhcpLeaseFromStore(row)
	}
	return leases, nil
}

func dhcpLeaseToStore(lease dhcp.Lease) store.DHCPLease {
	return store.DHCPLease{
		NodeID: lease.NodeID, Address: lease.Address, ScopeID: lease.ScopeID, ClientKey: lease.ClientKey,
		MAC: lease.MAC, ClientID: lease.ClientID, Hostname: lease.Hostname, Label: dhcpLabel(lease.Hostname, false),
		State: store.DHCPLeaseState(lease.State), BoundAt: lease.BoundAt, ExpiresAt: lease.ExpiresAt,
		Relay: lease.Relay, VendorClass: lease.VendorClass,
	}
}

func dhcpLeaseFromStore(row store.DHCPLease) dhcp.Lease {
	return dhcp.Lease{
		NodeID: row.NodeID, Address: row.Address, ScopeID: row.ScopeID, ClientKey: row.ClientKey,
		MAC: row.MAC, ClientID: row.ClientID, Hostname: row.Hostname,
		State: dhcp.LeaseState(row.State), BoundAt: row.BoundAt, ExpiresAt: row.ExpiresAt,
		Relay: row.Relay, VendorClass: row.VendorClass,
	}
}

// dhcpClusterRole is the node's role for DHCP: none outside a cluster, and
// dhcpRoleJoining while a join applies the primary's state, so the primary's
// [dhcp] is held and not served before the join completes (F30).
func dhcpClusterRole(state cluster.State) string {
	switch {
	case state.Initialized:
		return state.LocalRole
	case state.Joining:
		return dhcpRoleJoining
	}
	return ""
}

// dhcpRole is this node's cluster role for DHCP now.
func (process *process) dhcpRole() string {
	return dhcpClusterRole(process.clusterService.Snapshot())
}

// startDHCP starts the DHCP server with the configuration. A failure leaves
// DNS running and is logged: port 67 taken or a cluster shouldn't keep the
// rest of Sable down.
func (process *process) startDHCP() {
	clusterService := process.clusterService
	process.dhcp = newDHCPService(process.database,
		func() string { return clusterService.Snapshot().NodeID },
		process.dhcpRole, process.logger)
	process.dhcp.cluster = clusterService.Snapshot
	process.dhcp.ownProbes.cluster = func() string { return clusterService.Snapshot().ClusterID }
	names := newDHCPNamer(process.configurationManager, process.zoneManager, process.database.DHCPLeases, process.leading, process.logger)
	names.role = process.dhcpRole
	names.notifier = process.handler
	if process.unifiSync != nil {
		names.kick = process.unifiSync.SyncNow
	}
	identities := newDHCPIdentities(process.insightsEnabled, process.database.DHCPLeases,
		func() string { return clusterService.Snapshot().NodeID },
		func() config.DHCP { return process.current().DHCP },
		process.deviceAddresses.Record(process.database.RecordClientIdentities), process.logger)
	process.dhcp.changed = func() { names.Changed(); identities.Changed() }
	process.runWorker(func(context.Context) { names.Run(process.zoneRefreshContext) })
	process.runWorker(func(context.Context) { identities.Run(process.runtimeContext) })
	if err := process.dhcp.Apply(process.runtimeContext, process.runtimeContext, process.current().DHCP); err != nil {
		process.logger.Error("DHCP server not started", "error", err)
	}
}
