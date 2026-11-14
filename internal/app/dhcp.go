package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dhcp"
	"github.com/drudge/sable/internal/store"
)

// errDHCPOnCluster refuses DHCP on a cluster until ranges are pinned to
// nodes and leases mirrored; there is no half-working state.
var errDHCPOnCluster = errors.New("DHCP can't be enabled on a cluster yet")

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
	// role is this node's cluster role: empty when it isn't in a cluster.
	role   func() string
	listen func(context.Context, int) (dhcpConn, error)
	link   func(int) (dhcp.Meta, error)
	probe  dhcpProbe
	// links and seek look for other DHCP servers every othersEvery while
	// this one runs.
	links       func() ([]dhcpProbeLink, error)
	seek        dhcpSeek
	othersEvery time.Duration
	port        int
	// retry is the first wait before binding again after a failure.
	retry  time.Duration
	logger *slog.Logger
	stats  dhcpStats

	mutex   sync.Mutex
	active  config.DHCP
	running *dhcpRunning

	othersMutex sync.Mutex
	others      []dhcpOtherServer
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
		links: dhcpProbeLinks, seek: dhcpDefaultSeek, othersEvery: dhcpOthersInterval,
	}
}

// Check refuses a configuration the service can't run. A replica takes
// [dhcp] from its primary and only holds it, so refusing it there would stop
// every later synchronization (F29); the refusal belongs to the node whose
// sable.toml is edited.
func (service *dhcpService) Check(settings config.DHCP) error {
	if settings.Enabled && service.role() != "" && service.role() != cluster.RoleReplica {
		return errDHCPOnCluster
	}
	return nil
}

// Apply moves the server to settings: unchanged settings keep it running,
// disabled ones stop it, and anything else replaces it. Only settings the
// engine refuses reject the change. Port 67 or the store being unavailable
// is a condition of the host, not of the configuration, so it is logged and
// retried and never holds back a change elsewhere in sable.toml.
func (service *dhcpService) Apply(ctx context.Context, runtime context.Context, settings config.DHCP) error {
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if reflect.DeepEqual(service.active, settings) && (service.running != nil) == settings.Enabled {
		return nil
	}
	if err := service.Check(settings); err != nil {
		return err
	}
	var server *dhcpServer
	if settings.Enabled && service.role() != "" {
		service.logger.Info("DHCP settings kept from the primary; a cluster doesn't serve DHCP yet")
	} else if settings.Enabled {
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
	return nil
}

// prepare builds a server with an engine for settings. Its leases are read
// once the old server has stopped, so none it acknowledges are missed.
func (service *dhcpService) prepare(settings config.DHCP) (*dhcpServer, error) {
	engine, err := dhcp.New(settings, service.node())
	if err != nil {
		return nil, fmt.Errorf("start DHCP engine: %w", err)
	}
	return &dhcpServer{
		engine: engine, save: service.save, load: service.load, link: service.link, probe: service.probe,
		now: time.Now, logger: service.logger, stats: &service.stats,
	}, nil
}

// startLocked binds port 67 and reads the store's leases now, so the old
// server has stopped and nothing it acknowledged is missed, then leaves the
// server to supervise and the probe for other servers to run beside it.
func (service *dhcpService) startLocked(runtime context.Context, settings config.DHCP, server *dhcpServer) {
	ctx, cancel := context.WithCancel(runtime)
	running := &dhcpRunning{cancel: cancel, done: make(chan struct{})}
	err := service.bind(ctx, server)
	var group sync.WaitGroup
	group.Go(func() { service.supervise(ctx, settings, server, err) })
	group.Go(func() { service.watchOthers(ctx, settings) })
	go func() {
		group.Wait()
		close(running.done)
	}()
	service.running = running
}

// supervise serves until ctx ends. A bind that failed (err) or a socket that
// stops is tried again, waiting service.retry at first and twice as long
// each time after, up to dhcpRetryMax.
func (service *dhcpService) supervise(ctx context.Context, settings config.DHCP, server *dhcpServer, err error) {
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
		if server, err = service.prepare(settings); err != nil {
			service.logger.Error("DHCP server not restarted", "error", err)
			return
		}
		err = service.bind(ctx, server)
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
}

func (service *dhcpService) save(ctx context.Context, leases []dhcp.Lease) error {
	rows := make([]store.DHCPLease, len(leases))
	for index, lease := range leases {
		rows[index] = dhcpLeaseToStore(lease)
	}
	_, err := service.leases.SaveDHCPLeases(ctx, rows)
	return err
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
		MAC: lease.MAC, ClientID: lease.ClientID, Hostname: lease.Hostname,
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

// dhcpClusterRole is the node's role for DHCP: none outside a cluster, and a
// replica's while a join applies the primary's state, so the primary's
// [dhcp] is held and not served before the join completes (F30).
func dhcpClusterRole(state cluster.State) string {
	switch {
	case state.Initialized:
		return state.LocalRole
	case state.Joining:
		return cluster.RoleReplica
	}
	return ""
}

// startDHCP starts the DHCP server with the configuration. A failure leaves
// DNS running and is logged: port 67 taken or a cluster shouldn't keep the
// rest of Sable down.
func (process *process) startDHCP() {
	clusterService := process.clusterService
	process.dhcp = newDHCPService(process.database,
		func() string { return clusterService.Snapshot().NodeID },
		func() string { return dhcpClusterRole(clusterService.Snapshot()) },
		process.logger)
	if err := process.dhcp.Apply(process.runtimeContext, process.runtimeContext, process.current().DHCP); err != nil {
		process.logger.Error("DHCP server not started", "error", err)
	}
}
