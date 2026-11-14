package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"

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
	leases    dhcpLeaseStore
	node      func() string
	clustered func() bool
	listen    func(context.Context, int) (dhcpConn, error)
	link      func(int) (dhcp.Meta, error)
	probe     dhcpProbe
	port      int
	logger    *slog.Logger
	stats     dhcpStats

	mutex   sync.Mutex
	active  config.DHCP
	running *dhcpRunning
}

// dhcpRunning is one started server and how to stop it.
type dhcpRunning struct {
	cancel context.CancelFunc
	done   chan error
}

func newDHCPService(leases dhcpLeaseStore, node func() string, clustered func() bool, logger *slog.Logger) *dhcpService {
	logger = logger.With("component", "dhcp")
	return &dhcpService{
		leases: leases, node: node, clustered: clustered,
		listen: func(ctx context.Context, port int) (dhcpConn, error) { return listenDHCP(ctx, port) },
		link:   dhcpLink, probe: newDHCPProber(logger).probe, port: dhcpServerPort, logger: logger,
	}
}

// Check refuses a configuration the service can't run.
func (service *dhcpService) Check(settings config.DHCP) error {
	if settings.Enabled && service.clustered() {
		return errDHCPOnCluster
	}
	return nil
}

// Apply moves the server to settings: unchanged settings keep it running,
// disabled ones stop it, and anything else replaces it. The new engine is
// built and its leases read before the old server stops, and the old socket
// closes before the new one binds port 67.
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
	if settings.Enabled {
		prepared, err := service.prepare(ctx, settings)
		if err != nil {
			return err
		}
		server = prepared
	}
	service.stopLocked()
	if server != nil {
		if err := service.startLocked(runtime, server); err != nil {
			return err
		}
	}
	service.active = settings
	return nil
}

// prepare builds an engine for settings holding the store's leases.
func (service *dhcpService) prepare(ctx context.Context, settings config.DHCP) (*dhcpServer, error) {
	engine, err := dhcp.New(settings, service.node())
	if err != nil {
		return nil, fmt.Errorf("start DHCP engine: %w", err)
	}
	server := &dhcpServer{
		engine: engine, save: service.save, load: service.load, link: service.link, probe: service.probe,
		now: time.Now, logger: service.logger, stats: &service.stats,
	}
	if !server.reload(ctx) {
		return nil, errors.New("read DHCP leases from the store")
	}
	return server, nil
}

func (service *dhcpService) startLocked(runtime context.Context, server *dhcpServer) error {
	conn, err := service.listen(runtime, service.port)
	if err != nil {
		return fmt.Errorf("listen for DHCP on port %d: %w", service.port, err)
	}
	server.conn = conn
	ctx, cancel := context.WithCancel(runtime)
	running := &dhcpRunning{cancel: cancel, done: make(chan error, 1)}
	go func() {
		err := server.run(ctx)
		if err != nil {
			service.logger.Error("DHCP server stopped", "error", err)
		}
		running.done <- err
	}()
	service.running = running
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

// startDHCP starts the DHCP server with the configuration. A failure leaves
// DNS running and is logged: port 67 taken or a cluster shouldn't keep the
// rest of Sable down.
func (process *process) startDHCP() {
	clusterService := process.clusterService
	process.dhcp = newDHCPService(process.database,
		func() string { return clusterService.Snapshot().NodeID },
		func() bool { return clusterService.Snapshot().Initialized },
		process.logger)
	if err := process.dhcp.Apply(process.runtimeContext, process.runtimeContext, process.current().DHCP); err != nil {
		process.logger.Error("DHCP server not started", "error", err)
	}
}
