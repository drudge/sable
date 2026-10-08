package app

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/querylog"
)

// deviceRuleSets keeps the DNS server's table of addresses that belong to a
// device in a rule set, for devices named by hardware address. Each new
// batch of identities, from the neighbor table, UniFi, or the cluster lead,
// and each configuration change wakes it to rebuild the table from the store.
// Nothing here runs on the DNS request path.
type deviceRuleSets struct {
	read     func(context.Context, time.Time) ([]querylog.ClientIdentity, error)
	tracking func() bool
	apply    func(dnsserver.DeviceAddresses)
	logger   *slog.Logger

	mu      sync.Mutex
	clients []config.Client
	wake    chan struct{}
}

func newDeviceRuleSets(
	read func(context.Context, time.Time) ([]querylog.ClientIdentity, error),
	tracking func() bool,
	apply func(dnsserver.DeviceAddresses),
	logger *slog.Logger,
) *deviceRuleSets {
	return &deviceRuleSets{read: read, tracking: tracking, apply: apply, logger: logger, wake: make(chan struct{}, 1)}
}

// SetClients hands over the configured devices and asks for a rebuild. A
// process that never started DNS has no table, so a nil one does nothing.
func (table *deviceRuleSets) SetClients(clients []config.Client) {
	if table == nil {
		return
	}
	table.mu.Lock()
	table.clients = clients
	table.mu.Unlock()
	table.Refresh()
}

// Refresh asks for a rebuild without waiting for it. Requests made while one
// is pending fold into it.
func (table *deviceRuleSets) Refresh() {
	select {
	case table.wake <- struct{}{}:
	default:
	}
}

// Record wraps an identity recorder so every batch it stores refreshes the
// table.
func (table *deviceRuleSets) Record(record func(context.Context, []querylog.ClientIdentity) error) func(context.Context, []querylog.ClientIdentity) error {
	return func(ctx context.Context, identities []querylog.ClientIdentity) error {
		err := record(ctx, identities)
		table.Refresh()
		return err
	}
}

// Run rebuilds the table whenever it is asked to, until ctx ends.
func (table *deviceRuleSets) Run(ctx context.Context) {
	reported := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-table.wake:
		}
		if err := table.rebuild(ctx, time.Now()); err != nil && !reported && ctx.Err() == nil {
			// A store that can't be read fails the same way every minute.
			table.logger.Warn("read device addresses for blocking rule sets", "error", err)
			reported = true
		}
	}
}

func (table *deviceRuleSets) rebuild(ctx context.Context, now time.Time) error {
	table.mu.Lock()
	clients := table.clients
	table.mu.Unlock()
	ruleSets := ruleSetsByMAC(clients)
	// Without a device in a rule set by hardware address, or with Insights
	// off, there is nothing to look up: only configured addresses apply.
	if len(ruleSets) == 0 || !table.tracking() {
		table.apply(nil)
		return nil
	}
	identities, err := table.read(ctx, now.Add(-devices.Lookback))
	if err != nil {
		return err
	}
	table.apply(deviceAddresses(ruleSets, identities))
	return nil
}

// ruleSetsByMAC maps each device named by hardware address to its rule set.
func ruleSetsByMAC(clients []config.Client) map[string]string {
	var ruleSets map[string]string
	for _, client := range clients {
		if client.MAC == "" || client.RuleSet == "" {
			continue
		}
		if ruleSets == nil {
			ruleSets = make(map[string]string)
		}
		ruleSets[strings.ToLower(client.MAC)] = client.RuleSet
	}
	return ruleSets
}

// deviceAddresses ties each address to the rule set of the device that used
// it last. identities must be newest first, as the store returns them, so an
// address that moved to another device follows it.
func deviceAddresses(ruleSets map[string]string, identities []querylog.ClientIdentity) dnsserver.DeviceAddresses {
	addresses := make(dnsserver.DeviceAddresses)
	claimed := make(map[netip.Addr]struct{}, len(identities))
	for _, identity := range identities {
		address, err := netip.ParseAddr(identity.Address)
		if err != nil {
			continue
		}
		address = address.Unmap().WithZone("")
		if _, taken := claimed[address]; taken {
			continue
		}
		claimed[address] = struct{}{}
		if ruleSet, found := ruleSets[strings.ToLower(identity.MAC)]; found {
			addresses[address] = ruleSet
		}
	}
	return addresses
}
