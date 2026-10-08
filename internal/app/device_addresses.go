package app

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/insights/devices"
	"github.com/drudge/sable/internal/querylog"
)

// deviceAddressTable keeps the DNS server's table of the addresses used by
// devices that blocking names by hardware address: those in a rule set, and
// those with a hold. Each new batch of identities, from the neighbor table,
// UniFi, or the cluster lead, and each configuration change wakes it to
// rebuild the table from the store. Nothing here runs on the DNS request
// path.
type deviceAddressTable struct {
	read     func(context.Context, time.Time) ([]querylog.ClientIdentity, error)
	tracking func() bool
	apply    func(dnsserver.DeviceAddresses)
	logger   *slog.Logger

	mu   sync.Mutex
	macs map[string]struct{}
	wake chan struct{}
}

func newDeviceAddressTable(
	read func(context.Context, time.Time) ([]querylog.ClientIdentity, error),
	tracking func() bool,
	apply func(dnsserver.DeviceAddresses),
	logger *slog.Logger,
) *deviceAddressTable {
	return &deviceAddressTable{read: read, tracking: tracking, apply: apply, logger: logger, wake: make(chan struct{}, 1)}
}

// SetConfiguration picks out the devices blocking names by hardware address
// and asks for a rebuild. A process that never started DNS has no table, so
// a nil one does nothing.
func (table *deviceAddressTable) SetConfiguration(configuration config.Config) {
	if table == nil {
		return
	}
	macs := blockingHardwareAddresses(configuration)
	table.mu.Lock()
	table.macs = macs
	table.mu.Unlock()
	table.Refresh()
}

// Refresh asks for a rebuild without waiting for it. Requests made while one
// is pending fold into it.
func (table *deviceAddressTable) Refresh() {
	select {
	case table.wake <- struct{}{}:
	default:
	}
}

// Record wraps an identity recorder so every batch it stores refreshes the
// table.
func (table *deviceAddressTable) Record(record func(context.Context, []querylog.ClientIdentity) error) func(context.Context, []querylog.ClientIdentity) error {
	return func(ctx context.Context, identities []querylog.ClientIdentity) error {
		err := record(ctx, identities)
		table.Refresh()
		return err
	}
}

// Run rebuilds the table whenever it is asked to, until ctx ends.
func (table *deviceAddressTable) Run(ctx context.Context) {
	reported := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-table.wake:
		}
		if err := table.rebuild(ctx, time.Now()); err != nil && !reported && ctx.Err() == nil {
			// A store that can't be read fails the same way every minute.
			table.logger.Warn("read device addresses for blocking", "error", err)
			reported = true
		}
	}
}

func (table *deviceAddressTable) rebuild(ctx context.Context, now time.Time) error {
	table.mu.Lock()
	macs := table.macs
	table.mu.Unlock()
	// Without a device named by hardware address, or with Insights off,
	// there is nothing to look up: only configured addresses apply.
	if len(macs) == 0 || !table.tracking() {
		table.apply(nil)
		return nil
	}
	identities, err := table.read(ctx, now.Add(-devices.Lookback))
	if err != nil {
		return err
	}
	table.apply(deviceAddresses(macs, identities))
	return nil
}

// blockingHardwareAddresses collects the devices blocking names by hardware
// address, in net.HardwareAddr's form.
func blockingHardwareAddresses(configuration config.Config) map[string]struct{} {
	var macs map[string]struct{}
	add := func(value string) {
		mac, err := net.ParseMAC(value)
		if err != nil {
			return
		}
		if macs == nil {
			macs = make(map[string]struct{})
		}
		macs[mac.String()] = struct{}{}
	}
	for _, client := range configuration.Clients {
		if client.RuleSet != "" {
			add(client.MAC)
		}
	}
	for _, hold := range configuration.Blocking.Holds {
		add(hold.MAC)
	}
	return macs
}

// deviceAddresses ties each address to the device that used it last, for
// the devices in macs. identities must be newest first, as the store returns
// them, so an address that moved to another device follows it.
func deviceAddresses(macs map[string]struct{}, identities []querylog.ClientIdentity) dnsserver.DeviceAddresses {
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
		mac, err := net.ParseMAC(identity.MAC)
		if err != nil {
			continue
		}
		if _, found := macs[mac.String()]; found {
			addresses[address] = mac.String()
		}
	}
	return addresses
}
