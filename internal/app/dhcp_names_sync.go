package app

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/drudge/sable/internal/store"
	"github.com/drudge/sable/internal/zone"
)

// Timing of the DHCP name reconciler: it waits for a burst of lease changes
// to settle, commits at most once per spacing, and looks again every check
// so an expired lease loses its name without an event to say so.
const (
	dhcpNamesSettle  = 2 * time.Second
	dhcpNamesSpacing = 5 * time.Second
	dhcpNamesCheck   = 30 * time.Second
)

// dhcpNamer keeps the zones' DHCP records equal to the records the
// configuration and the leases ask for. It runs on the node that may write
// zones. It writes only when the wanted set changed, so a renewal never
// publishes a revision.
type dhcpNamer struct {
	configuration unifiConfiguration
	zones         unifiZoneEditor
	leases        func(context.Context) ([]store.DHCPLease, error)
	writable      func() bool
	// role is the node's cluster role for DHCP (dhcpClusterRole). Nil means
	// outside a cluster.
	role func() string
	// skipped is the last reconcile's list of names that didn't publish,
	// logged when it changes.
	skipped []string
	// notifier tells a changed zone's secondaries to fetch it (RFC 1996).
	// Nil skips it.
	notifier  zoneNotifier
	notifying sync.WaitGroup
	logger    *slog.Logger
	now       func() time.Time

	settle, spacing, check time.Duration
	wake                   chan struct{}
}

func newDHCPNamer(configuration unifiConfiguration, zones unifiZoneEditor, leases func(context.Context) ([]store.DHCPLease, error), writable func() bool, logger *slog.Logger) *dhcpNamer {
	return &dhcpNamer{
		configuration: configuration, zones: zones, leases: leases, writable: writable,
		logger: logger.With("component", "dhcp-names"), now: time.Now,
		settle: dhcpNamesSettle, spacing: dhcpNamesSpacing, check: dhcpNamesCheck,
		wake: make(chan struct{}, 1),
	}
}

// Changed asks for a reconcile: a lease or the configuration changed.
func (namer *dhcpNamer) Changed() {
	select {
	case namer.wake <- struct{}{}:
	default:
	}
}

// Run reconciles once at start, then after each change and each check.
func (namer *dhcpNamer) Run(ctx context.Context) {
	defer namer.notifying.Wait()
	ticker := time.NewTicker(namer.check)
	defer ticker.Stop()
	namer.Changed()
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !namer.configuration.Current().Config.DHCP.Enabled {
				continue
			}
		case <-namer.wake:
		}
		if !namer.sleep(ctx, last) {
			return
		}
		// A change that arrives while waiting is read below with the rest.
		select {
		case <-namer.wake:
		default:
		}
		namer.reconcile(ctx)
		last = namer.now()
	}
}

// sleep waits for changes to settle and for the spacing since the last
// commit, and reports false when ctx ends first.
func (namer *dhcpNamer) sleep(ctx context.Context, last time.Time) bool {
	wait := namer.settle
	if remaining := namer.spacing - namer.now().Sub(last); remaining > wait {
		wait = remaining
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// reconcile writes the wanted records in one zone update and notifies the
// secondaries of every zone whose serial advanced (RFC 1996 §4.7).
func (namer *dhcpNamer) reconcile(ctx context.Context) {
	if !namer.writable() {
		return
	}
	leases, err := namer.leases(ctx)
	if err != nil {
		namer.logger.Warn("read DHCP leases for names", "error", err)
		return
	}
	now := namer.now()
	settings := dhcpServedSettings(namer.configuration.Current().Config.DHCP, namer.role)
	wanted := desiredDHCPRecords(settings, leases, now)
	var changed, skipped []string
	err = namer.zones.UpdateZones(ctx, func(zones *[]zone.Zone) error {
		before := zoneSerials(*zones)
		skipped = planDHCPZones(zones, wanted, now).Skipped
		changed = advancedZones(before, *zones)
		return nil
	})
	if err != nil {
		namer.logger.Warn("publish DHCP names", "error", err)
		return
	}
	if !slices.Equal(skipped, namer.skipped) {
		namer.skipped = skipped
		namer.logger.Info("DHCP names not published", "names", skipped)
	}
	if namer.notifier == nil || len(changed) == 0 {
		return
	}
	zones := namer.zones.Current().Zones
	notifyCtx := context.WithoutCancel(ctx)
	namer.notifying.Go(func() {
		notifyZones(notifyCtx, namer.notifier, zones, changed, namer.logger, "DHCP names")
	})
}
