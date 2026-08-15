package app

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/drudge/sable/internal/zone"
)

const dnssecRefreshCheckInterval = time.Hour

type dnssecRefreshManager interface {
	Current() zone.Snapshot
	UpdateZones(context.Context, func(*[]zone.Zone) error) error
}

type dnssecRefreshNotifier interface {
	NotifyZone(context.Context, string, []string) []error
}

func runDNSSECRefresher(
	ctx context.Context,
	manager dnssecRefreshManager,
	signer *dnssecSigner,
	notifier dnssecRefreshNotifier,
	logger *slog.Logger,
) {
	ticker := time.NewTicker(dnssecRefreshCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshDNSSECZones(ctx, manager, signer, notifier, logger)
		}
	}
}

func refreshDNSSECZones(
	ctx context.Context,
	manager dnssecRefreshManager,
	signer *dnssecSigner,
	notifier dnssecRefreshNotifier,
	logger *slog.Logger,
) {
	zones, err := signer.ZonesNeedingRefresh(ctx, manager.Current().Zones)
	if err != nil {
		logger.Error("inspect DNSSEC refresh schedule", "error", err)
		return
	}
	if len(zones) == 0 {
		return
	}
	if err := manager.UpdateZones(ctx, func(*[]zone.Zone) error { return nil }); err != nil {
		logger.Error("refresh DNSSEC signatures", "zones", zones, "error", err)
		return
	}
	current := manager.Current()
	for _, zone := range current.Zones {
		if !slices.Contains(zones, zone.Name) {
			continue
		}
		logger.Info("DNSSEC signatures refreshed", "zone", zone.Name)
		for _, err := range notifier.NotifyZone(ctx, zone.Name, zone.Notify) {
			logger.Warn("notify secondary server after DNSSEC refresh", "zone", zone.Name, "error", err)
		}
	}
}
