package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/zone"
)

const (
	zoneRefreshTick      = time.Second
	notifyCoalesceWindow = 2 * time.Second
	// firstTransferRetry paces retries for a catalog member that has never
	// transferred. Such a zone has no SOA yet, so it has no retry timer of its
	// own to obey.
	firstTransferRetry = time.Minute
)

type zoneRefreshConfiguration interface {
	Current() zone.Snapshot
	UpdateZones(context.Context, func(*[]zone.Zone) error) error
}

type zoneRefreshDNS interface {
	FetchZone(context.Context, string, string, []string, string, string) ([]dnsserver.ZoneRecord, error)
	RefreshZone(context.Context, string, string, []string, string, string, []dnsserver.ZoneRecord) ([]dnsserver.ZoneRecord, bool, error)
	SetZoneExpired(string, bool)
	Notifications() <-chan dnsserver.ZoneNotification
}

type zoneRefreshState struct {
	serial      uint32
	nextAttempt time.Time
	expiresAt   time.Time
}

type zoneRefresher struct {
	configuration zoneRefreshConfiguration
	dns           zoneRefreshDNS
	logger        *slog.Logger
	states        map[string]zoneRefreshState
	lastNotify    map[string]time.Time
}

func newZoneRefresher(configuration zoneRefreshConfiguration, dnsService zoneRefreshDNS, logger *slog.Logger) *zoneRefresher {
	return &zoneRefresher{
		configuration: configuration, dns: dnsService, logger: logger,
		states: make(map[string]zoneRefreshState), lastNotify: make(map[string]time.Time),
	}
}

func (refresher *zoneRefresher) Run(ctx context.Context) {
	ticker := time.NewTicker(zoneRefreshTick)
	defer ticker.Stop()
	refresher.step(ctx, time.Now())
	notifications := refresher.dns.Notifications()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			refresher.step(ctx, now)
		case notification := <-notifications:
			refresher.handleNotification(ctx, notification)
		}
	}
}

func (refresher *zoneRefresher) handleNotification(ctx context.Context, notification dnsserver.ZoneNotification) {
	now := notification.ReceivedAt
	if now.IsZero() {
		now = time.Now()
	}
	if last := refresher.lastNotify[notification.Zone]; !last.IsZero() && now.Sub(last) < notifyCoalesceWindow {
		refresher.logger.Debug("coalesced duplicate zone notification", "zone", notification.Zone, "source", notification.Source)
		return
	}
	refresher.lastNotify[notification.Zone] = now
	state, tracked := refresher.states[notification.Zone]
	if !tracked {
		refresher.step(ctx, now)
		state, tracked = refresher.states[notification.Zone]
	}
	if !tracked {
		return
	}
	state.nextAttempt = now
	refresher.states[notification.Zone] = state
	refresher.logger.Debug("accepted zone notification", "zone", notification.Zone, "source", notification.Source)
	refresher.step(ctx, now)
}

func (refresher *zoneRefresher) step(ctx context.Context, now time.Time) {
	snapshot := refresher.configuration.Current()
	managed := make(map[string]struct{})
	for _, current := range snapshot.Zones {
		// A consumer catalog is refreshed on the same schedule as a secondary.
		// Applying its new membership happens inside the zone transaction that
		// stores the transferred records.
		if current.Type != "secondary" && current.Type != "stub" && !zone.IsConsumerCatalog(current) {
			continue
		}
		managed[current.Name] = struct{}{}
		if current.Disabled {
			refresher.dns.SetZoneExpired(current.Name, false)
			delete(refresher.states, current.Name)
			continue
		}
		if zone.AwaitingFirstTransfer(current) {
			refresher.fetchFirstTransfer(ctx, current, now)
			continue
		}
		soa, timers, err := configuredZoneSOA(current)
		if err != nil {
			refresher.logger.Error("read managed zone SOA", "zone", current.Name, "error", err)
			continue
		}
		state, tracked := refresher.states[current.Name]
		if !tracked || state.serial != soa.Serial {
			state = zoneRefreshState{
				serial: soa.Serial, nextAttempt: now.Add(timers.refresh), expiresAt: now.Add(timers.expire),
			}
			refresher.states[current.Name] = state
			refresher.dns.SetZoneExpired(current.Name, false)
			continue
		}
		if !now.Before(state.expiresAt) {
			refresher.dns.SetZoneExpired(current.Name, true)
		}
		if now.Before(state.nextAttempt) {
			continue
		}
		records := dnsserverZoneRecords(current.Records)
		updated, changed, refreshErr := refresher.dns.RefreshZone(
			ctx, current.Name, current.Type, current.PrimaryServers, current.PrimaryProtocol, current.TSIGKey, records,
		)
		if refreshErr == nil && changed {
			refreshErr = refresher.storeRecords(ctx, current.Name, updated)
		}
		if refreshErr != nil {
			state.nextAttempt = now.Add(timers.retry)
			refresher.states[current.Name] = state
			if !now.Before(state.expiresAt) {
				refresher.dns.SetZoneExpired(current.Name, true)
			}
			refresher.logger.Warn("managed zone refresh failed", "zone", current.Name, "retry_at", state.nextAttempt, "error", refreshErr)
			continue
		}
		if changed {
			current.Records = configuredZoneRecords(updated)
			soa, timers, err = configuredZoneSOA(current)
			if err != nil {
				refresher.logger.Error("read refreshed zone SOA", "zone", current.Name, "error", err)
				continue
			}
		}
		state = zoneRefreshState{
			serial: soa.Serial, nextAttempt: now.Add(timers.refresh), expiresAt: now.Add(timers.expire),
		}
		refresher.states[current.Name] = state
		refresher.dns.SetZoneExpired(current.Name, false)
		refresher.logger.Debug("managed zone refreshed", "zone", current.Name, "serial", soa.Serial, "changed", changed, "next_refresh", state.nextAttempt)
	}
	for name := range refresher.states {
		if _, found := managed[name]; found {
			continue
		}
		refresher.dns.SetZoneExpired(name, false)
		delete(refresher.states, name)
		delete(refresher.lastNotify, name)
	}
}

// fetchFirstTransfer pulls the initial content of a zone a catalog provisioned.
// The catalog names the zone but carries none of its records, so the member
// stays empty and unanswerable until this succeeds.
func (refresher *zoneRefresher) fetchFirstTransfer(ctx context.Context, member zone.Zone, now time.Time) {
	if state, tracked := refresher.states[member.Name]; tracked && now.Before(state.nextAttempt) {
		return
	}
	records, err := refresher.dns.FetchZone(
		ctx, member.Name, "secondary", member.PrimaryServers, member.PrimaryProtocol, member.TSIGKey,
	)
	if err == nil {
		err = refresher.storeRecords(ctx, member.Name, records)
	}
	if err != nil {
		refresher.states[member.Name] = zoneRefreshState{nextAttempt: now.Add(firstTransferRetry)}
		refresher.logger.Warn("catalog member first transfer failed",
			"zone", member.Name, "catalog", member.CatalogZone, "retry_at", now.Add(firstTransferRetry), "error", err)
		return
	}
	// The zone now carries its own SOA, so the next tick schedules it from the
	// timers the primary published.
	delete(refresher.states, member.Name)
	refresher.logger.Info("catalog member transferred", "zone", member.Name, "catalog", member.CatalogZone)
}

func (refresher *zoneRefresher) storeRecords(ctx context.Context, zoneName string, records []dnsserver.ZoneRecord) error {
	return refresher.configuration.UpdateZones(ctx, func(zones *[]zone.Zone) error {
		index := slices.IndexFunc(*zones, func(candidate zone.Zone) bool { return candidate.Name == zoneName })
		if index < 0 {
			return errors.New("zone was removed during refresh")
		}
		current := &(*zones)[index]
		if current.Type != "secondary" && current.Type != "stub" && current.Type != "catalog" {
			return errors.New("zone type changed during refresh")
		}
		current.Records = configuredZoneRecords(records)
		return nil
	})
}

type soaTimers struct {
	refresh time.Duration
	retry   time.Duration
	expire  time.Duration
}

func configuredZoneSOA(zone zone.Zone) (*dns.SOA, soaTimers, error) {
	for _, record := range zone.Records {
		if record.Name != "@" || !strings.EqualFold(record.Type, "SOA") || record.Disabled {
			continue
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN SOA %s", dns.Fqdn(zone.Name), record.TTL, record.Value))
		if err != nil {
			return nil, soaTimers{}, err
		}
		soa, ok := rr.(*dns.SOA)
		if !ok {
			return nil, soaTimers{}, errors.New("apex record is not an SOA")
		}
		timers := soaTimers{
			refresh: time.Duration(soa.Refresh) * time.Second,
			retry:   time.Duration(soa.Retry) * time.Second,
			expire:  time.Duration(soa.Expire) * time.Second,
		}
		if timers.refresh <= 0 || timers.retry <= 0 || timers.expire <= 0 {
			return nil, soaTimers{}, errors.New("SOA refresh, retry, and expire must be positive")
		}
		return soa, timers, nil
	}
	return nil, soaTimers{}, errors.New("zone has no active apex SOA")
}

func dnsserverZoneRecords(records []zone.Record) []dnsserver.ZoneRecord {
	result := make([]dnsserver.ZoneRecord, 0, len(records))
	for _, record := range records {
		result = append(result, dnsserver.ZoneRecord{
			Name: record.Name, Type: record.Type, Value: record.Value, TTL: record.TTL,
			Disabled: record.Disabled, ExpiresAt: record.ExpiresAt,
		})
	}
	return result
}

func configuredZoneRecords(records []dnsserver.ZoneRecord) []zone.Record {
	result := make([]zone.Record, 0, len(records))
	for _, record := range records {
		result = append(result, zone.Record{
			Name: record.Name, Type: record.Type, Value: record.Value, TTL: record.TTL,
			Disabled: record.Disabled, ExpiresAt: record.ExpiresAt,
		})
	}
	return result
}
