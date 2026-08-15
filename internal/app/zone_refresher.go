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
	for _, zone := range snapshot.Zones {
		if zone.Type != "secondary" && zone.Type != "stub" {
			continue
		}
		managed[zone.Name] = struct{}{}
		if zone.Disabled {
			refresher.dns.SetZoneExpired(zone.Name, false)
			delete(refresher.states, zone.Name)
			continue
		}
		soa, timers, err := configuredZoneSOA(zone)
		if err != nil {
			refresher.logger.Error("read managed zone SOA", "zone", zone.Name, "error", err)
			continue
		}
		state, tracked := refresher.states[zone.Name]
		if !tracked || state.serial != soa.Serial {
			state = zoneRefreshState{
				serial: soa.Serial, nextAttempt: now.Add(timers.refresh), expiresAt: now.Add(timers.expire),
			}
			refresher.states[zone.Name] = state
			refresher.dns.SetZoneExpired(zone.Name, false)
			continue
		}
		if !now.Before(state.expiresAt) {
			refresher.dns.SetZoneExpired(zone.Name, true)
		}
		if now.Before(state.nextAttempt) {
			continue
		}
		current := dnsserverZoneRecords(zone.Records)
		updated, changed, refreshErr := refresher.dns.RefreshZone(
			ctx, zone.Name, zone.Type, zone.PrimaryServers, zone.PrimaryProtocol, zone.TSIGKey, current,
		)
		if refreshErr == nil && changed {
			refreshErr = refresher.storeRecords(ctx, zone.Name, updated)
		}
		if refreshErr != nil {
			state.nextAttempt = now.Add(timers.retry)
			refresher.states[zone.Name] = state
			if !now.Before(state.expiresAt) {
				refresher.dns.SetZoneExpired(zone.Name, true)
			}
			refresher.logger.Warn("managed zone refresh failed", "zone", zone.Name, "retry_at", state.nextAttempt, "error", refreshErr)
			continue
		}
		if changed {
			zone.Records = configuredZoneRecords(updated)
			soa, timers, err = configuredZoneSOA(zone)
			if err != nil {
				refresher.logger.Error("read refreshed zone SOA", "zone", zone.Name, "error", err)
				continue
			}
		}
		state = zoneRefreshState{
			serial: soa.Serial, nextAttempt: now.Add(timers.refresh), expiresAt: now.Add(timers.expire),
		}
		refresher.states[zone.Name] = state
		refresher.dns.SetZoneExpired(zone.Name, false)
		refresher.logger.Debug("managed zone refreshed", "zone", zone.Name, "serial", soa.Serial, "changed", changed, "next_refresh", state.nextAttempt)
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

func (refresher *zoneRefresher) storeRecords(ctx context.Context, zoneName string, records []dnsserver.ZoneRecord) error {
	return refresher.configuration.UpdateZones(ctx, func(zones *[]zone.Zone) error {
		index := slices.IndexFunc(*zones, func(zone zone.Zone) bool { return zone.Name == zoneName })
		if index < 0 {
			return errors.New("zone was removed during refresh")
		}
		zone := &(*zones)[index]
		if zone.Type != "secondary" && zone.Type != "stub" {
			return errors.New("zone type changed during refresh")
		}
		zone.Records = configuredZoneRecords(records)
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
