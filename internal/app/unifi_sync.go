package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsname"
	"github.com/drudge/sable/internal/unifi"
	"github.com/drudge/sable/internal/zone"
)

// unifiSyncTick is the resolution at which the synchronizer notices a changed
// interval or a newly enabled integration. The configured interval controls how
// often the controller is actually contacted.
const unifiSyncTick = 5 * time.Second

type unifiZoneEditor interface {
	Current() zone.Snapshot
	UpdateZones(context.Context, func(*[]zone.Zone) error) error
}

type unifiConfiguration interface {
	Current() config.Snapshot
}

// unifiInventoryReader is the controller-facing dependency, which tests replace
// with a fixture.
type unifiInventoryReader interface {
	Inventory(context.Context) (unifi.Inventory, error)
}

// unifiCredentialReader hands out the controller credentials sealed in the
// secret vault.
type unifiCredentialReader interface {
	Get(context.Context) (unifi.Credentials, bool)
	Replace(context.Context, unifi.Credentials) error
	Clear(context.Context) error
}

// unifiSyncer publishes UniFi networks, reservations, and clients as records in
// the zones the operator mapped them to.
type unifiSyncer struct {
	configuration unifiConfiguration
	zones         unifiZoneEditor
	credentials   unifiCredentialReader
	writable      func() bool
	logger        *slog.Logger
	now           func() time.Time
	// newReader is swapped in tests to avoid contacting a controller.
	newReader func(unifi.Options) (unifiInventoryReader, error)

	wake chan struct{}

	mu     sync.Mutex
	status unifi.Status
}

func newUniFiSyncer(
	configuration unifiConfiguration,
	zones unifiZoneEditor,
	credentials unifiCredentialReader,
	writable func() bool,
	logger *slog.Logger,
) *unifiSyncer {
	return &unifiSyncer{
		configuration: configuration,
		zones:         zones,
		credentials:   credentials,
		writable:      writable,
		logger:        logger,
		now:           time.Now,
		newReader: func(options unifi.Options) (unifiInventoryReader, error) {
			return unifi.New(options)
		},
		wake: make(chan struct{}, 1),
	}
}

// Status returns the current synchronizer state for the console.
func (syncer *unifiSyncer) Status() unifi.Status {
	syncer.mu.Lock()
	defer syncer.mu.Unlock()
	status := syncer.status
	status.Enabled = syncer.configuration.Current().Config.UniFi.Runnable()
	return status
}

// SyncNow asks the background loop to run immediately. The status flips to
// running here rather than in the worker so the console reflects the click
// straight away instead of waiting for the next poll.
func (syncer *unifiSyncer) SyncNow() {
	if !syncer.configuration.Current().Config.UniFi.Runnable() {
		return
	}
	syncer.mu.Lock()
	syncer.status.Running = true
	syncer.mu.Unlock()
	select {
	case syncer.wake <- struct{}{}:
	default:
	}
}

// Run drives the synchronizer until the context is cancelled.
func (syncer *unifiSyncer) Run(ctx context.Context) {
	ticker := time.NewTicker(unifiSyncTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if syncer.due() {
				syncer.runOnce(ctx)
			}
		case <-syncer.wake:
			syncer.runOnce(ctx)
		}
	}
}

func (syncer *unifiSyncer) due() bool {
	settings := syncer.configuration.Current().Config.UniFi
	if !settings.Runnable() {
		return false
	}
	syncer.mu.Lock()
	defer syncer.mu.Unlock()
	next := syncer.status.NextAttempt
	return next.IsZero() || !syncer.now().Before(next)
}

func (syncer *unifiSyncer) runOnce(ctx context.Context) {
	settings := syncer.configuration.Current().Config.UniFi
	// A replica serves a copy of the primary's zones. Writing here would fight
	// the replication stream, so only the writable node synchronizes. Either way
	// the running flag must be released, or a queued click would spin forever.
	if !settings.Runnable() || (syncer.writable != nil && !syncer.writable()) {
		syncer.mu.Lock()
		syncer.status.Running = false
		syncer.mu.Unlock()
		return
	}
	started := syncer.now()
	syncer.beginAttempt(started)
	plan, hosts, err := syncer.synchronize(ctx, settings, false)
	syncer.finishAttempt(started, settings.Interval.Duration, plan, hosts, err)
	switch {
	case err != nil:
		syncer.logger.Warn("UniFi synchronization failed", "error", err)
	case !plan.Empty():
		syncer.logger.Info("UniFi synchronization applied",
			"hosts", hosts, "zones_created", len(plan.CreatedZones),
			"added", len(plan.Added), "updated", len(plan.Updated), "removed", len(plan.Removed))
	}
}

// Preview computes what a synchronization would do without changing anything.
// The setup wizard renders the result on its review step.
func (syncer *unifiSyncer) Preview(ctx context.Context, settings config.UniFi) (unifi.Plan, error) {
	plan, _, err := syncer.synchronize(ctx, settings, true)
	return plan, err
}

// Inventory reads the controller without touching any zone. The wizard uses it
// to test the connection and to list the networks available for mapping.
func (syncer *unifiSyncer) Inventory(ctx context.Context, settings config.UniFi) (unifi.Inventory, error) {
	credentials, found := unifi.Credentials{}, false
	if syncer.credentials != nil {
		credentials, found = syncer.credentials.Get(ctx)
	}
	if !found || !credentials.Configured() {
		return unifi.Inventory{}, errors.New("UniFi controller credentials are not configured")
	}
	reader, err := syncer.newReader(unifi.Options{
		ControllerURL:      settings.ControllerURL,
		Site:               settings.Site,
		Credentials:        credentials,
		CAFile:             settings.CAFile,
		InsecureSkipVerify: settings.Insecure,
	})
	if err != nil {
		return unifi.Inventory{}, err
	}
	return reader.Inventory(ctx)
}

// PutCredentials seals new controller credentials in the vault, replacing
// whatever was stored so switching authentication modes cannot leave a stale
// password behind.
func (syncer *unifiSyncer) PutCredentials(ctx context.Context, credentials unifi.Credentials) error {
	if syncer.credentials == nil {
		return errors.New("secret vault is unavailable")
	}
	return syncer.credentials.Replace(ctx, credentials)
}

// ForgetCredentials retires the stored controller credentials so removing the
// integration leaves no secret behind.
func (syncer *unifiSyncer) ForgetCredentials(ctx context.Context) error {
	if syncer.credentials == nil {
		return errors.New("secret vault is unavailable")
	}
	syncer.mu.Lock()
	syncer.status = unifi.Status{}
	syncer.mu.Unlock()
	return syncer.credentials.Clear(ctx)
}

// StoredCredentials reports the saved credentials so the console can prefill
// the non-secret parts of the connection form.
func (syncer *unifiSyncer) StoredCredentials(ctx context.Context) (unifi.Credentials, bool) {
	if syncer.credentials == nil {
		return unifi.Credentials{}, false
	}
	return syncer.credentials.Get(ctx)
}

func (syncer *unifiSyncer) beginAttempt(started time.Time) {
	syncer.mu.Lock()
	defer syncer.mu.Unlock()
	syncer.status.Running = true
	syncer.status.LastAttempt = started
}

func (syncer *unifiSyncer) finishAttempt(started time.Time, interval time.Duration, plan unifi.Plan, hosts int, err error) {
	syncer.mu.Lock()
	defer syncer.mu.Unlock()
	syncer.status.Running = false
	syncer.status.Duration = syncer.now().Sub(started)
	syncer.status.NextAttempt = syncer.now().Add(interval)
	if err != nil {
		syncer.status.LastError = err.Error()
		return
	}
	syncer.status.LastError = ""
	syncer.status.LastSuccess = started
	syncer.status.Hosts = hosts
	syncer.status.ZonesCreated = len(plan.CreatedZones)
	syncer.status.Added = len(plan.Added)
	syncer.status.Updated = len(plan.Updated)
	syncer.status.Removed = len(plan.Removed)
}

// synchronize reads the controller and reconciles the mapped zones. In preview
// mode it computes the same plan against the current snapshot without writing.
func (syncer *unifiSyncer) synchronize(ctx context.Context, settings config.UniFi, preview bool) (unifi.Plan, int, error) {
	credentials, found := unifi.Credentials{}, false
	if syncer.credentials != nil {
		credentials, found = syncer.credentials.Get(ctx)
	}
	if !found || !credentials.Configured() {
		return unifi.Plan{}, 0, errors.New("UniFi controller credentials are not configured")
	}
	reader, err := syncer.newReader(unifi.Options{
		ControllerURL:      settings.ControllerURL,
		Site:               settings.Site,
		Credentials:        credentials,
		CAFile:             settings.CAFile,
		InsecureSkipVerify: settings.Insecure,
	})
	if err != nil {
		return unifi.Plan{}, 0, err
	}
	inventory, err := reader.Inventory(ctx)
	if err != nil {
		return unifi.Plan{}, 0, err
	}
	desired, skipped, err := desiredUniFiRecords(settings, inventory)
	if err != nil {
		return unifi.Plan{}, 0, err
	}
	if preview {
		zones := syncer.zones.Current().Zones
		plan := planUniFiZones(&zones, desired, syncer.now())
		plan.Skipped = skipped
		plan.Hosts = len(inventory.Hosts)
		return plan, len(inventory.Hosts), nil
	}
	var plan unifi.Plan
	err = syncer.zones.UpdateZones(ctx, func(zones *[]zone.Zone) error {
		plan = planUniFiZones(zones, desired, syncer.now())
		return nil
	})
	if err != nil {
		return unifi.Plan{}, 0, err
	}
	plan.Skipped = skipped
	plan.Hosts = len(inventory.Hosts)
	return plan, len(inventory.Hosts), nil
}

// desiredZone collects the records one zone should hold after a sync.
type desiredZone struct {
	name    string
	ttl     uint32
	records []zone.Record
}

// desiredUniFiRecords turns the controller inventory into the record set each
// mapped zone should contain. Skipped entries are reported so the console can
// explain a device that produced no record.
func desiredUniFiRecords(settings config.UniFi, inventory unifi.Inventory) (map[string]*desiredZone, []string, error) {
	zones := make(map[string]*desiredZone)
	var skipped []string
	ensure := func(name string, ttl uint32) *desiredZone {
		existing, found := zones[name]
		if !found {
			existing = &desiredZone{name: name, ttl: ttl}
			zones[name] = existing
		}
		return existing
	}
	hostsByNetwork := make(map[string][]unifi.Host, len(inventory.Networks))
	for _, host := range inventory.Hosts {
		hostsByNetwork[host.NetworkID] = append(hostsByNetwork[host.NetworkID], host)
	}
	for _, mapping := range settings.ActiveNetworks() {
		template, err := unifi.ParseTemplate(mapping.HostnameTemplate)
		if err != nil {
			return nil, nil, fmt.Errorf("network %s: %w", mapping.DisplayName(), err)
		}
		network, known := inventory.NetworkByID(mapping.ID)
		if !known {
			skipped = append(skipped, fmt.Sprintf("network %s is mapped but the controller no longer reports it", mapping.DisplayName()))
			continue
		}
		forward := ensure(mapping.Zone, mapping.TTL)
		reverseZones := make(map[netip.Prefix]string)
		if mapping.Reverse {
			for _, subnet := range network.Subnets {
				name, err := dnsname.ReverseZone(subnet)
				if err != nil {
					skipped = append(skipped, fmt.Sprintf("subnet %s has no reverse zone: %v", subnet, err))
					continue
				}
				reverseZones[subnet] = name
				ensure(name, mapping.TTL)
			}
		}
		for _, host := range hostsByNetwork[mapping.ID] {
			if host.Reserved && !settings.SyncsReservations() {
				continue
			}
			if !host.Reserved && !settings.SyncsActiveClients() {
				continue
			}
			fqdn, err := template.Render(host.Hostname, network.Name, mapping.Zone)
			if err != nil {
				skipped = append(skipped, fmt.Sprintf("%s (%s): %v", host.Hostname, host.Address, err))
				continue
			}
			recordType := "A"
			if host.Address.Is6() {
				recordType = "AAAA"
			}
			forward.records = append(forward.records, zone.Record{
				Name: unifi.RelativeOwner(fqdn, mapping.Zone), Type: recordType,
				Value: host.Address.String(), TTL: mapping.TTL, Source: zone.SourceUniFi,
			})
			if !mapping.Reverse {
				continue
			}
			reverseZoneName, ok := reverseZoneFor(reverseZones, host.Address)
			if !ok {
				continue
			}
			reverseName, err := dnsname.ReverseName(host.Address)
			if err != nil {
				skipped = append(skipped, fmt.Sprintf("%s (%s): %v", host.Hostname, host.Address, err))
				continue
			}
			zones[reverseZoneName].records = append(zones[reverseZoneName].records, zone.Record{
				Name: unifi.RelativeOwner(reverseName, reverseZoneName), Type: "PTR",
				Value: fqdn + ".", TTL: mapping.TTL, Source: zone.SourceUniFi,
			})
		}
	}
	for _, entry := range zones {
		entry.records = dedupeUniFiRecords(entry.records)
	}
	sort.Strings(skipped)
	return zones, skipped, nil
}

// reverseZoneFor finds the reverse zone covering an address, preferring the
// most specific subnet when a network carries several.
func reverseZoneFor(zones map[netip.Prefix]string, address netip.Addr) (string, bool) {
	best, bestBits, found := "", -1, false
	for subnet, name := range zones {
		if subnet.Contains(address) && subnet.Bits() > bestBits {
			best, bestBits, found = name, subnet.Bits(), true
		}
	}
	return best, found
}

// dedupeUniFiRecords drops exact duplicates and keeps one address per owner and
// type, so two devices claiming the same name cannot produce a round-robin the
// operator never asked for. Sorting first makes the winner deterministic.
func dedupeUniFiRecords(records []zone.Record) []zone.Record {
	slices.SortFunc(records, func(left, right zone.Record) int {
		if compared := strings.Compare(left.Name, right.Name); compared != 0 {
			return compared
		}
		if compared := strings.Compare(left.Type, right.Type); compared != 0 {
			return compared
		}
		return strings.Compare(left.Value, right.Value)
	})
	result := make([]zone.Record, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		key := record.Name + "\x00" + record.Type
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, record)
	}
	return result
}

// planUniFiZones applies the desired record sets to the zone list and reports
// what changed. Records the synchronizer does not own are never touched, so a
// hand-authored record in a mapped zone survives every sync.
func planUniFiZones(zones *[]zone.Zone, desired map[string]*desiredZone, now time.Time) unifi.Plan {
	var plan unifi.Plan
	names := make([]string, 0, len(desired))
	for name := range desired {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := desired[name]
		index := slices.IndexFunc(*zones, func(candidate zone.Zone) bool { return candidate.Name == name })
		if index < 0 {
			created, err := zone.NewPrimary(name, entry.ttl, "", "", now)
			if err != nil {
				plan.Skipped = append(plan.Skipped, fmt.Sprintf("zone %s could not be created: %v", name, err))
				continue
			}
			*zones = append(*zones, created)
			index = len(*zones) - 1
			plan.CreatedZones = append(plan.CreatedZones, name)
		}
		target := &(*zones)[index]
		// Only primary zones hold locally authored records. A mapping pointed
		// at a secondary or forwarder zone is a configuration mistake, not a
		// reason to corrupt a synchronized copy.
		if target.Type != "primary" {
			plan.Skipped = append(plan.Skipped, fmt.Sprintf("zone %s is a %s zone and cannot hold synchronized records", name, target.Type))
			continue
		}
		for _, record := range entry.records {
			plan.Publishing = append(plan.Publishing, planRecord(name, record))
		}
		if applyUniFiRecords(target, entry.records, &plan) {
			zone.AdvanceSerial(target, now)
		}
	}
	return plan
}

// applyUniFiRecords replaces the synchronizer-owned records in one zone and
// reports whether anything changed.
func applyUniFiRecords(target *zone.Zone, desired []zone.Record, plan *unifi.Plan) bool {
	existing := make(map[string]zone.Record)
	retained := make([]zone.Record, 0, len(target.Records))
	for _, record := range target.Records {
		if record.Source != zone.SourceUniFi {
			retained = append(retained, record)
			continue
		}
		existing[record.Name+"\x00"+record.Type] = record
	}
	changed := false
	for _, record := range desired {
		key := record.Name + "\x00" + record.Type
		previous, found := existing[key]
		switch {
		case !found:
			plan.Added = append(plan.Added, planRecord(target.Name, record))
			changed = true
		case previous.Value != record.Value || previous.TTL != record.TTL:
			plan.Updated = append(plan.Updated, planRecord(target.Name, record))
			changed = true
		}
		delete(existing, key)
	}
	removed := make([]unifi.PlanRecord, 0, len(existing))
	for _, record := range existing {
		removed = append(removed, planRecord(target.Name, record))
		changed = true
	}
	slices.SortFunc(removed, compareUniFiPlanRecords)
	plan.Removed = append(plan.Removed, removed...)
	if !changed {
		return false
	}
	target.Records = append(retained, desired...)
	return true
}

func planRecord(zoneName string, record zone.Record) unifi.PlanRecord {
	return unifi.PlanRecord{Zone: zoneName, Name: record.Name, Type: record.Type, Value: record.Value}
}

func compareUniFiPlanRecords(left, right unifi.PlanRecord) int {
	if compared := strings.Compare(left.Zone, right.Zone); compared != 0 {
		return compared
	}
	if compared := strings.Compare(left.Name, right.Name); compared != 0 {
		return compared
	}
	if compared := strings.Compare(left.Type, right.Type); compared != 0 {
		return compared
	}
	return strings.Compare(left.Value, right.Value)
}
