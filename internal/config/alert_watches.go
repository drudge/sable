package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/drudge/sable/internal/dnsname"
)

// What a watch alerts on.
const (
	// AlertWatchAny alerts whether the lookup was allowed or blocked. It is
	// the default, so it is written as no result at all.
	AlertWatchAny = "any"
	// AlertWatchAllowed alerts only on lookups that were answered.
	AlertWatchAllowed = "allowed"
	// AlertWatchBlocked alerts only on lookups that blocking stopped.
	AlertWatchBlocked = "blocked"
)

// Limits on watches. Every node checks each new query log row against every
// watched domain once a minute, so the lists stay small enough to keep that
// cheap.
const (
	MaximumAlertWatches       = 50
	MaximumAlertWatchDomains  = 100
	MaximumAlertWatchDevices  = 50
	MaximumAlertWatchName     = 64
	DefaultAlertWatchQuiet    = time.Hour
	MinimumAlertWatchQuiet    = time.Minute
	MaximumAlertWatchQuiet    = 24 * time.Hour
	alertWatchIDDerivedLength = 16
	alertWatchDevicePrefixMAC = "mac:"
	alertWatchDevicePrefixIP  = "ip:"
)

// AlertWatch alerts when a device looks up one of its domains, or a name
// under one.
type AlertWatch struct {
	// ID names the watch in its alerts. It never changes, however the watch
	// is renamed.
	ID   string `toml:"id"`
	Name string `toml:"name,omitempty"`
	// Domains are matched with every name under them, as blocking rules are.
	Domains []string `toml:"domains"`
	// Devices limits the watch to some devices. Each is an Insights device
	// key ("mac:aa:bb:cc:dd:ee:ff" or "ip:10.0.7.20"), an address, or a
	// network such as 10.0.7.0/24. Empty means any device.
	Devices []string `toml:"devices,omitempty"`
	// Result is "any", "allowed", or "blocked".
	Result string `toml:"result,omitempty"`
	// Quiet is how long a device stays quiet for this watch after it alerts.
	Quiet   Duration `toml:"quiet"`
	Enabled bool     `toml:"enabled"`
}

// Label is what people call the watch: its name, or its first domain.
func (watch AlertWatch) Label() string {
	if watch.Name != "" {
		return watch.Name
	}
	if len(watch.Domains) > 0 {
		return watch.Domains[0]
	}
	return "Watch"
}

// Allows reports whether a lookup's result is one the watch alerts on.
func (watch AlertWatch) Allows(blocked bool) bool {
	switch watch.Result {
	case AlertWatchAllowed:
		return !blocked
	case AlertWatchBlocked:
		return blocked
	default:
		return true
	}
}

// Covers reports whether the watch covers a device, which has the Insights
// key device and looked up from address. A watch with no devices covers
// every one.
func (watch AlertWatch) Covers(device, address string) bool {
	if len(watch.Devices) == 0 {
		return true
	}
	client, err := netip.ParseAddr(address)
	if err != nil {
		return slices.Contains(watch.Devices, device)
	}
	// A link-local client carries the zone it came in on, as in
	// fe80::1%eth0, which a watch written by hand leaves out.
	client = client.Unmap()
	bare := client.WithZone("")
	for _, entry := range watch.Devices {
		entry = strings.TrimPrefix(entry, alertWatchDevicePrefixIP)
		switch {
		case entry == device, entry == client.String(), entry == bare.String():
			return true
		case strings.Contains(entry, "/"):
			if prefix, err := netip.ParsePrefix(entry); err == nil && prefix.Contains(bare) {
				return true
			}
		}
	}
	return false
}

// Normalize tidies a watch as written by hand or in the console: domains in
// the form blocking rules use, devices in one spelling each, and duplicates
// dropped. What cannot be read is kept as written for Validate to name.
func (watch *AlertWatch) Normalize() {
	watch.ID = strings.TrimSpace(watch.ID)
	watch.Name = strings.TrimSpace(watch.Name)
	domains := make([]string, 0, len(watch.Domains))
	for _, domain := range watch.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		if normalized := normalizeDomain(domain); normalized != "" {
			domain = normalized
		}
		if !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	watch.Domains = domains
	devices := make([]string, 0, len(watch.Devices))
	for _, device := range watch.Devices {
		device = NormalizeAlertWatchDevice(device)
		if device != "" && !slices.Contains(devices, device) {
			devices = append(devices, device)
		}
	}
	watch.Devices = devices
	if len(watch.Devices) == 0 {
		watch.Devices = nil
	}
	watch.Result = strings.ToLower(strings.TrimSpace(watch.Result))
	if watch.Result == AlertWatchAny {
		watch.Result = ""
	}
	if watch.Quiet.Duration == 0 {
		watch.Quiet.Duration = DefaultAlertWatchQuiet
	}
	if watch.ID == "" {
		watch.ID = derivedAlertWatchID(*watch)
	}
}

// NormalizeAlertWatchDevice writes a watch's device in one spelling: a device
// key with its address in canonical form, an address unmapped from IPv6, or
// a network by its first address. It returns what it cannot read trimmed,
// and nothing for a blank entry.
func NormalizeAlertWatchDevice(device string) string {
	device = strings.TrimSpace(device)
	lower := strings.ToLower(device)
	switch {
	case device == "":
		return ""
	case strings.HasPrefix(lower, alertWatchDevicePrefixMAC):
		if mac, err := net.ParseMAC(strings.TrimSpace(device[len(alertWatchDevicePrefixMAC):])); err == nil && len(mac) == 6 {
			return alertWatchDevicePrefixMAC + mac.String()
		}
	case strings.HasPrefix(lower, alertWatchDevicePrefixIP):
		if address, err := netip.ParseAddr(strings.TrimSpace(device[len(alertWatchDevicePrefixIP):])); err == nil {
			return alertWatchDevicePrefixIP + address.Unmap().String()
		}
	case strings.Contains(device, "/"):
		if prefix, err := netip.ParsePrefix(device); err == nil {
			// An IPv4 network written as IPv6, as in ::ffff:10.0.7.0/120,
			// is the IPv4 network the query log names its clients by.
			if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			return prefix.Masked().String()
		}
	default:
		if address, err := netip.ParseAddr(device); err == nil {
			return address.Unmap().String()
		}
	}
	return device
}

// validAlertWatchDevice reports whether a normalized device is one a watch
// can match.
func validAlertWatchDevice(device string) bool {
	switch {
	case strings.HasPrefix(device, alertWatchDevicePrefixMAC):
		_, err := net.ParseMAC(device[len(alertWatchDevicePrefixMAC):])
		return err == nil
	case strings.HasPrefix(device, alertWatchDevicePrefixIP):
		_, err := netip.ParseAddr(device[len(alertWatchDevicePrefixIP):])
		return err == nil
	case strings.Contains(device, "/"):
		_, err := netip.ParsePrefix(device)
		return err == nil
	default:
		_, err := netip.ParseAddr(device)
		return err == nil
	}
}

// derivedAlertWatchID names a watch written by hand without an ID by what it
// watches, so it keeps the same ID on every load until Sable writes one back.
func derivedAlertWatchID(watch AlertWatch) string {
	sum := sha256.Sum256([]byte(watch.Name + "\x00" + strings.Join(watch.Domains, "\x00")))
	return hex.EncodeToString(sum[:])[:alertWatchIDDerivedLength]
}

func validateAlertWatches(watches []AlertWatch) error {
	if len(watches) > MaximumAlertWatches {
		return fmt.Errorf("alerts.watches has more than %d watches", MaximumAlertWatches)
	}
	ids := make(map[string]bool, len(watches))
	for index, watch := range watches {
		field := fmt.Sprintf("alerts.watches[%d]", index)
		if !validAlertDestinationID(watch.ID) {
			return fmt.Errorf("%s.id must be 1 to 64 letters, digits, dashes, or underscores", field)
		}
		if ids[watch.ID] {
			return fmt.Errorf("%s.id %q is used by another watch", field, watch.ID)
		}
		ids[watch.ID] = true
		if utf8.RuneCountInString(watch.Name) > MaximumAlertWatchName {
			return fmt.Errorf("%s.name is longer than %d characters", field, MaximumAlertWatchName)
		}
		if len(watch.Domains) == 0 {
			return fmt.Errorf("%s.domains needs at least one domain", field)
		}
		if len(watch.Domains) > MaximumAlertWatchDomains {
			return fmt.Errorf("%s.domains has more than %d domains", field, MaximumAlertWatchDomains)
		}
		for _, domain := range watch.Domains {
			if _, err := dnsname.Normalize(domain); err != nil {
				return fmt.Errorf("%s.domains: %q is not a domain name", field, domain)
			}
		}
		if len(watch.Devices) > MaximumAlertWatchDevices {
			return fmt.Errorf("%s.devices has more than %d devices", field, MaximumAlertWatchDevices)
		}
		for _, device := range watch.Devices {
			if !validAlertWatchDevice(device) {
				return fmt.Errorf("%s.devices: %q is not a device, an address, or a network", field, device)
			}
		}
		switch watch.Result {
		case "", AlertWatchAny, AlertWatchAllowed, AlertWatchBlocked:
		default:
			return fmt.Errorf("%s.result must be %q, %q, or %q", field, AlertWatchAny, AlertWatchAllowed, AlertWatchBlocked)
		}
		if quiet := watch.Quiet.Duration; quiet < MinimumAlertWatchQuiet || quiet > MaximumAlertWatchQuiet {
			return fmt.Errorf("%s.quiet must be between 1 minute and 24 hours", field)
		}
	}
	return nil
}

// ValidateAlertWatch reports whether one watch is sound, as the console checks
// it before saving.
func ValidateAlertWatch(watch AlertWatch) error {
	return validateAlertWatches([]AlertWatch{watch})
}
