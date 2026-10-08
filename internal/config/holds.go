package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Hold blocks everything for one device, the way a router's "pause internet"
// does, except the domains the device is allowed. It names the device as a
// [[clients]] entry does. A zero Until holds until the hold is removed.
type Hold struct {
	MAC     string    `toml:"mac,omitempty"`
	Address string    `toml:"address,omitempty"`
	Until   time.Time `toml:"until,omitempty"`
}

// Key is the identifier a hold is matched and de-duplicated by, the same as
// the device's [[clients]] entry.
func (hold Hold) Key() string { return hold.device().Key() }

func (hold Hold) device() Client { return Client{MAC: hold.MAC, Address: hold.Address} }

// Active reports whether the hold still blocks the device at now.
func (hold Hold) Active(now time.Time) bool { return hold.Until.IsZero() || now.Before(hold.Until) }

func normalizeHolds(holds []Hold) []Hold {
	for index, hold := range holds {
		device := normalizeClient(hold.device())
		holds[index].MAC, holds[index].Address = device.MAC, device.Address
	}
	slices.SortStableFunc(holds, func(left, right Hold) int { return strings.Compare(left.Key(), right.Key()) })
	return holds
}

func validateHolds(holds []Hold) []error {
	var validationErrors []error
	seen := make(map[string]int, len(holds))
	for index, hold := range holds {
		field := fmt.Sprintf("blocking.holds[%d]", index)
		if err := validateDevice(field, hold.MAC, hold.Address); err != nil {
			validationErrors = append(validationErrors, err)
			continue
		}
		if previous, taken := seen[hold.Key()]; taken {
			validationErrors = append(validationErrors, fmt.Errorf("%s holds the same device as blocking.holds[%d]", field, previous))
		}
		seen[hold.Key()] = index
	}
	return validationErrors
}

// SetHold blocks everything for a device until until, or until the hold is
// removed when until is zero, replacing any hold it already had. Holds that
// have ended are dropped along the way, so they don't pile up.
func SetHold(holds []Hold, device Client, until time.Time, now time.Time) ([]Hold, error) {
	device = normalizeClient(device)
	if err := validateDevice("device", device.MAC, device.Address); err != nil {
		return nil, err
	}
	if !until.IsZero() && !now.Before(until) {
		return nil, errors.New("a hold must end in the future")
	}
	updated, _ := EndHold(holds, device, now)
	return append(updated, Hold{MAC: device.MAC, Address: device.Address, Until: until}), nil
}

// EndHold removes a device's hold, and any holds that have already ended. It
// reports whether the device had a hold that was still active.
func EndHold(holds []Hold, device Client, now time.Time) ([]Hold, bool) {
	key := normalizeClient(device).Key()
	ended := false
	updated := slices.DeleteFunc(slices.Clone(holds), func(hold Hold) bool {
		if normalizeClient(hold.device()).Key() == key {
			ended = ended || hold.Active(now)
			return true
		}
		return !hold.Active(now)
	})
	return updated, ended
}

// HoldFor returns a device's hold, if it has one that is still active.
func HoldFor(holds []Hold, device Client, now time.Time) (Hold, bool) {
	key := normalizeClient(device).Key()
	for _, hold := range holds {
		if normalizeClient(hold.device()).Key() == key && hold.Active(now) {
			return hold, true
		}
	}
	return Hold{}, false
}
