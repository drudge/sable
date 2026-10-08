package web

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights/devices"
)

// holdService blocks everything for a device for a while, or until the
// hold is ended, for every caller. Holds are blocking configuration, so they
// need blocking.write, reach every node, and show in the Change Center.
type holdService struct{ server *Server }

func (server *Server) holdService() holdService { return holdService{server} }

// maximumHoldMinutes bounds a hold given in minutes to a week; longer ones
// can be held until turned off.
const maximumHoldMinutes = 7 * 24 * 60

type holdChange struct {
	Device  string `json:"device"`
	Held    bool   `json:"held"`
	Until   string `json:"until,omitempty"`
	Changed bool   `json:"changed"`
	Message string `json:"message"`
}

// Hold blocks everything but its allowed domains for device until until, or
// until the hold is ended when until is zero. It replaces any hold the
// device already has.
func (service holdService) Hold(ctx context.Context, who actor, device config.Client, until time.Time) (holdChange, error) {
	policy := service.server.policyService()
	if err := policy.ready(who); err != nil {
		return holdChange{}, err
	}
	if device.MAC != "" && !service.tracking() {
		return holdChange{}, refuse(http.StatusUnprocessableEntity, "with Insights off, Sable can only block a device by its IP address or network")
	}
	now := time.Now()
	if _, err := config.SetHold(nil, device, until, now); err != nil {
		return holdChange{}, refuse(http.StatusUnprocessableEntity, "%v", err)
	}
	action := "blocking.hold.set"
	err := policy.update(ctx, who, action, func(blocking *config.Blocking) {
		// Checked above, so this can't fail on the device or the time.
		blocking.Holds, _ = config.SetHold(blocking.Holds, device, until, now)
	}, "device", device.Key())
	if err != nil {
		return holdChange{}, err
	}
	change := holdChange{Device: deviceKeyIdentifier(device.Key()), Held: true, Changed: true}
	change.Message = "Everything but allowed domains is blocked for " + change.Device + " until it is turned off"
	if !until.IsZero() {
		change.Until = until.Format(time.RFC3339)
		change.Message = "Everything but allowed domains is blocked for " + change.Device + " until " + change.Until
	}
	policy.finish(ctx, who, action, "", change.Message)
	return change, nil
}

// End lifts a device's hold, if it has one.
func (service holdService) End(ctx context.Context, who actor, device config.Client) (holdChange, error) {
	policy := service.server.policyService()
	if err := policy.ready(who); err != nil {
		return holdChange{}, err
	}
	now := time.Now()
	change := holdChange{Device: deviceKeyIdentifier(device.Key())}
	if _, held := config.HoldFor(service.server.config.Current().Config.Blocking.Holds, device, now); !held {
		change.Message = change.Device + " has no hold"
		return change, nil
	}
	action := "blocking.hold.end"
	err := policy.update(ctx, who, action, func(blocking *config.Blocking) {
		blocking.Holds, change.Changed = config.EndHold(blocking.Holds, device, now)
	}, "device", device.Key())
	if err != nil {
		return holdChange{}, err
	}
	change.Message = change.Device + " has no hold"
	if change.Changed {
		change.Message = "Blocking for " + change.Device + " is back to normal"
		policy.finish(ctx, who, action, "", change.Message)
	}
	return change, nil
}

// Device finds the device a caller means: a hardware address, the name of a
// device in the configuration, or an IP address or network. An address
// Sable has tied to a device's hardware address names that device, so the
// hold follows it to its other addresses.
func (service holdService) Device(ctx context.Context, value string) (config.Client, error) {
	value = strings.TrimSpace(value)
	if mac, err := net.ParseMAC(value); err == nil {
		return config.Client{MAC: mac.String()}, nil
	}
	clients := service.server.config.Current().Config.Clients
	for _, client := range clients {
		if client.Name != "" && strings.EqualFold(client.Name, value) {
			return config.Client{MAC: client.MAC, Address: client.Address}, nil
		}
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return config.Client{Address: value}, nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return config.Client{}, refuse(http.StatusUnprocessableEntity, "%q is not a hardware address, IP address, network, or device name Sable knows", value)
	}
	address = address.Unmap().WithZone("")
	// With Insights off, Sable ties no addresses to hardware, so a hold by
	// hardware address would never match.
	if reader, ok := service.server.queries.(clientIdentityReader); ok && service.tracking() {
		identities, err := reader.ClientIdentities(ctx, time.Now().Add(-devices.Lookback))
		if err != nil {
			return config.Client{}, err
		}
		// Newest first, so the device using the address now wins.
		for _, identity := range identities {
			if candidate, err := netip.ParseAddr(identity.Address); err == nil && candidate.Unmap().WithZone("") == address {
				if mac, err := net.ParseMAC(identity.MAC); err == nil {
					return config.Client{MAC: mac.String()}, nil
				}
				break
			}
		}
	}
	return config.Client{Address: address.String()}, nil
}

func (service holdService) tracking() bool {
	tracker, ok := service.server.queries.(interface{ ClientTracking() bool })
	return ok && tracker.ClientTracking()
}
