package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"unicode"
)

// maximumClientNameLength bounds a device name so it fits the console's
// tables and drawers.
const maximumClientNameLength = 64

// Client is a name an operator gave one device on the network. Sable uses it
// ahead of every name it discovers. A device is identified by its hardware
// address when Sable has seen one, which survives address changes, or by an
// address or network otherwise.
type Client struct {
	Name string `toml:"name"`
	MAC  string `toml:"mac,omitempty"`
	// Address is one IP address or a CIDR network such as a guest VLAN.
	Address string `toml:"address,omitempty"`
}

// Key is the identifier a client is matched and de-duplicated by.
func (client Client) Key() string {
	if client.MAC != "" {
		return "mac:" + client.MAC
	}
	return "address:" + client.Address
}

func validateClient(field string, client Client) error {
	name := strings.TrimSpace(client.Name)
	if name == "" {
		return fmt.Errorf("%s.name is required", field)
	}
	if len([]rune(name)) > maximumClientNameLength {
		return fmt.Errorf("%s.name must be at most %d characters", field, maximumClientNameLength)
	}
	if strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s.name must not contain control characters", field)
	}
	switch {
	case client.MAC != "" && client.Address != "":
		return fmt.Errorf("%s must set mac or address, not both", field)
	case client.MAC != "":
		if _, err := net.ParseMAC(client.MAC); err != nil {
			return fmt.Errorf("%s.mac must be a hardware address", field)
		}
	case client.Address != "":
		if _, err := netip.ParsePrefix(client.Address); err != nil {
			if _, err := netip.ParseAddr(client.Address); err != nil {
				return fmt.Errorf("%s.address must be an IP address or CIDR network", field)
			}
		}
	default:
		return fmt.Errorf("%s must set mac or address", field)
	}
	return nil
}

func validateClients(clients []Client) error {
	errs := make([]error, 0)
	seen := make(map[string]int, len(clients))
	for index, client := range clients {
		field := fmt.Sprintf("clients[%d]", index)
		if err := validateClient(field, client); err != nil {
			errs = append(errs, err)
			continue
		}
		if previous, taken := seen[client.Key()]; taken {
			errs = append(errs, fmt.Errorf("%s names the same device as clients[%d]", field, previous))
		}
		seen[client.Key()] = index
	}
	return errors.Join(errs...)
}

// normalizeClient puts a client's identifier in canonical form: a lower-case
// colon-separated hardware address, or a canonical address or masked network.
func normalizeClient(client Client) Client {
	client.Name = strings.TrimSpace(client.Name)
	client.MAC = strings.TrimSpace(client.MAC)
	client.Address = strings.TrimSpace(client.Address)
	if mac, err := net.ParseMAC(client.MAC); err == nil {
		client.MAC = mac.String()
	}
	if prefix, err := netip.ParsePrefix(client.Address); err == nil {
		client.Address = prefix.Masked().String()
	} else if address, err := netip.ParseAddr(client.Address); err == nil {
		client.Address = address.Unmap().WithZone("").String()
	}
	return client
}

func (configuration *Config) normalizeClients() {
	for index := range configuration.Clients {
		configuration.Clients[index] = normalizeClient(configuration.Clients[index])
	}
	slices.SortStableFunc(configuration.Clients, func(left, right Client) int {
		return strings.Compare(left.Key(), right.Key())
	})
}

// SetClientName names a device, replacing any name it already had. An empty
// name removes the device's entry.
func SetClientName(clients []Client, named Client) ([]Client, error) {
	named = normalizeClient(named)
	updated := slices.DeleteFunc(slices.Clone(clients), func(client Client) bool {
		return normalizeClient(client).Key() == named.Key()
	})
	if named.Name == "" {
		if named.MAC == "" && named.Address == "" {
			return nil, errors.New("a device needs a hardware address or an IP address")
		}
		return updated, nil
	}
	if err := validateClient("client", named); err != nil {
		return nil, err
	}
	return append(updated, named), nil
}
