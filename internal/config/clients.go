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

// Client is what an operator told Sable about one device on the network: its
// name, what kind of device it is, or both. Sable uses these ahead of every
// name it discovers and every type it guesses. A device is identified by its
// hardware address when Sable has seen one, which survives address changes,
// or by an address or network otherwise.
type Client struct {
	Name string `toml:"name,omitempty"`
	MAC  string `toml:"mac,omitempty"`
	// Address is one IP address or a CIDR network such as a guest VLAN.
	Address string `toml:"address,omitempty"`
	// Type is one of ClientTypes, set when the operator corrected Sable's guess.
	Type string `toml:"type,omitempty"`
}

// ClientTypes are the kinds of device Sable recognizes, as stored in a
// client's type.
var ClientTypes = []string{
	"phone", "tablet", "computer", "server", "tv", "streaming-player", "smart-speaker", "speaker",
	"camera", "doorbell", "game-console", "printer", "storage", "network", "thermostat", "lighting",
	"smart-plug", "smart-home", "watch",
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
	if name == "" && client.Type == "" {
		return fmt.Errorf("%s.name or %s.type is required", field, field)
	}
	if client.Type != "" && !slices.Contains(ClientTypes, client.Type) {
		return fmt.Errorf("%s.type must be one of %s", field, strings.Join(ClientTypes, ", "))
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
	client.Type = strings.TrimSpace(client.Type)
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

// SetClientName names a device, replacing any name it already had and keeping
// its type. An empty name removes the name, and the entry with it when no type
// is left. For a device named by hardware address, addresses lists the client
// addresses it uses, and any name kept on one of them is cleared: Sable only
// names an address until it knows the hardware behind it, and a name left
// there would come back once this one is removed.
func SetClientName(clients []Client, named Client, addresses ...string) ([]Client, error) {
	return updateClient(clients, named, addresses, strings.TrimSpace(named.Name), func(client *Client, name string) { client.Name = name })
}

// SetClientType records what kind of device a device is, keeping its name. An
// empty type returns the device to Sable's own guess. addresses clears the
// types kept on a device's addresses the way SetClientName clears names.
func SetClientType(clients []Client, typed Client, addresses ...string) ([]Client, error) {
	return updateClient(clients, typed, addresses, strings.TrimSpace(typed.Type), func(client *Client, kind string) { client.Type = kind })
}

// updateClient sets one field of the entry for a device. A device known by
// hardware address takes the field over from the entries of its addresses.
func updateClient(clients []Client, target Client, addresses []string, value string, set func(*Client, string)) ([]Client, error) {
	target = normalizeClient(target)
	if target.MAC == "" && target.Address == "" {
		return nil, errors.New("a device needs a hardware address or an IP address")
	}
	updated := clients
	if target.MAC != "" {
		for _, address := range addresses {
			// Only an exact address stood in for the hardware; a network names
			// every device on it.
			if _, err := netip.ParseAddr(address); err != nil {
				continue
			}
			var err error
			if updated, err = changeClient(updated, Client{Address: address}, func(client *Client) { set(client, "") }); err != nil {
				return nil, err
			}
		}
	}
	return changeClient(updated, target, func(client *Client) { set(client, value) })
}

// changeClient changes the entry for one device, creating it when needed and
// dropping it when nothing is left to say about the device.
func changeClient(clients []Client, target Client, change func(*Client)) ([]Client, error) {
	target = normalizeClient(target)
	entry := Client{MAC: target.MAC, Address: target.Address}
	updated := slices.DeleteFunc(slices.Clone(clients), func(client Client) bool {
		if normalizeClient(client).Key() != target.Key() {
			return false
		}
		entry = normalizeClient(client)
		return true
	})
	change(&entry)
	if entry.Name == "" && entry.Type == "" {
		return updated, nil
	}
	if err := validateClient("client", entry); err != nil {
		return nil, err
	}
	return append(updated, entry), nil
}
