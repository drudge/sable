package dhcpimport

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/drudge/sable/internal/unifi"
)

// export holds every JSON shape Parse knows; whichever list is present
// names the format.
type export struct {
	// AdGuard Home's data/leases.json.
	Leases []adGuardLease `json:"leases"`
	// AdGuard Home's GET /control/dhcp/status.
	StaticLeases []adGuardLease `json:"static_leases"`
	// Technitium's GET /api/dhcp/scopes/get, whole or its response.
	Response       *export           `json:"response"`
	ReservedLeases []technitiumLease `json:"reservedLeases"`
	// A UniFi controller's api/s/{site}/rest/user.
	Data []unifiUser `json:"data"`
}

type adGuardLease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Static   *bool  `json:"static"`
}

type technitiumLease struct {
	HostName        string `json:"hostName"`
	HardwareAddress string `json:"hardwareAddress"`
	Address         string `json:"address"`
	Comments        string `json:"comments"`
}

type unifiUser struct {
	MAC        string `json:"mac"`
	Name       string `json:"name"`
	Hostname   string `json:"hostname"`
	Note       string `json:"note"`
	UseFixedIP bool   `json:"use_fixedip"`
	FixedIP    string `json:"fixed_ip"`
}

func parseJSON(data []byte) (Result, error) {
	var document export
	if err := json.Unmarshal(data, &document); err != nil {
		return Result{}, fmt.Errorf("the file isn't an export Sable reads: %w", err)
	}
	if document.Response != nil {
		document = *document.Response
	}
	switch {
	case document.StaticLeases != nil:
		return adGuardResult(document.StaticLeases), nil
	case document.Leases != nil:
		return adGuardResult(document.Leases), nil
	case document.ReservedLeases != nil:
		return technitiumResult(document.ReservedLeases), nil
	case document.Data != nil:
		return unifiResult(document.Data), nil
	}
	return Result{}, errors.New("the JSON isn't an AdGuard Home, Technitium, or UniFi export")
}

// adGuardResult keeps static leases. leases.json marks them static, and the
// status endpoint's static_leases carries no flag at all.
func adGuardResult(leases []adGuardLease) Result {
	result := Result{Format: FormatAdGuard}
	for index, lease := range leases {
		if lease.Static != nil && !*lease.Static {
			continue
		}
		result.add(index+1, lease.MAC, lease.IP, lease.Hostname, "")
	}
	return result
}

func technitiumResult(leases []technitiumLease) Result {
	result := Result{Format: FormatTechnitium}
	for index, lease := range leases {
		result.add(index+1, lease.HardwareAddress, lease.Address, lease.HostName, lease.Comments)
	}
	return result
}

// unifiResult keeps the clients with a fixed address, named the way Sable's
// UniFi sync names them (unifi.SanitizeLabel on the alias the operator gave
// the client in the controller, then the host name it sent), so a device
// keeps its name in DNS when its reservation moves to Sable.
func unifiResult(users []unifiUser) Result {
	result := Result{Format: FormatUniFi}
	for index, user := range users {
		if !user.UseFixedIP {
			continue
		}
		name := unifi.SanitizeLabel(user.Name)
		if name == "" {
			name = user.Hostname
		}
		result.add(index+1, user.MAC, user.FixedIP, name, user.Note)
	}
	return result
}
