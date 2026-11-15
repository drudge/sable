package app

import (
	"context"
	"errors"
	"reflect"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
)

// errClusterWithDHCP refuses creating or joining a cluster while this node
// serves DHCP (D31). Until slice 8 pins ranges to nodes, a node that became a
// cluster at runtime would keep serving and then drop DHCP at its next start.
var errClusterWithDHCP = errors.New("turn off DHCP before creating or joining a cluster")

// dhcpClusterGuard is the cluster service the console and API use. It
// refuses Initialize and Join while dhcpEnabled reports [dhcp] enabled.
type dhcpClusterGuard struct {
	*cluster.Service
	dhcpEnabled func() bool
}

// Initialize creates a cluster unless this node serves DHCP.
func (guard dhcpClusterGuard) Initialize(ctx context.Context, domain string, addresses []string) error {
	if guard.dhcpEnabled() {
		return errClusterWithDHCP
	}
	return guard.Service.Initialize(ctx, domain, addresses)
}

// Join joins a cluster unless this node serves DHCP.
func (guard dhcpClusterGuard) Join(ctx context.Context, options cluster.JoinOptions) error {
	if guard.dhcpEnabled() {
		return errClusterWithDHCP
	}
	return guard.Service.Join(ctx, options)
}

// checkDHCP reports whether a reload changes [dhcp] and, if it does, whether
// the service can run the new settings. A reload that leaves [dhcp] alone
// never fails because of DHCP (D30), even where DHCP was refused at start,
// as on a cluster.
func (process *process) checkDHCP(active, candidate config.DHCP) (bool, error) {
	if process.dhcp == nil || reflect.DeepEqual(active, candidate) {
		return false, nil
	}
	return true, process.dhcp.Check(candidate)
}
