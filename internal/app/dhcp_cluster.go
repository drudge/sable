package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/version"
)

// dhcpRoleJoining is dhcpClusterRole while a join applies the primary's
// state: the primary's [dhcp] is held, not served, until the join completes
// (F30).
const dhcpRoleJoining = "joining"

// errDHCPRangeUnpinned refuses a range without a node on a cluster: every
// node would lease from it at once.
var errDHCPRangeUnpinned = errors.New("set node on every DHCP range of a cluster, so one node leases each address")

// checkDHCPCluster refuses DHCP settings the cluster can't serve safely. On
// a cluster every range names a current member, so each address has one
// allocator and a partition can't lease it twice (design §3), and no member
// runs a release older than this node's, which may refuse the [dhcp] section
// the snapshot carries (config is strict TOML). Outside a cluster a range may
// name only this node.
func checkDHCPCluster(settings config.DHCP, state cluster.State, release string) error {
	if !state.Initialized {
		var self []string
		if state.NodeID != "" {
			self = []string{state.NodeID}
		}
		return settings.ValidateNodes(self)
	}
	members := make([]string, 0, len(state.Nodes))
	var older []string
	for _, node := range state.Nodes {
		members = append(members, node.ID)
		if version.Older(node.Version, release) {
			older = append(older, fmt.Sprintf("%s (%s)", node.Name, strings.TrimPrefix(node.Version, "v")))
		}
	}
	if err := settings.ValidateNodes(members); err != nil {
		return err
	}
	if err := dhcpRangesPinned(settings); err != nil {
		return err
	}
	if len(older) > 0 {
		return fmt.Errorf("update %s to Sable %s or later before serving DHCP on this cluster",
			strings.Join(older, ", "), strings.TrimPrefix(release, "v"))
	}
	return nil
}

// dhcpRangesPinned refuses a range without a node (errDHCPRangeUnpinned).
func dhcpRangesPinned(settings config.DHCP) error {
	for scopeIndex, scope := range settings.Scopes {
		for rangeIndex, pool := range scope.Ranges {
			if pool.Node == "" {
				return fmt.Errorf("dhcp.scopes[%d].ranges[%d]: %w", scopeIndex, rangeIndex, errDHCPRangeUnpinned)
			}
		}
	}
	return nil
}

// dhcpNodeSettings is what a node serves of settings. On a cluster a range
// without a node is left out, so a replica that holds settings its primary
// refused (checkDHCPCluster) never leases from it beside the other nodes.
func dhcpNodeSettings(settings config.DHCP, clustered bool) config.DHCP {
	if !clustered {
		return settings
	}
	settings.Scopes = slices.Clone(settings.Scopes)
	for index, scope := range settings.Scopes {
		settings.Scopes[index].Ranges = slices.DeleteFunc(slices.Clone(scope.Ranges),
			func(pool config.DHCPRange) bool { return pool.Node == "" })
	}
	return settings
}

// dhcpServesAnything reports whether node has something to answer in
// settings: a serving scope with a range pinned to it or unpinned, or with
// reservations, which every node serving the scope answers (design §3).
func dhcpServesAnything(settings config.DHCP, node string) bool {
	for _, scope := range settings.Scopes {
		if !scope.Serves() {
			continue
		}
		if len(scope.Reservations) > 0 || slices.ContainsFunc(scope.Ranges,
			func(pool config.DHCPRange) bool { return pool.Node == "" || pool.Node == node }) {
			return true
		}
	}
	return false
}

// errClusterWithDHCP refuses creating or joining a cluster while this node
// serves DHCP (D31). A node that became a cluster at runtime would keep
// serving its unpinned ranges beside the other nodes until its next start.
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
