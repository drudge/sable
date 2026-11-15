package web

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/cluster"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
)

// clusterNodes are the members of this node's cluster; none outside one.
func (service dhcpService) clusterNodes() []cluster.Node {
	if service.server.cluster == nil {
		return nil
	}
	state := service.server.cluster.Snapshot()
	if !state.Initialized {
		return nil
	}
	return state.Nodes
}

// TakeOverRanges pins every range pinned to from to the node to, and reports
// how many moved (design §3: range takeover). Whether from may be taken over
// is the caller's to check (dhcpTakeover). Like SetScope it needs
// settings.write.
func (service dhcpService) TakeOverRanges(ctx context.Context, who actor, from cluster.Node, to string) (int, error) {
	if err := service.allowed(who, auth.PermissionSettingsWrite); err != nil {
		return 0, err
	}
	moved := 0
	err := service.update(ctx, who, "dhcp.takeover", "took over the DHCP ranges of "+from.Name, func(settings *config.DHCP) error {
		moved = 0
		for scopeIndex := range settings.Scopes {
			for rangeIndex := range settings.Scopes[scopeIndex].Ranges {
				if pool := &settings.Scopes[scopeIndex].Ranges[rangeIndex]; pool.Node == from.ID {
					pool.Node = to
					moved++
				}
			}
		}
		if moved == 0 {
			return refuse(http.StatusUnprocessableEntity, "%s has no DHCP ranges to take over", from.Name)
		}
		return nil
	})
	return moved, err
}

// dhcpTakeover moves the ranges of the member with id to this node. The
// member must be offline, the condition promote already sets, so two nodes
// never lease one range; if it comes back it sees it no longer owns them.
func (server *Server) dhcpTakeover(ctx context.Context, who actor, id string) (string, error) {
	service := server.dhcpService()
	nodes := service.clusterNodes()
	if len(nodes) == 0 {
		return "", refuse(http.StatusUnprocessableEntity, "This node isn't in a cluster")
	}
	self := server.cluster.Snapshot().NodeID
	index := slices.IndexFunc(nodes, func(node cluster.Node) bool { return node.ID == id })
	switch {
	case id == self:
		return "", refuse(http.StatusUnprocessableEntity, "This node already serves its own ranges")
	case index < 0:
		return "", refuse(http.StatusUnprocessableEntity, "%s isn't a member of this cluster", id)
	case nodes[index].State == cluster.StateOnline:
		return "", refuse(http.StatusUnprocessableEntity, "%s is online; take over its ranges only once it's offline", nodes[index].Name)
	}
	moved, err := service.TakeOverRanges(ctx, who, nodes[index], self)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("took over %d DHCP %s from %s", moved, ifThenString(moved == 1, "range", "ranges"), nodes[index].Name), nil
}

// takeOverDHCPRanges is the Cluster page's Take Over DHCP Ranges.
func (server *Server) takeOverDHCPRanges(writer http.ResponseWriter, request *http.Request) {
	message, err := server.dhcpTakeover(request.Context(), requestActor(request, ""), strings.TrimSpace(request.FormValue("node")))
	if err != nil {
		server.renderClusterMutation(writer, request, serviceStatus(err), "", err.Error())
		return
	}
	server.renderClusterMutation(writer, request, http.StatusOK, sentence(message), "")
}

// takeOverDHCPRangesAPI moves an offline member's ranges to this node.
func (server *Server) takeOverDHCPRangesAPI(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		Node string `json:"node"`
	}
	if err := decodeJSON(request, &body); err != nil {
		apiError(writer, http.StatusBadRequest, err.Error())
		return
	}
	message, err := server.dhcpTakeover(request.Context(), requestActor(request, ""), strings.TrimSpace(body.Node))
	if err != nil {
		apiError(writer, serviceStatus(err), err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"message": sentence(message)})
}

// dhcpFormRanges is the scope's ranges after the scope dialog. Outside a
// cluster the dialog edits the first range. On a cluster it edits the whole
// range, split evenly across the nodes (design §3); the same range keeps the
// split it has, so an edit doesn't undo a takeover. Ranges set by hand with a
// gap between them keep it: the dialog moves only the outer edges, since an
// even re-split would lease the addresses the operator kept out of the pool.
func dhcpFormRanges(ranges []config.DHCPRange, start, end string, nodes []cluster.Node) ([]config.DHCPRange, error) {
	if len(nodes) == 0 {
		return dhcpFirstRange(ranges, start, end), nil
	}
	if start == "" && end == "" {
		return nil, nil
	}
	if first, last := dhcpRangeEnvelope(ranges); first == start && last == end &&
		!slices.ContainsFunc(ranges, func(pool config.DHCPRange) bool { return pool.Node == "" }) {
		return ranges, nil
	}
	if gap, ok := dhcpRangeGap(ranges); ok {
		return dhcpMoveRangeEdges(ranges, gap, start, end)
	}
	ids := make([]string, len(nodes))
	for index, node := range nodes {
		ids[index] = node.ID
	}
	split, err := config.SplitDHCPRange(start, end, ids)
	if err != nil {
		return nil, refuse(http.StatusUnprocessableEntity, "%s", sentence(err.Error()))
	}
	return split, nil
}

// dhcpRangeGap is the first stretch of addresses that pinned ranges leave out
// of the pool, as "first–last". It reports false when a range has no node, a
// bound doesn't parse, or the ranges, sorted by start, are contiguous.
func dhcpRangeGap(ranges []config.DHCPRange) (string, bool) {
	sorted := slices.Clone(ranges)
	for _, pool := range sorted {
		if pool.Node == "" {
			return "", false
		}
	}
	slices.SortFunc(sorted, func(left, right config.DHCPRange) int {
		return dhcpRangeStart(left).Compare(dhcpRangeStart(right))
	})
	for index := 1; index < len(sorted); index++ {
		previous, errEnd := netip.ParseAddr(sorted[index-1].End)
		next, errStart := netip.ParseAddr(sorted[index].Start)
		if errEnd != nil || errStart != nil {
			return "", false
		}
		if next.Compare(previous.Next()) > 0 {
			return previous.Next().String() + "–" + next.Prev().String(), true
		}
	}
	return "", false
}

// dhcpMoveRangeEdges moves the whole range's outer edges and leaves each
// range's node and the inner ranges as they are. The start has to stay within
// the first range and the end within the last, or the edge would cross the
// gap the operator left; that is refused, naming the gap.
func dhcpMoveRangeEdges(ranges []config.DHCPRange, gap, start, end string) ([]config.DHCPRange, error) {
	moved := slices.Clone(ranges)
	slices.SortFunc(moved, func(left, right config.DHCPRange) int {
		return dhcpRangeStart(left).Compare(dhcpRangeStart(right))
	})
	low, high := &moved[0], &moved[len(moved)-1]
	newStart, startErr := netip.ParseAddr(start)
	newEnd, endErr := netip.ParseAddr(end)
	if startErr != nil || endErr != nil {
		return nil, refuse(http.StatusUnprocessableEntity, "the range start and end must be IPv4 addresses")
	}
	lowEnd, _ := netip.ParseAddr(low.End)
	if newStart.Compare(lowEnd) > 0 || newEnd.Compare(dhcpRangeStart(*high)) < 0 {
		return nil, refuse(http.StatusUnprocessableEntity,
			"the ranges leave %s out of the pool; move the start or end only within the first and last range, or edit the ranges in the configuration", gap)
	}
	low.Start, high.End = start, end
	return moved, nil
}

// dhcpRangeStart is the start of pool, or the zero address when it doesn't
// parse, which sorts first.
func dhcpRangeStart(pool config.DHCPRange) netip.Addr {
	start, _ := netip.ParseAddr(pool.Start)
	return start
}

// dhcpRangeEnvelope is the lowest start and highest end of ranges.
func dhcpRangeEnvelope(ranges []config.DHCPRange) (string, string) {
	var first, last netip.Addr
	for _, pool := range ranges {
		start, startErr := netip.ParseAddr(pool.Start)
		end, endErr := netip.ParseAddr(pool.End)
		if startErr != nil || endErr != nil {
			continue
		}
		if !first.IsValid() || start.Less(first) {
			first = start
		}
		if !last.IsValid() || last.Less(end) {
			last = end
		}
	}
	if !first.IsValid() {
		return "", ""
	}
	return first.String(), last.String()
}

// dhcpClusterScopeView shows a cluster's scope as the dialog edits it: the
// whole range, then each node's slice, with a warning on a slice too small
// to carry the scope's active leases alone (design §3).
func dhcpClusterScopeView(view *pages.DHCPScopeView, scope config.DHCPScope, nodes []cluster.Node, active int) {
	view.SplitNodes, view.MoreRanges = len(nodes), 0
	view.RangeStart, view.RangeEnd = dhcpRangeEnvelope(scope.Ranges)
	for _, pool := range scope.Ranges {
		split := pages.DHCPRangeSplit{Node: pool.Node, Range: pool.Start + " – " + pool.End}
		if index := slices.IndexFunc(nodes, func(node cluster.Node) bool { return node.ID == pool.Node }); index >= 0 {
			split.Node = nodes[index].Name
		}
		switch size, err := config.DHCPRangeSize(pool.Start, pool.End); {
		case pool.Node == "":
			split.Node, split.Warning = "No node", "No node leases from it; save the scope to split it"
		case err == nil && size < uint64(active):
			split.Warning = fmt.Sprintf("Too small to carry the scope's %d active leases alone", active)
		}
		view.Split = append(view.Split, split)
	}
}

// dhcpActiveLeases counts each scope's leases from its pool: the leases
// that hold an address (dhcpService.Leases), less reserved ones.
func dhcpActiveLeases(leases []dhcpLeaseView) map[string]int {
	active := map[string]int{}
	for _, lease := range leases {
		if !lease.Reserved {
			active[lease.Scope]++
		}
	}
	return active
}

// annotateClusterDHCP marks each node's DHCP ranges on the Cluster page: an
// offline replica with ranges offers Take Over, and a replica promoted for
// recovery takes over its primary's in the same step.
func (server *Server) annotateClusterDHCP(view *pages.ClusterPageView) {
	owned := map[string]int{}
	for _, scope := range server.config.Current().Config.DHCP.Scopes {
		for _, pool := range scope.Ranges {
			owned[pool.Node]++
		}
	}
	primary := slices.IndexFunc(view.Nodes, func(node pages.ClusterNodeView) bool { return node.ID == view.PrimaryID })
	for index := range view.Nodes {
		node := &view.Nodes[index]
		node.DHCPRanges = owned[node.ID]
		if node.Local && node.Role == "Replica" && primary >= 0 && owned[view.PrimaryID] > 0 {
			node.DHCPTakeover, node.DHCPTakeoverName = view.PrimaryID, view.Nodes[primary].Name
		}
	}
}
