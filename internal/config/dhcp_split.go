package config

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// SplitDHCPRange divides the IPv4 range start-end into one contiguous range
// per node, in order, as evenly as the address count allows; the first
// slices take the remainder. With no nodes it is the range, unpinned. Each
// node needs at least one address.
func SplitDHCPRange(start, end string, nodes []string) ([]DHCPRange, error) {
	first, last, err := dhcpRangeBounds(start, end)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return []DHCPRange{{Start: start, End: end}}, nil
	}
	size := uint64(last) - uint64(first) + 1
	if size < uint64(len(nodes)) {
		return nil, fmt.Errorf("range %s-%s has %d addresses; it needs one for each of the %d nodes", start, end, size, len(nodes))
	}
	share, extra := size/uint64(len(nodes)), size%uint64(len(nodes))
	ranges := make([]DHCPRange, 0, len(nodes))
	next := uint64(first)
	for index, node := range nodes {
		count := share
		if uint64(index) < extra {
			count++
		}
		ranges = append(ranges, DHCPRange{Start: dhcpIPv4(next).String(), End: dhcpIPv4(next + count - 1).String(), Node: node})
		next += count
	}
	return ranges, nil
}

// DHCPRangeSize counts the addresses of the IPv4 range start-end.
func DHCPRangeSize(start, end string) (uint64, error) {
	first, last, err := dhcpRangeBounds(start, end)
	if err != nil {
		return 0, err
	}
	return uint64(last) - uint64(first) + 1, nil
}

// dhcpRangeBounds parses an IPv4 range whose start is before its end.
func dhcpRangeBounds(start, end string) (uint32, uint32, error) {
	first, err := netip.ParseAddr(start)
	if err != nil || !first.Is4() {
		return 0, 0, fmt.Errorf("range start %q is not an IPv4 address", start)
	}
	last, err := netip.ParseAddr(end)
	if err != nil || !last.Is4() {
		return 0, 0, fmt.Errorf("range end %q is not an IPv4 address", end)
	}
	if last.Less(first) {
		return 0, 0, fmt.Errorf("range %s-%s ends before it starts", start, end)
	}
	firstBytes, lastBytes := first.As4(), last.As4()
	return binary.BigEndian.Uint32(firstBytes[:]), binary.BigEndian.Uint32(lastBytes[:]), nil
}

func dhcpIPv4(value uint64) netip.Addr {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], uint32(value))
	return netip.AddrFrom4(bytes)
}
