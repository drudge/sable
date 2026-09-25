//go:build linux

package neighbors

import "syscall"

func read() ([]Entry, error) {
	raw, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return parseNeighborMessages(raw), nil
}
