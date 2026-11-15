//go:build !linux

package app

import (
	"context"
	"errors"
)

// listenDHCP is Linux only for now: the server needs the arrival interface of
// each broadcast, which it reads with IP_PKTINFO.
func listenDHCP(context.Context, int) (*udpDHCPConn, error) {
	return nil, errors.New("the DHCP server runs on Linux only")
}

type udpDHCPConn struct{ dhcpConn }
