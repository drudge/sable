//go:build !linux

package app

import (
	"context"
	"errors"
	"time"
)

// listenDHCP is Linux only for now: the server needs the arrival interface of
// each broadcast, which it reads with IP_PKTINFO.
func listenDHCP(context.Context, int) (*udpDHCPConn, error) {
	return nil, errors.New("the DHCP server runs on Linux only")
}

type udpDHCPConn struct{ dhcpConn }

func seekDHCP(context.Context, dhcpProbeLink, []byte, time.Duration) ([][]byte, error) {
	return nil, errors.New("the DHCP server probe runs on Linux only")
}
