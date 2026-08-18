//go:build linux

package dnsserver

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePortSupported reports whether the platform spreads inbound datagrams
// across every socket bound to the same port. Linux hashes each client flow to
// one socket, so a second socket is a second reader. The BSDs deliver unicast
// datagrams to a single socket instead, which would leave the extra readers
// idle, so they stay on one socket and lose nothing.
const reusePortSupported = true

// udpSocketControl enables SO_REUSEPORT before the bind, which is the only
// point the option can be set.
func udpSocketControl(_, _ string, connection syscall.RawConn) error {
	var controlErr error
	err := connection.Control(func(descriptor uintptr) {
		controlErr = unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return controlErr
}
