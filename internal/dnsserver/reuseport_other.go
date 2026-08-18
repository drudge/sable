//go:build !linux

package dnsserver

import "syscall"

// reusePortSupported is false everywhere but Linux. See the Linux build of this
// file for why the other platforms gain nothing from a second socket.
const reusePortSupported = false

func udpSocketControl(_, _ string, _ syscall.RawConn) error { return nil }
