//go:build linux

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	capabilityNetBindService = 10
	capabilityVersion3       = 0x20080522
	prctlCapAmbient          = 47
	prctlCapAmbientRaise     = 2
)

type capabilityHeader struct {
	version uint32
	pid     int32
}

type capabilitySets struct {
	effective, permitted, inheritable uint32
}

// capabilityRequest lives outside any stack: AllThreadsSyscall takes its
// pointers as uintptr, and a stack can move while the call runs. The launcher
// raises capabilities once, before anything else starts.
var capabilityRequest struct {
	header capabilityHeader
	sets   [2]capabilitySets
}

// raiseBindCapability moves CAP_NET_BIND_SERVICE from the permitted set, where
// the image's file capability puts it, into the effective, inheritable, and
// ambient sets on every thread. The ambient set keeps it across the exec of a
// web-updated executable, which has no file capability of its own. When the
// capability isn't permitted, as with cap_drop ALL, it does nothing.
func raiseBindCapability() error {
	request := &capabilityRequest
	request.header = capabilityHeader{version: capabilityVersion3}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&request.header)),
		uintptr(unsafe.Pointer(&request.sets[0])), 0); errno != 0 {
		return fmt.Errorf("read the process capabilities: %w", errno)
	}
	bit := uint32(1) << capabilityNetBindService
	if request.sets[0].permitted&bit == 0 {
		return nil
	}
	request.sets[0].effective |= bit
	request.sets[0].inheritable |= bit
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&request.header)),
		uintptr(unsafe.Pointer(&request.sets[0])), 0); errno != 0 {
		return fmt.Errorf("raise CAP_NET_BIND_SERVICE: %w", errno)
	}
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prctlCapAmbient, prctlCapAmbientRaise,
		capabilityNetBindService); errno != 0 {
		return fmt.Errorf("make CAP_NET_BIND_SERVICE ambient: %w", errno)
	}
	return nil
}
