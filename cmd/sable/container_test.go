package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestContainerWebUpdatesAreExplicitlyEnabled(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: "", want: false},
		{value: "false", want: false},
		{value: "true", want: true},
		{value: "1", want: true},
	} {
		got, err := containerWebUpdatesEnabled(test.value)
		if err != nil {
			t.Fatalf("containerWebUpdatesEnabled(%q): %v", test.value, err)
		}
		if got != test.want {
			t.Fatalf("containerWebUpdatesEnabled(%q) = %t, want %t", test.value, got, test.want)
		}
	}
	if _, err := containerWebUpdatesEnabled("sometimes"); err == nil {
		t.Fatal("an invalid web-update switch was accepted")
	}
}

func TestContainerPrefersOnlyANewerPersistentRelease(t *testing.T) {
	for _, test := range []struct {
		image, mutable string
		want           bool
	}{
		{image: "1.2.0", mutable: "1.3.0", want: true},
		{image: "1.2.0", mutable: "1.3.0-rc.1", want: true},
		{image: "1.2.0", mutable: "1.2.0", want: false},
		{image: "1.2.0", mutable: "1.1.9", want: false},
		{image: "dev", mutable: "1.2.0", want: false},
		{image: "1.2.0-snapshot", mutable: "1.3.0", want: false},
		{image: "1.2.0-rc.1", mutable: "1.2.0", want: true},
		{image: "1.2.0", mutable: "broken", want: false},
	} {
		if got := preferMutableRelease(test.image, test.mutable); got != test.want {
			t.Fatalf("preferMutableRelease(%q, %q) = %t, want %t", test.image, test.mutable, got, test.want)
		}
	}
}

func TestExecutableReleaseReadsTheMachineVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture is a shell script")
	}
	path := filepath.Join(t.TempDir(), "sable")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '2.4.0-rc.2\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	release, err := executableRelease(path)
	if err != nil {
		t.Fatal(err)
	}
	if release != "2.4.0-rc.2" {
		t.Fatalf("release = %q", release)
	}
}

func TestContainerBindErrorSaysWhy(t *testing.T) {
	denied := fmt.Errorf("listen udp 0.0.0.0:53: %w", &net.OpError{Op: "listen", Net: "udp",
		Addr: &net.UDPAddr{IP: net.IPv4zero, Port: 53}, Err: os.NewSyscallError("bind", syscall.EACCES)})
	if got := explainContainerBind(denied).Error(); !strings.Contains(got, "NET_BIND_SERVICE") || !strings.Contains(got, "bind: permission denied") {
		t.Fatalf("explainContainerBind(%v) = %q, want the cause kept and NET_BIND_SERVICE named", denied, got)
	}
	other := errors.New("open /data/sable.toml: no such file or directory")
	if got := explainContainerBind(other); got != other {
		t.Fatalf("explainContainerBind changed an unrelated error: %v", got)
	}
	if explainContainerBind(nil) != nil {
		t.Fatal("explainContainerBind(nil) is not nil")
	}
}

func TestRaiseBindCapabilityWithoutPermittedIsNoOp(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root holds every capability")
	}
	if err := raiseBindCapability(); err != nil {
		t.Fatalf("raiseBindCapability without the capability permitted: %v", err)
	}
}

func TestContainerBindHintOnlyForLowPortListen(t *testing.T) {
	listenDenied := func(network string, addr net.Addr) error {
		return fmt.Errorf("%s %s: %w", "listen "+network, addr, &net.OpError{Op: "listen", Net: network,
			Addr: addr, Err: os.NewSyscallError("bind", syscall.EACCES)})
	}
	cases := []struct {
		name string
		err  error
		hint bool
	}{
		{"udp 67", listenDenied("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 67}), true},
		{"tcp 853", listenDenied("tcp", &net.TCPAddr{IP: net.IPv6unspecified, Port: 853}), true},
		{"tcp 8053", listenDenied("tcp", &net.TCPAddr{IP: net.IPv4zero, Port: 8053}), false},
		{"unreadable config", fmt.Errorf("open configuration: %w",
			&os.PathError{Op: "open", Path: "/config/sable.toml", Err: syscall.EACCES}), false},
		{"data volume owned by root", fmt.Errorf("open database: %w",
			&os.PathError{Op: "open", Path: "/data/sable.db", Err: syscall.EACCES}), false},
	}
	for _, tc := range cases {
		got := strings.Contains(explainContainerBind(tc.err).Error(), "NET_BIND_SERVICE")
		if got != tc.hint {
			t.Errorf("%s: NET_BIND_SERVICE hint = %v, want %v (error: %v)", tc.name, got, tc.hint, tc.err)
		}
	}
}
