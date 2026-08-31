//go:build linux

package main

import "syscall"

func execContainerBinary(path string, arguments, environment []string) error {
	return syscall.Exec(path, append([]string{path}, arguments...), environment)
}
