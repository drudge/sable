//go:build !linux

package main

import "errors"

func execContainerBinary(string, []string, []string) error {
	return errors.New("the container launcher is supported only on Linux")
}
