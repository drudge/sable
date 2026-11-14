//go:build !linux

package main

func raiseBindCapability() error { return nil }
