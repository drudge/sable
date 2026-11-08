//go:build !faultinject

package faultinject

import "time"

// Enabled reports whether this binary was built with the faultinject tag.
const Enabled = false

// Now returns the current time.
func Now() time.Time { return time.Now() }

// CheckWrite returns nil; only a faultinject build can fail a write.
func CheckWrite(string) error { return nil }

// SQLDriver returns name unchanged.
func SQLDriver(name string) string { return name }
