//go:build faultinject

package faultinject

import (
	"errors"
	"os"
	"sync"
	"time"
)

// Enabled reports whether this binary was built with the faultinject tag.
const Enabled = true

// RefreshInterval is how long a read of the control file is trusted before
// the next Now or CheckWrite reads it again.
var RefreshInterval = 250 * time.Millisecond

var control = struct {
	sync.Mutex
	path   string
	readAt time.Time
	faults Faults
}{path: os.Getenv(ControlEnv)}

// SetControlFile points the hooks at another control file and drops the
// cached faults, for tests in this build.
func SetControlFile(path string) {
	control.Lock()
	defer control.Unlock()
	control.path, control.readAt, control.faults = path, time.Time{}, Faults{}
}

// Current returns the faults in force, re-reading the control file when the
// cached copy is older than RefreshInterval. A file that can't be read or
// parsed keeps the last faults that could.
func Current() Faults {
	control.Lock()
	defer control.Unlock()
	now := time.Now()
	if control.path == "" || (!control.readAt.IsZero() && now.Sub(control.readAt) < RefreshInterval) {
		return control.faults
	}
	control.readAt = now
	if faults, err := readControlFile(control.path); err == nil {
		control.faults = faults
	}
	return control.faults
}

func readControlFile(path string) (Faults, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Faults{}, nil
	}
	if err != nil {
		return Faults{}, err
	}
	return decodeControlFile(contents)
}

// Now returns the current time moved by the clock offset. The offset moves
// the monotonic reading too, so a change to it shows up as a step in local
// durations as well as in wall time.
func Now() time.Time { return time.Now().Add(Current().ClockOffset) }

// CheckWrite returns an error wrapping syscall.ENOSPC while the disk is
// full. what names the write, as in "write cluster manifest".
func CheckWrite(what string) error {
	if !Current().DiskFull {
		return nil
	}
	return diskFullError(what)
}
