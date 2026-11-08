package faultinject

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Faults is what the control file asks for.
type Faults struct {
	ClockOffset time.Duration
	DiskFull    bool
	// Unreachable lists host:port addresses, exactly as the node dials them,
	// that its outgoing connections fail to reach.
	Unreachable []string
}

type controlFile struct {
	ClockOffset string   `json:"clock_offset,omitempty"`
	DiskFull    bool     `json:"disk_full,omitempty"`
	Unreachable []string `json:"unreachable,omitempty"`
}

// WriteControlFile writes faults to path for a faultinject build to pick up.
// It works in any build, so a harness built without the tag can drive nodes
// built with it.
func WriteControlFile(path string, faults Faults) error {
	file := controlFile{DiskFull: faults.DiskFull, Unreachable: faults.Unreachable}
	if faults.ClockOffset != 0 {
		file.ClockOffset = faults.ClockOffset.String()
	}
	contents, err := json.Marshal(file)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, contents, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func decodeControlFile(contents []byte) (Faults, error) {
	var file controlFile
	if err := json.Unmarshal(contents, &file); err != nil {
		return Faults{}, fmt.Errorf("parse fault control file: %w", err)
	}
	faults := Faults{DiskFull: file.DiskFull, Unreachable: file.Unreachable}
	if file.ClockOffset != "" {
		var err error
		if faults.ClockOffset, err = time.ParseDuration(file.ClockOffset); err != nil {
			return Faults{}, fmt.Errorf("parse clock_offset: %w", err)
		}
	}
	return faults, nil
}
