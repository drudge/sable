//go:build windows

package procstats

import "syscall"

func cpuSeconds() (float64, bool) {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, false
	}
	var creation, exit, kernel, user syscall.Filetime
	if syscall.GetProcessTimes(process, &creation, &exit, &kernel, &user) != nil {
		return 0, false
	}
	// Filetime durations count 100-nanosecond intervals.
	return float64(filetimeTicks(kernel)+filetimeTicks(user)) / 1e7, true
}

func filetimeTicks(value syscall.Filetime) uint64 {
	return uint64(value.HighDateTime)<<32 | uint64(value.LowDateTime)
}

// maxFDs has no Windows equivalent: handles have no per-process soft limit.
func maxFDs() (uint64, bool) { return 0, false }
