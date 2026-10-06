//go:build unix

package procstats

import (
	"syscall"
	"time"
)

func cpuSeconds() (float64, bool) {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
		return 0, false
	}
	used := time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
	return used.Seconds(), true
}
