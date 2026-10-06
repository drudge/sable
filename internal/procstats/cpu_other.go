//go:build !unix && !windows

package procstats

func cpuSeconds() (float64, bool) { return 0, false }
