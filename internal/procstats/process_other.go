//go:build !unix && !windows

package procstats

func cpuSeconds() (float64, bool) { return 0, false }

func maxFDs() (uint64, bool) { return 0, false }
