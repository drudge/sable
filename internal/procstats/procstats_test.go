package procstats

import (
	"runtime"
	"testing"
	"time"
)

func TestRead(t *testing.T) {
	runtime.GC()
	stats := Read()
	if stats.StartTime.IsZero() || stats.StartTime.After(time.Now()) {
		t.Fatalf("start time = %v", stats.StartTime)
	}
	if stats.Goroutines < 1 || stats.Threads < 1 || stats.NumCPU < 1 || stats.GOMAXPROCS < 1 {
		t.Fatalf("scheduler counts = %d goroutines, %d threads, %d CPUs, GOMAXPROCS %d", stats.Goroutines, stats.Threads, stats.NumCPU, stats.GOMAXPROCS)
	}
	if stats.HeapAllocBytes == 0 || stats.HeapInuseBytes < stats.HeapAllocBytes || stats.SysBytes < stats.HeapSysBytes || stats.NextGCBytes == 0 {
		t.Fatalf("heap = alloc %d, in use %d, sys %d, heap sys %d, goal %d", stats.HeapAllocBytes, stats.HeapInuseBytes, stats.SysBytes, stats.HeapSysBytes, stats.NextGCBytes)
	}
	if stats.GCCycles == 0 || stats.LastGC.IsZero() || stats.GCPauseQuantiles[4] < stats.GCPauseQuantiles[0] {
		t.Fatalf("GC = %d cycles, last %v, pause quantiles %v after runtime.GC", stats.GCCycles, stats.LastGC, stats.GCPauseQuantiles)
	}
	if !stats.HasCPU {
		t.Fatal("CPU time is not reported")
	}
	// GetProcessTimes counts in steps of about 15.6 ms, so an early reading
	// on Windows can still be zero.
	if runtime.GOOS != "windows" && stats.CPUSeconds <= 0 {
		t.Fatalf("CPU = %v seconds", stats.CPUSeconds)
	}
	if runtime.GOOS == "linux" {
		if !stats.HasMemory || stats.ResidentBytes < stats.HeapInuseBytes || stats.VirtualBytes < stats.ResidentBytes {
			t.Fatalf("memory = resident %d, virtual %d, reported %v, heap in use %d", stats.ResidentBytes, stats.VirtualBytes, stats.HasMemory, stats.HeapInuseBytes)
		}
		if !stats.HasOpenFDs || stats.OpenFDs < 3 {
			t.Fatalf("open descriptors = %d, reported %v", stats.OpenFDs, stats.HasOpenFDs)
		}
	}
	if runtime.GOOS != "windows" && (!stats.HasMaxFDs || stats.MaxFDs < stats.OpenFDs) {
		t.Fatalf("descriptor limit = %d, reported %v, open %d", stats.MaxFDs, stats.HasMaxFDs, stats.OpenFDs)
	}
}
