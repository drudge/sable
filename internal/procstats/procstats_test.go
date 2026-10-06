package procstats

import (
	"runtime"
	"testing"
)

func TestRead(t *testing.T) {
	runtime.GC()
	stats := Read()
	if stats.Goroutines < 1 || stats.NumCPU < 1 || stats.GOMAXPROCS < 1 {
		t.Fatalf("scheduler counts = %d goroutines, %d CPUs, GOMAXPROCS %d", stats.Goroutines, stats.NumCPU, stats.GOMAXPROCS)
	}
	if stats.HeapAllocBytes == 0 || stats.HeapInuseBytes == 0 || stats.SysBytes < stats.HeapSysBytes {
		t.Fatalf("heap = alloc %d, in use %d, sys %d, heap sys %d", stats.HeapAllocBytes, stats.HeapInuseBytes, stats.SysBytes, stats.HeapSysBytes)
	}
	if stats.GCCycles == 0 || stats.LastGC.IsZero() {
		t.Fatalf("GC = %d cycles, last %v after runtime.GC", stats.GCCycles, stats.LastGC)
	}
	if runtime.GOOS != "windows" && (!stats.HasCPU || stats.CPUSeconds <= 0) {
		t.Fatalf("CPU = %v seconds, reported %v", stats.CPUSeconds, stats.HasCPU)
	}
	if runtime.GOOS == "linux" && (!stats.HasResident || stats.ResidentBytes < stats.HeapInuseBytes) {
		t.Fatalf("resident = %d bytes, reported %v, heap in use %d", stats.ResidentBytes, stats.HasResident, stats.HeapInuseBytes)
	}
}
