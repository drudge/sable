//go:build faultinject

package faultinject

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestNowFollowsTheControlFileWithoutARestart(t *testing.T) {
	write := UseFaults(t, Faults{ClockOffset: time.Hour})
	if skew := Now().Sub(time.Now()); skew < 59*time.Minute || skew > 61*time.Minute {
		t.Fatalf("skew = %v, want about 1h", skew)
	}
	write(Faults{ClockOffset: -30 * time.Second})
	if skew := time.Until(Now()); skew > -29*time.Second || skew < -31*time.Second {
		t.Fatalf("skew after rewrite = %v, want about -30s", skew)
	}
}

func TestCurrentCachesReadsForRefreshInterval(t *testing.T) {
	write := UseFaults(t, Faults{ClockOffset: time.Minute})
	RefreshInterval = time.Hour
	if got := Current().ClockOffset; got != time.Minute {
		t.Fatalf("ClockOffset = %v, want 1m", got)
	}
	write(Faults{ClockOffset: 2 * time.Minute})
	if got := Current().ClockOffset; got != time.Minute {
		t.Fatalf("ClockOffset inside the refresh interval = %v, want the cached 1m", got)
	}
}

func TestCurrentKeepsLastGoodFaultsWhenTheFileBreaks(t *testing.T) {
	UseFaults(t, Faults{DiskFull: true})
	if !Current().DiskFull {
		t.Fatal("DiskFull = false, want true")
	}
	path := control.path
	if err := os.WriteFile(path, []byte(`{"clock_offset": "soon"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !Current().DiskFull {
		t.Fatal("a broken control file dropped the last good faults")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(Current(), Faults{}) {
		t.Fatalf("Current() = %+v after the file was removed, want no faults", Current())
	}
}

func TestNoControlFileMeansNoFaults(t *testing.T) {
	UseFaults(t, Faults{})
	SetControlFile(filepath.Join(t.TempDir(), "missing.json"))
	if !reflect.DeepEqual(Current(), Faults{}) {
		t.Fatalf("Current() = %+v, want no faults", Current())
	}
	if err := CheckWrite("write"); err != nil {
		t.Fatalf("CheckWrite() = %v, want nil", err)
	}
}

func TestCheckWriteFailsWithENOSPCWhileTheDiskIsFull(t *testing.T) {
	write := UseFaults(t, Faults{DiskFull: true})
	err := CheckWrite("write cluster.json")
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("CheckWrite() = %v, want ENOSPC", err)
	}
	write(Faults{})
	if err := CheckWrite("write cluster.json"); err != nil {
		t.Fatalf("CheckWrite() after the disk cleared = %v, want nil", err)
	}
}

func TestEnabledInAFaultinjectBuild(t *testing.T) {
	if !Enabled {
		t.Fatal("Enabled = false in a faultinject build")
	}
}
