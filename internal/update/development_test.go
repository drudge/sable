package update

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/drudge/sable/internal/version"
)

func setTestRelease(t *testing.T, release string) {
	t.Helper()
	previous := version.Release
	version.Release = release
	t.Cleanup(func() { version.Release = previous })
}

func TestDevelopmentBuildCannotCheckOrReplaceItsExecutable(t *testing.T) {
	for _, release := range []string{"dev", "unknown", "dev-snapshot", "1.0.0-dev.7", "1.0.0-snapshot"} {
		t.Run(release, func(t *testing.T) {
			setTestRelease(t, release)
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				http.Error(writer, "unexpected release request", http.StatusInternalServerError)
			}))
			defer server.Close()
			binaryPath := installedExecutable(t, "development executable")
			mirrorPath := installedExecutable(t, "service executable")
			for _, checkOnly := range []bool{false, true} {
				for _, requestedVersion := range []string{"", "v1.0.0"} {
					result, err := Apply(context.Background(), Options{
						APIBaseURL: server.URL, BinaryPath: binaryPath, MirrorBinaryPath: mirrorPath,
						CheckOnly: checkOnly, Version: requestedVersion, PreRelease: true,
					})
					if !errors.Is(err, ErrDevelopmentBuild) || result.Applied {
						t.Fatalf("Apply(checkOnly=%t, version=%q) = %+v, %v", checkOnly, requestedVersion, result, err)
					}
				}
			}
			if err := Installable(binaryPath); !errors.Is(err, ErrDevelopmentBuild) {
				t.Fatalf("Installable() = %v", err)
			}
			manager := NewManager(Options{APIBaseURL: server.URL, BinaryPath: binaryPath})
			initial := manager.Status()
			if !initial.Development || initial.Blocked == "" || initial.Available || initial.Busy() || initial.UpToDate() {
				t.Fatalf("development update status = %+v", initial)
			}
			if _, err := manager.Check(context.Background(), false); !errors.Is(err, ErrDevelopmentBuild) {
				t.Fatal("development manager allowed a release check")
			}
			if err := manager.Install(false); !errors.Is(err, ErrDevelopmentBuild) {
				t.Fatal("development manager accepted an installation")
			}
			if manager.Status() != initial {
				t.Fatalf("rejected operation changed the development status: %+v", manager.Status())
			}
			if requests.Load() != 0 {
				t.Fatalf("development update made %d release requests", requests.Load())
			}
			for path, want := range map[string]string{binaryPath: "development executable", mirrorPath: "service executable"} {
				contents, err := os.ReadFile(path)
				if err != nil || string(contents) != want {
					t.Fatalf("executable %s changed: %q, %v", path, contents, err)
				}
				if leftovers := stagingLeftovers(t, filepath.Dir(path)); len(leftovers) != 0 {
					t.Fatalf("development update left staging files: %v", leftovers)
				}
			}
		})
	}
}
