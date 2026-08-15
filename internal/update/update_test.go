package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIsNewerTreatsDevelopmentBuildsAsOutdated(t *testing.T) {
	if !isNewer("0.7.0", "0.6.0") {
		t.Fatal("0.7.0 should supersede 0.6.0")
	}
	if !isNewer("0.6.0", "0.6.0-dev") {
		t.Fatal("a release should supersede its own pre-release build")
	}
	if !isNewer("0.6.0", "unknown") {
		t.Fatal("an unrecognizable running version should always be updated")
	}
	if isNewer("0.6.0", "0.6.0") || isNewer("0.5.9", "0.6.0") {
		t.Fatal("older or equal releases should not be offered")
	}
	if isNewer("nightly", "0.6.0") {
		t.Fatal("an unversioned tag should never be offered")
	}
}

func TestNewestReleasePrefersHighestVersionAndSkipsDrafts(t *testing.T) {
	selected, err := newestRelease([]release{
		{TagName: "v0.7.0-rc.1", PreRelease: true},
		{TagName: "v0.8.0", Draft: true},
		{TagName: "v0.6.5"},
		{TagName: "nightly"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if selected.TagName != "v0.7.0-rc.1" {
		t.Fatalf("selected release = %q", selected.TagName)
	}
	if _, err := newestRelease([]release{{TagName: "v1.0.0", Draft: true}}); err == nil {
		t.Fatal("a draft-only release list should not produce a candidate")
	}
}

func TestSelectAssetMatchesRunningPlatform(t *testing.T) {
	expected := assetName("0.7.0", runtime.GOOS, runtime.GOARCH)
	selected := release{TagName: "v0.7.0", Assets: []releaseAsset{
		{Name: "checksums.txt"},
		{Name: "sable_0.7.0_plan9_mips.tar.gz"},
		{Name: expected},
	}}
	asset, err := selectAsset(selected, "0.7.0")
	if err != nil {
		t.Fatal(err)
	}
	if asset.Name != expected {
		t.Fatalf("selected asset = %q, want %q", asset.Name, expected)
	}
	if _, err := selectAsset(release{TagName: "v0.7.0"}, "0.7.0"); err == nil {
		t.Fatal("a release without a platform build should fail")
	}
}

func TestExpectedChecksumReadsPublishedDigests(t *testing.T) {
	checksums := []byte("abc123  sable_0.7.0_linux_amd64.tar.gz\ndef456  sable_0.7.0_darwin_arm64.tar.gz\n")
	digest, err := expectedChecksum(checksums, "sable_0.7.0_darwin_arm64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if digest != "def456" {
		t.Fatalf("checksum = %q", digest)
	}
	if _, err := expectedChecksum(checksums, "sable_0.7.0_windows_amd64.zip"); err == nil {
		t.Fatal("a missing asset should fail checksum lookup")
	}
}

func TestExtractExecutableReadsBothArchiveFormats(t *testing.T) {
	contents := []byte("#!/bin/sh\nexit 0\n")
	extracted, err := extractExecutable("sable_0.7.0_linux_amd64.tar.gz", tarGzipArchive(t, "sable_0.7.0_linux_amd64/sable", contents))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(extracted, contents) {
		t.Fatalf("tar.gz executable = %q", extracted)
	}
	extracted, err = extractExecutable("sable_0.7.0_windows_amd64.zip", zipArchive(t, "sable_0.7.0_windows_amd64/sable.exe", contents))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(extracted, contents) {
		t.Fatalf("zip executable = %q", extracted)
	}
	if _, err := extractExecutable("sable_0.7.0_linux_amd64.tar.gz", tarGzipArchive(t, "sable_0.7.0_linux_amd64/README.md", contents)); err == nil {
		t.Fatal("an archive without the executable should fail")
	}
}

func TestApplyVerifiesAndReplacesTheInstalledExecutable(t *testing.T) {
	requireExecutableScripts(t)
	binaryPath := installedExecutable(t, "#!/bin/sh\necho old\n")
	server := releaseServer(t, "v9.9.9", false, nil)
	result, err := Apply(context.Background(), Options{
		APIBaseURL: server.URL,
		BinaryPath: binaryPath,
		Output:     testWriter{t},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied || result.LatestVersion != "9.9.9" {
		t.Fatalf("result = %+v", result)
	}
	installed, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installed), "echo 9.9.9") {
		t.Fatalf("installed executable = %q", installed)
	}
	info, err := os.Stat(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("installed executable mode = %v", info.Mode().Perm())
	}
	if entries := stagingLeftovers(t, filepath.Dir(binaryPath)); len(entries) != 0 {
		t.Fatalf("update left staging files behind: %v", entries)
	}
}

func TestApplyRejectsAnArchiveThatFailsChecksumVerification(t *testing.T) {
	requireExecutableScripts(t)
	binaryPath := installedExecutable(t, "#!/bin/sh\necho old\n")
	server := releaseServer(t, "v9.9.9", false, func(checksums []byte) []byte {
		return bytes.Replace(checksums, checksums[:8], []byte("00000000"), 1)
	})
	if _, err := Apply(context.Background(), Options{APIBaseURL: server.URL, BinaryPath: binaryPath}); err == nil {
		t.Fatal("a tampered archive should abort the update")
	} else if !strings.Contains(err.Error(), "checksum verification failed") {
		t.Fatalf("error = %v", err)
	}
	installed, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installed), "echo old") {
		t.Fatalf("a failed update replaced the executable: %q", installed)
	}
}

func TestApplyReportsAnAvailableReleaseWithoutInstallingIt(t *testing.T) {
	server := releaseServer(t, "v9.9.9", false, nil)
	result, err := Apply(context.Background(), Options{APIBaseURL: server.URL, CheckOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Applied || result.UpToDate || result.LatestVersion != "9.9.9" {
		t.Fatalf("result = %+v", result)
	}
}

func TestApplySkipsPreReleasesUnlessRequested(t *testing.T) {
	server := releaseServer(t, "v9.9.9-rc.1", true, nil)
	if _, err := Apply(context.Background(), Options{APIBaseURL: server.URL, CheckOnly: true}); err == nil {
		t.Fatal("a pre-release-only repository should report no stable release")
	} else if !strings.Contains(err.Error(), "pre-release") {
		t.Fatalf("error = %v", err)
	}
	result, err := Apply(context.Background(), Options{APIBaseURL: server.URL, CheckOnly: true, PreRelease: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.PreRelease || result.LatestVersion != "9.9.9-rc.1" {
		t.Fatalf("result = %+v", result)
	}
}

func TestApplyReportsAnUpToDateInstallation(t *testing.T) {
	server := releaseServer(t, "v0.0.1", false, nil)
	result, err := Apply(context.Background(), Options{APIBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !result.UpToDate || result.Applied {
		t.Fatalf("result = %+v", result)
	}
}

// releaseServer publishes a single Sable release for the running platform. The
// optional tamper function corrupts the published checksums.
func releaseServer(t *testing.T, tag string, preRelease bool, tamper func([]byte) []byte) *httptest.Server {
	t.Helper()
	releaseVersion := strings.TrimPrefix(tag, "v")
	archiveName := assetName(releaseVersion, runtime.GOOS, runtime.GOARCH)
	executable := []byte(fmt.Sprintf("#!/bin/sh\necho %s\n", releaseVersion))
	archive := tarGzipArchive(t, strings.TrimSuffix(archiveName, ".tar.gz")+"/sable", executable)
	if strings.HasSuffix(archiveName, ".zip") {
		archive = zipArchive(t, strings.TrimSuffix(archiveName, ".zip")+"/sable.exe", executable)
	}
	digest := sha256.Sum256(archive)
	checksums := []byte(fmt.Sprintf("%s  %s\n", hex.EncodeToString(digest[:]), archiveName))
	if tamper != nil {
		checksums = tamper(checksums)
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	published := release{
		TagName: tag, PreRelease: preRelease, HTMLURL: server.URL + "/releases/" + tag,
		Assets: []releaseAsset{
			{Name: archiveName, DownloadURL: server.URL + "/download/" + archiveName},
			{Name: checksumsAssetName, DownloadURL: server.URL + "/download/" + checksumsAssetName},
		},
	}
	mux.HandleFunc("/repos/"+defaultRepository+"/releases/latest", func(writer http.ResponseWriter, request *http.Request) {
		if preRelease {
			http.Error(writer, "not found", http.StatusNotFound)
			return
		}
		writeJSON(t, writer, published)
	})
	mux.HandleFunc("/repos/"+defaultRepository+"/releases", func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(t, writer, []release{published})
	})
	mux.HandleFunc("/download/"+archiveName, func(writer http.ResponseWriter, request *http.Request) {
		writer.Write(archive)
	})
	mux.HandleFunc("/download/"+checksumsAssetName, func(writer http.ResponseWriter, request *http.Request) {
		writer.Write(checksums)
	})
	return server
}

func writeJSON(t *testing.T, writer http.ResponseWriter, payload any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(payload); err != nil {
		t.Error(err)
	}
}

func installedExecutable(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sable")
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func stagingLeftovers(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	leftovers := make([]string, 0)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".sable-update-") {
			leftovers = append(leftovers, entry.Name())
		}
	}
	return leftovers
}

func tarGzipArchive(t *testing.T, name string, contents []byte) []byte {
	t.Helper()
	buffer := &bytes.Buffer{}
	compressor := gzip.NewWriter(buffer)
	writer := tar.NewWriter(compressor)
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(contents)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(contents); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func zipArchive(t *testing.T, name string, contents []byte) []byte {
	t.Helper()
	buffer := &bytes.Buffer{}
	writer := zip.NewWriter(buffer)
	entry, err := writer.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(contents); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func requireExecutableScripts(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the update test installs a shell script as the Sable executable")
	}
}

type testWriter struct{ t *testing.T }

func (writer testWriter) Write(contents []byte) (int, error) {
	writer.t.Log(strings.TrimRight(string(contents), "\n"))
	return len(contents), nil
}
