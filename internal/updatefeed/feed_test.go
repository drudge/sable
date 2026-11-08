package updatefeed

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFeedOffersTheReleaseArchiveWithItsChecksum(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "sable")
	if err := os.WriteFile(binary, []byte("not really sable"), 0o755); err != nil {
		t.Fatal(err)
	}
	feed, err := Start(Release{Version: "1.0.2", Binary: binary, Directory: directory, Notes: "notes"})
	if err != nil {
		t.Fatal(err)
	}
	defer feed.Close()
	var release struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(get(t, feed.URL+"/repos/drudge/sable/releases/latest"), &release); err != nil {
		t.Fatal(err)
	}
	if release.Tag != "v1.0.2" || len(release.Assets) != 2 {
		t.Fatalf("release = %+v, want v1.0.2 with an archive and checksums", release)
	}
	archive := get(t, release.Assets[0].URL)
	want := fmt.Sprintf("%x  %s\n", sha256.Sum256(archive), release.Assets[0].Name)
	if got := string(get(t, release.Assets[1].URL)); got != want {
		t.Fatalf("checksums.txt = %q, want %q", got, want)
	}
	if !strings.HasPrefix(release.Assets[0].URL, feed.URL+"/downloads/") {
		t.Fatalf("archive URL %q is not on the feed", release.Assets[0].URL)
	}
}

func get(t *testing.T, url string) []byte {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %v", url, response.StatusCode, err)
	}
	return contents
}
