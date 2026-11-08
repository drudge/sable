package updatefeed

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Release is the one release a feed offers.
type Release struct {
	Version       string        // like 1.0.2, without the v
	Binary        string        // the built binary to offer
	Directory     string        // where the release archive is written
	Notes         string        // the release body, in Markdown
	DownloadDelay time.Duration // held before each archive download
}

// Feed is a running release feed.
type Feed struct {
	URL    string
	server *http.Server
}

// Close stops the feed.
func (feed *Feed) Close() { _ = feed.server.Close() }

// Start archives the release's binary and serves it on a loopback port in
// the shape of the GitHub releases API.
func Start(release Release) (*Feed, error) {
	archiveName := fmt.Sprintf("sable_%s_%s_%s.tar.gz", release.Version, runtime.GOOS, runtime.GOARCH)
	archivePath := filepath.Join(release.Directory, archiveName)
	if err := archiveBinary(release.Binary, archivePath); err != nil {
		return nil, err
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		return nil, err
	}
	checksum := fmt.Sprintf("%x  %s\n", sha256.Sum256(archive), archiveName)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	feed := &Feed{URL: "http://" + listener.Addr().String()}
	releaseURL := "https://github.com/drudge/sable/releases/tag/v" + release.Version
	metadata := map[string]any{
		"tag_name": "v" + release.Version, "draft": false, "prerelease": false,
		"html_url": releaseURL, "body": release.Notes,
		"assets": []map[string]any{
			{"name": archiveName, "size": len(archive), "browser_download_url": feed.URL + "/downloads/" + archiveName},
			{"name": "checksums.txt", "size": len(checksum), "browser_download_url": feed.URL + "/downloads/checksums.txt"},
		},
	}
	mux := http.NewServeMux()
	for _, path := range []string{"/repos/drudge/sable/releases/latest", "/repos/drudge/sable/releases/tags/v" + release.Version} {
		mux.HandleFunc("GET "+path, func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(metadata)
		})
	}
	mux.HandleFunc("GET /repos/drudge/sable/releases", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode([]any{metadata})
	})
	mux.HandleFunc("GET /downloads/"+archiveName, func(writer http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
			return
		case <-time.After(release.DownloadDelay):
		}
		http.ServeFile(writer, request, archivePath)
	})
	mux.HandleFunc("GET /downloads/checksums.txt", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(writer, checksum)
	})
	mux.HandleFunc("GET /release-notes", func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, releaseURL, http.StatusFound)
	})
	feed.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = feed.server.Serve(listener) }()
	return feed, nil
}

func archiveBinary(binary, archivePath string) error {
	source, err := os.Open(binary)
	if err != nil {
		return err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	destination, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer destination.Close()
	compressed := gzip.NewWriter(destination)
	defer compressed.Close()
	archive := tar.NewWriter(compressed)
	defer archive.Close()
	if err := archive.WriteHeader(&tar.Header{Name: "sable", Mode: 0o755, Size: info.Size()}); err != nil {
		return err
	}
	if _, err := io.Copy(archive, source); err != nil {
		return err
	}
	if err := archive.Close(); err != nil {
		return err
	}
	if err := compressed.Close(); err != nil {
		return err
	}
	return destination.Close()
}
