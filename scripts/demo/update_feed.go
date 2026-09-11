package main

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

const updateDemoNotes = `## Update demonstration

These are local demonstration builds of the current source, labeled 1.0.1 and 1.0.2. They are not the published GitHub binaries.

### What's new
- Check for updates automatically after sign-in, with an option to turn checks off.
- Read release notes directly in the console and follow version links to GitHub.
- Update replicas one at a time, verify synchronization, and restart the primary last.

### Try it
Open **Cluster**, choose **Update all**, and watch the rollout. The terminal probes DNS throughout the update.

This feed uses curated release notes; merge commits and raw commit lists are excluded.
`

type updateDemoFeed struct {
	URL    string
	server *http.Server
}

func (feed *updateDemoFeed) Close() { _ = feed.server.Close() }

func startUpdateDemoFeed(workspace, target string) (*updateDemoFeed, error) {
	archiveName := fmt.Sprintf("sable_%s_%s_%s.tar.gz", updateDemoTarget, runtime.GOOS, runtime.GOARCH)
	archivePath := filepath.Join(workspace, "build", archiveName)
	if err := archiveUpdateDemoBinary(target, archivePath); err != nil {
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
	feed := &updateDemoFeed{URL: "http://" + listener.Addr().String()}
	metadata := map[string]any{
		"tag_name": "v" + updateDemoTarget, "draft": false, "prerelease": false,
		"html_url": feed.URL + "/release-notes", "body": updateDemoNotes,
		"assets": []map[string]any{
			{"name": archiveName, "size": len(archive), "browser_download_url": feed.URL + "/downloads/" + archiveName},
			{"name": "checksums.txt", "size": len(checksum), "browser_download_url": feed.URL + "/downloads/checksums.txt"},
		},
	}
	mux := http.NewServeMux()
	for _, path := range []string{"/repos/drudge/sable/releases/latest", "/repos/drudge/sable/releases/tags/v" + updateDemoTarget} {
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
		// A short delay makes each installation visible in the console.
		select {
		case <-request.Context().Done():
			return
		case <-time.After(3 * time.Second):
		}
		http.ServeFile(writer, request, archivePath)
	})
	mux.HandleFunc("GET /downloads/checksums.txt", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(writer, checksum)
	})
	mux.HandleFunc("GET /release-notes", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(writer, updateDemoNotes)
	})
	feed.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = feed.server.Serve(listener) }()
	return feed, nil
}

func archiveUpdateDemoBinary(binary, archivePath string) error {
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
