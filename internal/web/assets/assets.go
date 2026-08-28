package assets

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	assetPrefix          = "/assets/"
	fingerprintHexLength = 16
	immutableCachePolicy = "public, max-age=31536000, immutable"
	legacyCachePolicy    = "no-cache"
)

//go:embed app.css app.js bootstrap.js htmx.min.js sable-headshot.png sable-icon-180.png sable-mark.svg
var files embed.FS

type asset struct {
	content     []byte
	compressed  []byte
	fingerprint string
	digest      string
	contentType string
}

var manifest = loadManifest()

func loadManifest() map[string]asset {
	names := []string{
		"app.css", "app.js", "bootstrap.js", "htmx.min.js",
		"sable-headshot.png", "sable-icon-180.png", "sable-mark.svg",
	}
	loaded := make(map[string]asset, len(names))
	for _, name := range names {
		content, err := files.ReadFile(name)
		if err != nil {
			panic(fmt.Sprintf("read embedded web asset %s: %v", name, err))
		}
		sum := sha256.Sum256(content)
		digest := hex.EncodeToString(sum[:])
		compressed := gzipAsset(content)
		if len(compressed) >= len(content) {
			compressed = nil
		}
		contentType := mime.TypeByExtension(filepath.Ext(name))
		switch filepath.Ext(name) {
		case ".css":
			contentType = "text/css; charset=utf-8"
		case ".js":
			contentType = "text/javascript; charset=utf-8"
		case ".svg":
			contentType = "image/svg+xml"
		}
		loaded[name] = asset{
			content: content, compressed: compressed,
			fingerprint: digest[:fingerprintHexLength], digest: digest,
			contentType: contentType,
		}
	}
	return loaded
}

func gzipAsset(content []byte) []byte {
	var output bytes.Buffer
	writer, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		panic(fmt.Sprintf("create web asset compressor: %v", err))
	}
	if _, err := writer.Write(content); err != nil {
		panic(fmt.Sprintf("compress web asset: %v", err))
	}
	if err := writer.Close(); err != nil {
		panic(fmt.Sprintf("finish web asset compression: %v", err))
	}
	return output.Bytes()
}

// URL returns the immutable, content-addressed path for an embedded asset.
func URL(name string) string {
	entry, found := manifest[name]
	if !found {
		return assetPrefix + name
	}
	return assetPrefix + entry.fingerprint + "/" + name
}

// Handler serves embedded assets with content-addressed caching, validators,
// and precompressed representations. Legacy unversioned paths remain usable
// with revalidation so external bookmarks do not break across an upgrade.
func Handler() http.Handler {
	return http.HandlerFunc(serve)
}

func serve(writer http.ResponseWriter, request *http.Request) {
	relative := strings.TrimPrefix(request.URL.Path, assetPrefix)
	parts := strings.Split(relative, "/")
	name := ""
	fingerprinted := false
	switch len(parts) {
	case 1:
		name = parts[0]
	case 2:
		fingerprinted = true
		name = parts[1]
	default:
		http.NotFound(writer, request)
		return
	}
	entry, found := manifest[name]
	if !found || fingerprinted && parts[0] != entry.fingerprint {
		http.NotFound(writer, request)
		return
	}

	content := entry.content
	encoding := ""
	if len(entry.compressed) > 0 {
		writer.Header().Set("Vary", "Accept-Encoding")
		if acceptsGzip(request.Header.Get("Accept-Encoding")) {
			content = entry.compressed
			encoding = "gzip"
			writer.Header().Set("Content-Encoding", encoding)
		}
	}
	etag := `"` + entry.digest
	if encoding != "" {
		etag += "-" + encoding
	}
	etag += `"`
	writer.Header().Set("ETag", etag)
	writer.Header().Set("Content-Type", entry.contentType)
	if fingerprinted {
		writer.Header().Set("Cache-Control", immutableCachePolicy)
	} else {
		writer.Header().Set("Cache-Control", legacyCachePolicy)
	}
	if matchesETag(request.Header.Get("If-None-Match"), etag) {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	writer.Header().Set("Content-Length", strconv.Itoa(len(content)))
	if request.Method != http.MethodHead {
		_, _ = writer.Write(content)
	}
}

func acceptsGzip(header string) bool {
	for _, item := range strings.Split(header, ",") {
		parts := strings.Split(item, ";")
		if !strings.EqualFold(strings.TrimSpace(parts[0]), "gzip") {
			continue
		}
		for _, parameter := range parts[1:] {
			name, value, found := strings.Cut(strings.TrimSpace(parameter), "=")
			if found && strings.EqualFold(name, "q") {
				quality, err := strconv.ParseFloat(value, 64)
				return err == nil && quality > 0 && quality <= 1
			}
		}
		return true
	}
	return false
}

func matchesETag(header, target string) bool {
	for _, value := range strings.Split(header, ",") {
		value = strings.TrimSpace(value)
		if value == "*" || value == target {
			return true
		}
	}
	return false
}
