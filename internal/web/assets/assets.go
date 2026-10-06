package assets

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	assetPrefix          = "/assets/"
	fingerprintHexLength = 16
	immutableCachePolicy = "public, max-age=31536000, immutable"
	legacyCachePolicy    = "no-cache"
)

// Each asset is embedded as a string, which stays in the binary's read-only
// data. Reading it from an embed.FS would copy every file onto the heap.
var (
	//go:embed inter-latin.woff2
	interLatin string
	//go:embed inter-extra.woff2
	interExtra string
	//go:embed app.css
	appCSS string
	//go:embed app.js
	appJS string
	//go:embed passkeys.js
	passkeysJS string
	//go:embed bootstrap.js
	bootstrapJS string
	//go:embed htmx.min.js
	htmxJS string
	//go:embed sw.js
	serviceWorkerJS string
	//go:embed sable-headshot.png
	headshotPNG string
	//go:embed sable-icon-180.png
	iconPNG string
	//go:embed sable-mark.svg
	markSVG string
)

type embeddedFile struct {
	name    string
	content string
}

// The fonts come before the stylesheet, which links them by fingerprint.
var embeddedFiles = []embeddedFile{
	{"inter-latin.woff2", interLatin}, {"inter-extra.woff2", interExtra},
	{"app.css", appCSS}, {"app.js", appJS}, {"passkeys.js", passkeysJS},
	{"bootstrap.js", bootstrapJS}, {"htmx.min.js", htmxJS}, {"sw.js", serviceWorkerJS},
	{"sable-headshot.png", headshotPNG}, {"sable-icon-180.png", iconPNG}, {"sable-mark.svg", markSVG},
}

// contentTypes names each embedded type directly. mime.TypeByExtension would
// read the host's mime.types into a table on first use, thousands of
// allocations at package init that vary with the host.
var contentTypes = map[string]string{
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".png":   "image/png",
	".svg":   "image/svg+xml",
	".woff2": "font/woff2",
}

type asset struct {
	content     string
	fingerprint string
	digest      string
	contentType string
}

var manifest = loadManifest()

// gzipped holds the gzip encoding of every asset that shrinks under it. It is
// built on the first request that needs it rather than at package init, so a
// process that never serves the console, including every CLI subcommand,
// never pays for a compressor.
var gzipped = sync.OnceValue(compressManifest)

func loadManifest() map[string]asset {
	loaded := make(map[string]asset, len(embeddedFiles))
	chunk := make([]byte, writeChunkSize)
	for _, file := range embeddedFiles {
		content := file.content
		if filepath.Ext(file.name) == ".css" {
			content = linkAssets(content, loaded)
		}
		hash := sha256.New()
		writeString(hash, content, chunk)
		digest := hex.EncodeToString(hash.Sum(nil))
		contentType, found := contentTypes[filepath.Ext(file.name)]
		if !found {
			panic("no content type for web asset " + file.name)
		}
		loaded[file.name] = asset{
			content:     content,
			fingerprint: digest[:fingerprintHexLength], digest: digest,
			contentType: contentType,
		}
	}
	return loaded
}

// linkAssets points a stylesheet's url("name") references at the fingerprinted
// paths of assets already loaded. The fonts it names are then cached as long
// as it is, and a changed font changes the stylesheet's fingerprint too.
func linkAssets(stylesheet string, loaded map[string]asset) string {
	pairs := make([]string, 0, 2*len(loaded))
	for name, entry := range loaded {
		pairs = append(pairs, `url("`+name+`")`, `url("`+assetPrefix+entry.fingerprint+"/"+name+`")`)
	}
	// Each link only lengthens a url() by its fingerprint directory, so a
	// little headroom keeps the builder from regrowing a copy of the sheet.
	var linked strings.Builder
	linked.Grow(len(stylesheet) + 1024)
	_, _ = strings.NewReplacer(pairs...).WriteString(&linked, stylesheet)
	return linked.String()
}

// compressManifest gzips each asset with one reused compressor. Fonts and PNGs
// are already compressed, so they are skipped, as is any asset gzip doesn't
// shrink.
func compressManifest() map[string]string {
	var output bytes.Buffer
	writer, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		panic(fmt.Sprintf("create web asset compressor: %v", err))
	}
	chunk := make([]byte, writeChunkSize)
	encoded := make(map[string]string, len(manifest))
	for name, entry := range manifest {
		switch filepath.Ext(name) {
		case ".woff2", ".png":
			continue
		}
		output.Reset()
		writer.Reset(&output)
		writeString(writer, entry.content, chunk)
		if err := writer.Close(); err != nil {
			panic(fmt.Sprintf("compress web asset %s: %v", name, err))
		}
		if output.Len() < len(entry.content) {
			encoded[name] = output.String()
		}
	}
	return encoded
}

const writeChunkSize = 32 << 10

// writeString feeds content to a hash or compressor through chunk, so a large
// asset is never copied whole just to become a []byte. Neither writer fails
// on Write; the compressor reports any error from Close.
func writeString(writer io.Writer, content string, chunk []byte) {
	for len(content) > 0 {
		n := copy(chunk, content)
		_, _ = writer.Write(chunk[:n])
		content = content[n:]
	}
}

// URL returns the immutable, content-addressed path for an embedded asset.
func URL(name string) string {
	entry, found := manifest[name]
	if !found {
		return assetPrefix + name
	}
	return assetPrefix + entry.fingerprint + "/" + name
}

// Root serves one embedded asset at a fixed path outside /assets/, for files
// a browser looks for by name, such as a service worker, whose path sets what
// it controls and which must never be cached past an update.
func Root(name string) http.Handler {
	entry, found := manifest[name]
	if !found {
		panic("serve unknown web asset " + name)
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", entry.contentType)
		writer.Header().Set("Cache-Control", legacyCachePolicy)
		writer.Header().Set("ETag", `"`+entry.digest+`"`)
		http.ServeContent(writer, request, name, time.Time{}, strings.NewReader(entry.content))
	})
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
	if compressed, ok := gzipped()[name]; ok {
		writer.Header().Set("Vary", "Accept-Encoding")
		if acceptsGzip(request.Header.Get("Accept-Encoding")) {
			content = compressed
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
		_, _ = io.WriteString(writer, content)
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
