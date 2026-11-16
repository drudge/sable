package web

import (
	"net/http"
	"runtime"
	"runtime/pprof"
	"strconv"
)

// debugProfiles are the runtime profiles the API serves. Each is a snapshot
// that costs little to take, so none of them slows DNS. CPU profiles and
// execution traces are left out because they run for as long as they are
// asked to.
var debugProfiles = map[string]bool{
	"heap":         true,
	"allocs":       true,
	"goroutine":    true,
	"threadcreate": true,
}

// debugProfile writes one runtime profile in the pprof format, for
// `go tool pprof`, or as text with debug=1 (or debug=2 for full goroutine
// stacks). gc=1 collects garbage first so a heap profile shows only what is
// still live.
func (server *Server) debugProfile(writer http.ResponseWriter, request *http.Request) {
	name := request.PathValue("profile")
	profile := pprof.Lookup(name)
	if !debugProfiles[name] || profile == nil {
		http.Error(writer, "unknown profile", http.StatusNotFound)
		return
	}
	debug, err := strconv.Atoi(request.URL.Query().Get("debug"))
	if err != nil || debug < 0 || debug > 2 {
		debug = 0
	}
	if name == "heap" && request.URL.Query().Get("gc") == "1" {
		runtime.GC()
	}
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Cache-Control", "no-store")
	if debug == 0 {
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.Header().Set("Content-Disposition", `attachment; filename="sable-`+name+`.pprof"`)
	} else {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	_ = profile.WriteTo(writer, debug)
}
