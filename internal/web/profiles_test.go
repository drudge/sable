package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/auth"
)

func TestDebugProfileNeedsMetricsRead(t *testing.T) {
	t.Parallel()
	current := routeAt(t, http.MethodGet, "/api/v1/debug/pprof/heap")
	if current.perm != auth.PermissionMetricsRead || current.public {
		t.Fatalf("profile route perm = %q public = %t, want metrics.read", current.perm, current.public)
	}
}

func TestDebugProfileServesSnapshotsOnly(t *testing.T) {
	t.Parallel()
	server := &Server{}
	serve := func(target string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.SetPathValue("profile", strings.TrimPrefix(strings.SplitN(target, "?", 2)[0], "/api/v1/debug/pprof/"))
		recorder := httptest.NewRecorder()
		server.debugProfile(recorder, request)
		return recorder
	}
	heap := serve("/api/v1/debug/pprof/heap?gc=1")
	if heap.Code != http.StatusOK || heap.Header().Get("Content-Type") != "application/octet-stream" || heap.Body.Len() == 0 {
		t.Fatalf("heap profile = %d %q, %d bytes", heap.Code, heap.Header().Get("Content-Type"), heap.Body.Len())
	}
	goroutines := serve("/api/v1/debug/pprof/goroutine?debug=1")
	if goroutines.Code != http.StatusOK || !strings.Contains(goroutines.Body.String(), "goroutine profile:") {
		t.Fatalf("goroutine profile = %d %q", goroutines.Code, goroutines.Body.String())
	}
	for _, name := range []string{"profile", "trace", "block", "mutex", "nope"} {
		if response := serve("/api/v1/debug/pprof/" + name); response.Code != http.StatusNotFound {
			t.Errorf("%s profile = %d, want 404", name, response.Code)
		}
	}
}
