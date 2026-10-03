package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/drudge/sable/internal/auth"
)

var testRouter = sync.OnceValue(func() *http.ServeMux {
	mux := http.NewServeMux()
	for pattern := range routesByPattern {
		mux.Handle(pattern, http.NotFoundHandler())
	}
	return mux
})

// routeFor finds the route the console serves a request with, or nil when
// none matches.
func routeFor(request *http.Request) *route {
	_, pattern := testRouter().Handler(request)
	return routesByPattern[pattern]
}

func routeAt(t *testing.T, method, path string) *route {
	t.Helper()
	current := routeFor(httptest.NewRequest(method, path, nil))
	if current == nil {
		t.Fatalf("no route serves %s %s", method, path)
	}
	return current
}

// accessControl serves handler behind the access policy of the route the
// request matches, as the console does.
func (server *Server) accessControl(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current := routeFor(request)
		if current == nil {
			http.NotFound(writer, request)
			return
		}
		if request, allowed := server.authorizeRoute(writer, request, current); allowed {
			handler.ServeHTTP(writer, request)
		}
	})
}

func TestEveryRouteDeclaresItsAccess(t *testing.T) {
	t.Parallel()
	routes := routeTable()
	if len(routes) != len(routesByPattern) {
		t.Fatalf("%d routes declared, %d registered", len(routes), len(routesByPattern))
	}
	for _, current := range routes {
		if err := current.policyError(); err != nil {
			t.Error(err)
		}
		method, path, _ := strings.Cut(current.pattern, " ")
		zoneWrite := !safeMethod(method) && (strings.HasPrefix(path, "/ui/zones") || strings.HasPrefix(path, "/api/v1/zones"))
		if zoneWrite && current.zone.action == "" {
			t.Errorf("%s changes zones without declaring its zone action", current.pattern)
		}
		if current.zone.action != "" && !current.zone.create && len(current.zone.perms) == 0 {
			t.Errorf("%s declares a zone action without the permissions it needs", current.pattern)
		}
	}
}

func TestRouteWithoutAnAccessPolicyIsRefused(t *testing.T) {
	t.Parallel()
	for _, current := range []route{
		{pattern: "GET /forgotten"},
		{pattern: "GET /both", public: true, perm: auth.PermissionSettingsRead},
		{pattern: "POST /ui/zones/sneaky", perm: auth.PermissionZonesRead, zone: zoneMutation{action: "zone.sneaky"}},
	} {
		if current.policyError() == nil {
			t.Errorf("%s was accepted", current.pattern)
		}
	}
}

func TestZoneMutationWithoutPermissionsIsForbidden(t *testing.T) {
	t.Parallel()
	server := &Server{securityEnabled: true}
	request := httptest.NewRequest(http.MethodPost, "/ui/zones/unknown", nil)
	if err := server.authorizeZoneMutation(request); err != auth.ErrForbidden {
		t.Fatalf("undeclared zone mutation = %v, want forbidden", err)
	}
}

func TestRouteBodyLimitAppliesToEveryWrite(t *testing.T) {
	t.Parallel()
	server := &Server{}
	read := func(current *route, size int) error {
		var readErr error
		current.handler = func(_ *Server, _ http.ResponseWriter, request *http.Request) {
			_, readErr = io.ReadAll(request.Body)
		}
		request := httptest.NewRequest(http.MethodPost, "/ui/profile/password", strings.NewReader(strings.Repeat("a", size)))
		server.routeHandler(current).ServeHTTP(httptest.NewRecorder(), request)
		return readErr
	}
	if err := read(&route{signedIn: true}, maximumFormBytes+1); err == nil {
		t.Fatal("a form past the default limit was read")
	}
	if err := read(&route{signedIn: true}, maximumFormBytes); err != nil {
		t.Fatalf("a form at the default limit failed: %v", err)
	}
	if err := read(&route{signedIn: true, bodyLimit: maximumDomainImportBytes}, maximumFormBytes+1); err != nil {
		t.Fatalf("a route's own limit was not used: %v", err)
	}
}

func TestUploadRoutesGetTheLongBodyWindow(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/ui/backup/restore",
		"/ui/zones/import",
		"/ui/zones/import-new",
		"/ui/blocking/domains/import",
		"/ui/blocking/allowed/import",
	} {
		if timeout := routeAt(t, http.MethodPost, path).bodyTimeout; timeout != webReadTimeout {
			t.Errorf("%s body timeout = %s, want %s", path, timeout, webReadTimeout)
		}
	}
	for _, path := range []string{"/setup", "/login", "/api/v1/cluster/enroll"} {
		if timeout := routeAt(t, http.MethodPost, path).bodyTimeout; timeout != 0 {
			t.Errorf("%s body timeout = %s, want the server default", path, timeout)
		}
	}
}

func TestMCPToolWithoutItsGrantIsRefusedBeforeItRuns(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	before := len(configuration.zoneSnapshot.Zones)
	_, failure := callMCPToolForTest(t, server, "sable_pat_metrics", "list_zones", map[string]any{})
	if failure != "this token needs zones.read to use list_zones" {
		t.Fatalf("list_zones without zones.read = %q", failure)
	}
	_, failure = callMCPToolForTest(t, server, "sable_pat_settings", "purge_cache", map[string]any{"name": "www.example.test"})
	if failure != "this token needs settings.write to use purge_cache" {
		t.Fatalf("purge_cache without settings.write = %q", failure)
	}
	if len(configuration.zoneSnapshot.Zones) != before {
		t.Fatal("a refused tool changed the zones")
	}
	if use := server.lastMCPUse(t.Context()); use.Tool != "" {
		t.Fatalf("a refused call was counted as use of %s", use.Tool)
	}
	// A zone grant that covers only some zones still opens a zone tool,
	// which then checks the zone it is asked about.
	if _, failure := callMCPToolForTest(t, server, "sable_pat_reader", "list_zones", map[string]any{}); failure != "" {
		t.Fatalf("scoped reader was refused: %s", failure)
	}
}
