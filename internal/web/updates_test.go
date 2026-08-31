package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/update"
)

// testUpdateController reports a fixed release state and records what the
// console asked it to do.
type testUpdateController struct {
	mutex          sync.Mutex
	status         update.Status
	checkError     error
	installError   error
	serviceManaged bool
	checks         int
	installs       int
	preRelease     bool
}

func (controller *testUpdateController) Status() update.Status {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	return controller.status
}

func (controller *testUpdateController) Check(_ context.Context, preRelease bool) (update.Status, error) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	controller.checks++
	controller.preRelease = preRelease
	return controller.status, controller.checkError
}

func (controller *testUpdateController) Install(preRelease bool) error {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	if controller.installError != nil {
		return controller.installError
	}
	controller.installs++
	controller.preRelease = preRelease
	controller.status = update.Status{
		Phase: update.PhaseInstalling, CurrentVersion: controller.status.CurrentVersion,
		LatestVersion: controller.status.LatestVersion, IncludePreRelease: preRelease,
		Progress: "Downloading sable_9.9.9_linux_amd64.tar.gz...", CheckedAt: time.Now(),
	}
	return nil
}

func (controller *testUpdateController) ServiceManaged() bool { return controller.serviceManaged }

func updateTestServer(t *testing.T, controller updateController) *Server {
	t.Helper()
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		testConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}},
		testZones{}, "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	server.SetUpdateController(controller)
	return server
}

func serveUpdateForm(server *Server, target string, form url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	return response
}

func TestAboutPageOffersAnAvailableRelease(t *testing.T) {
	t.Parallel()
	server := updateTestServer(t, &testUpdateController{status: update.Status{
		Phase: update.PhaseIdle, CurrentVersion: "0.7.0", LatestVersion: "9.9.9",
		ReleaseURL: "https://github.com/drudge/sable/releases/tag/v9.9.9",
		Available:  true, CheckedAt: time.Now(),
	}})
	body := serveRequest(server, http.MethodGet, "/about").Body.String()
	for _, expected := range []string{
		"Sable v9.9.9 is available",
		`hx-post="/ui/updates/install"`,
		"Download &amp; Install",
		"Install v9.9.9",
		"https://github.com/drudge/sable/releases/tag/v9.9.9",
		"Install this release?",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("about page does not contain %q", expected)
		}
	}
}

func TestAboutPageReportsAnUpToDateInstallation(t *testing.T) {
	t.Parallel()
	server := updateTestServer(t, &testUpdateController{status: update.Status{
		Phase: update.PhaseIdle, CurrentVersion: "9.9.9", LatestVersion: "9.9.9", CheckedAt: time.Now(),
	}})
	body := serveRequest(server, http.MethodGet, "/about").Body.String()
	if !strings.Contains(body, "Sable is up to date") {
		t.Error("about page does not report an up-to-date installation")
	}
	if strings.Contains(body, `hx-post="/ui/updates/install"`) {
		t.Error("about page offers an installation without an available release")
	}
}

func TestCommandPaletteUpdateCheckReturnsToast(t *testing.T) {
	t.Parallel()
	controller := &testUpdateController{status: update.Status{
		Phase: update.PhaseIdle, CurrentVersion: "0.7.0", LatestVersion: "9.9.9",
		Available: true, CheckedAt: time.Now(),
	}}
	server := updateTestServer(t, controller)
	response := serveUpdateForm(server, "/ui/updates/command-check", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("palette update check status = %d", response.Code)
	}
	body := response.Body.String()
	for _, expected := range []string{`class="toast-region"`, "Sable v9.9.9 is available. Open About to review and install it."} {
		if !strings.Contains(body, expected) {
			t.Errorf("palette update check does not contain %q: %s", expected, body)
		}
	}
	if strings.Contains(body, `id="about-update"`) {
		t.Error("palette update check returned the About page panel instead of a toast")
	}
	if controller.checks != 1 || controller.preRelease {
		t.Fatalf("palette update checks = %d pre-release = %t", controller.checks, controller.preRelease)
	}
}

func TestCommandPaletteUpdateCheckReportsUnavailableController(t *testing.T) {
	t.Parallel()
	server := updateTestServer(t, nil)
	response := serveUpdateForm(server, "/ui/updates/command-check", nil)
	if response.Code != http.StatusNotImplemented || !strings.Contains(response.Body.String(), "Updates are unavailable on this server.") {
		t.Fatalf("unavailable palette update check = %d %s", response.Code, response.Body.String())
	}
}

func TestCheckForUpdatesForwardsThePreReleaseChoice(t *testing.T) {
	t.Parallel()
	controller := &testUpdateController{status: update.Status{
		Phase: update.PhaseIdle, CurrentVersion: "0.7.0-rc.1", LatestVersion: "0.7.0-rc.2",
		Available: true, PreRelease: true, IncludePreRelease: true, CheckedAt: time.Now(),
	}}
	server := updateTestServer(t, controller)
	response := serveUpdateForm(server, "/ui/updates/check", url.Values{"pre_release": {"true"}})
	if response.Code != http.StatusOK {
		t.Fatalf("check status = %d", response.Code)
	}
	if controller.checks != 1 || !controller.preRelease {
		t.Fatalf("checks = %d, pre-release = %v", controller.checks, controller.preRelease)
	}
	if !strings.Contains(response.Body.String(), "Sable v0.7.0-rc.2 is available") {
		t.Errorf("panel does not report the pre-release: %s", response.Body.String())
	}
}

func TestInstallUpdateStartsTheInstallationAndReportsProgress(t *testing.T) {
	t.Parallel()
	controller := &testUpdateController{status: update.Status{
		Phase: update.PhaseIdle, CurrentVersion: "0.7.0", LatestVersion: "9.9.9", Available: true, CheckedAt: time.Now(),
	}}
	server := updateTestServer(t, controller)
	response := serveUpdateForm(server, "/ui/updates/install", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("install status = %d", response.Code)
	}
	if controller.installs != 1 || controller.preRelease {
		t.Fatalf("installs = %d, pre-release = %v", controller.installs, controller.preRelease)
	}
	body := response.Body.String()
	for _, expected := range []string{
		"Installing Sable v9.9.9",
		"Downloading sable_9.9.9_linux_amd64.tar.gz...",
		`hx-get="/ui/updates"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("panel does not contain %q: %s", expected, body)
		}
	}
}

func TestInstallUpdateReportsAConcurrentInstallation(t *testing.T) {
	t.Parallel()
	controller := &testUpdateController{installError: update.ErrUpdateInProgress}
	server := updateTestServer(t, controller)
	response := serveUpdateForm(server, "/ui/updates/install", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("install status = %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), update.ErrUpdateInProgress.Error()) {
		t.Errorf("panel does not report the running installation: %s", response.Body.String())
	}
}

func TestInstalledUpdateOffersAConfirmedRestart(t *testing.T) {
	t.Parallel()
	server := updateTestServer(t, &testUpdateController{
		serviceManaged: true,
		status: update.Status{
			Phase: update.PhaseInstalled, CurrentVersion: "0.7.0", LatestVersion: "9.9.9",
			Available: true, Installed: true, CheckedAt: time.Now(),
		},
	})
	server.SetRestartController(func() {})
	body := serveRequest(server, http.MethodGet, "/about").Body.String()
	for _, expected := range []string{
		"Sable v9.9.9 is installed",
		"data-sable-restart",
		`data-restart-url="/ui/updates/restart"`,
		"data-restart-confirm",
		"Restart Sable",
		"The service manager starts the new build after a restart.",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("about page does not contain %q", expected)
		}
	}
	if strings.Contains(body, `hx-post="/ui/updates/check"`) {
		t.Error("about page offers a release check while an installed build waits for a restart")
	}
}

func TestAboutPageReportsUnavailableUpdates(t *testing.T) {
	t.Parallel()
	server := updateTestServer(t, nil)
	server.updates = nil
	body := serveRequest(server, http.MethodGet, "/about").Body.String()
	if !strings.Contains(body, "Update checks are unavailable") {
		t.Error("about page does not report that updates are unavailable")
	}
	if strings.Contains(body, `hx-post="/ui/updates/check"`) {
		t.Error("about page offers a release check without an update controller")
	}
}

func TestUpdateViewSeparatesReadingFromApplying(t *testing.T) {
	t.Parallel()
	server := updateTestServer(t, &testUpdateController{status: update.Status{Phase: update.PhaseIdle}})
	server.securityEnabled = true
	server.SetRestartController(func() {})
	reader := auth.Principal{UserID: 2, Username: "auditor", Permissions: []string{auth.PermissionUpdatesRead}}
	request := httptest.NewRequest(http.MethodGet, "/about", nil)
	view := server.updateView(request.WithContext(
		context.WithValue(request.Context(), principalContextKey{}, reader),
	), server.updateStatus())
	if !view.CanCheck || view.CanApply || view.CanRestart {
		t.Fatalf("read-only view = %+v", view)
	}
	operator := auth.Principal{UserID: 1, Username: "admin", Permissions: []string{auth.PermissionAll}}
	view = server.updateView(request.WithContext(
		context.WithValue(request.Context(), principalContextKey{}, operator),
	), server.updateStatus())
	if !view.CanCheck || !view.CanApply || !view.CanRestart {
		t.Fatalf("administrator view = %+v", view)
	}
}

func TestAboutPageExplainsAnInstallationItCannotApply(t *testing.T) {
	t.Parallel()
	server := updateTestServer(t, &testUpdateController{status: update.Status{
		Phase: update.PhaseIdle, CurrentVersion: "0.7.0", LatestVersion: "9.9.9",
		ReleaseURL: "https://github.com/drudge/sable/releases/tag/v9.9.9",
		Available:  true, CheckedAt: time.Now(),
		Blocked: "/usr/local/bin is read-only for the running server, so it cannot replace its own executable. " +
			"Install this release with sudo sable update, or by pulling a newer container image.",
	}})
	body := serveRequest(server, http.MethodGet, "/about").Body.String()
	if !strings.Contains(body, "Sable v9.9.9 is available") {
		t.Error("about page does not report the available release")
	}
	if !strings.Contains(body, "read-only for the running server") {
		t.Error("about page does not explain why it cannot install the release")
	}
	if strings.Contains(body, `hx-post="/ui/updates/install"`) {
		t.Error("about page offers an installation it cannot apply")
	}
}

func TestCheckForUpdatesRemembersThePreReleaseChoice(t *testing.T) {
	t.Parallel()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	server, err := New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		testStats{snapshot: dnsserver.Stats{StartedAt: time.Now()}},
		configuration, configuration.zoneStore(), "sqlite", testQueryLog{}, testQueryLog{},
		func(context.Context) error { return nil }, nil, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	server.SetUpdateController(&testUpdateController{status: update.Status{
		Phase: update.PhaseIdle, CurrentVersion: "0.7.0-rc.1", LatestVersion: "0.7.0-rc.1",
		IncludePreRelease: true, CheckedAt: time.Now(),
	}})
	if configuration.snapshot.Config.Updates.PreRelease {
		t.Fatal("pre-releases should be off by default")
	}
	if response := serveUpdateForm(server, "/ui/updates/check", url.Values{"pre_release": {"true"}}); response.Code != http.StatusOK {
		t.Fatalf("check status = %d", response.Code)
	}
	if !configuration.snapshot.Config.Updates.PreRelease {
		t.Fatal("the pre-release choice was not written to the configuration")
	}
	// A restarted server seeds its manager from the stored configuration.
	restarted := update.NewManager(update.Options{PreRelease: configuration.snapshot.Config.Updates.PreRelease})
	if !restarted.Status().IncludePreRelease {
		t.Fatal("a restarted server did not resume checking pre-releases")
	}
	if response := serveUpdateForm(server, "/ui/updates/check", nil); response.Code != http.StatusOK {
		t.Fatalf("check status = %d", response.Code)
	}
	if configuration.snapshot.Config.Updates.PreRelease {
		t.Fatal("clearing the checkbox did not return the server to stable releases")
	}
}
