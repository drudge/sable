package web

import (
	"context"
	"errors"
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
	"github.com/drudge/sable/internal/cluster"
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
	if strings.Contains(body, `hx-post="/ui/updates/check"`) {
		t.Error("about page offers a redundant release check while an update is available")
	}
}

func TestDevelopmentUpdatesAreDisabledInTheConsoleAndDirectRequests(t *testing.T) {
	t.Parallel()
	server := updateTestServer(t, update.NewManager(update.Options{}))
	for _, endpoint := range []string{"/about", "/ui/updates/check", "/ui/updates/install", "/ui/updates/command-check"} {
		var response *httptest.ResponseRecorder
		if endpoint == "/about" {
			response = serveRequest(server, http.MethodGet, endpoint)
		} else {
			response = serveUpdateForm(server, endpoint, url.Values{"pre_release": {"true"}})
		}
		body := response.Body.String()
		if response.Code != http.StatusOK || !strings.Contains(body, "disabled for development builds") {
			t.Errorf("%s = %d %s, want development build explanation", endpoint, response.Code, body)
		}
		for _, forbidden := range []string{`hx-post="/ui/updates/install"`, `hx-post="/ui/updates/check"`, "is available", "up to date", "Open About to review and install"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s offers an update for a development build: %s", endpoint, forbidden)
			}
		}
	}
	status := server.updates.Status()
	if status.Busy() || status.Installed || status.Checked() || !status.Development {
		t.Fatalf("development request changed update state: %+v", status)
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

func TestCommandPaletteUpdateCheckReturnsUpdateNotification(t *testing.T) {
	t.Parallel()
	controller := &testUpdateController{status: update.Status{
		Phase: update.PhaseIdle, CurrentVersion: "0.7.0", LatestVersion: "9.9.9",
		Available: true, CheckedAt: time.Now(), ReleaseNotes: "### Improvements\n\n- Faster updates.",
	}}
	server := updateTestServer(t, controller)
	response := serveUpdateForm(server, "/ui/updates/command-check", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("palette update check status = %d", response.Code)
	}
	body := response.Body.String()
	for _, expected := range []string{
		`id="update-notification"`, "Sable v9.9.9 is available", `data-toast-duration="0"`,
		`data-dialog-open="notification-release-notes-dialog"`, "Faster updates.",
		`hx-post="/ui/updates/install"`, `name="notification" value="true"`, "Install update",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("palette update check does not contain %q: %s", expected, body)
		}
	}
	if strings.Contains(body, `id="about-update"`) || strings.Contains(body, "Open About to review and install") {
		t.Error("palette update check did not offer the update directly in the notification")
	}
	if controller.checks != 1 || controller.preRelease {
		t.Fatalf("palette update checks = %d pre-release = %t", controller.checks, controller.preRelease)
	}
}

func TestCommandPaletteUpdateCheckKeepsStatusToasts(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		checkError error
		wantStatus int
		message    string
	}{
		{name: "up to date", wantStatus: http.StatusOK, message: "Sable is up to date."},
		{name: "failed check", checkError: errors.New("release feed unavailable"), wantStatus: http.StatusBadGateway, message: "release feed unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := updateTestServer(t, &testUpdateController{
				status:     update.Status{Phase: update.PhaseIdle, CurrentVersion: "9.9.9", LatestVersion: "9.9.9", CheckedAt: time.Now()},
				checkError: test.checkError,
			})
			response := serveUpdateForm(server, "/ui/updates/command-check", nil)
			body := response.Body.String()
			if response.Code != test.wantStatus || !strings.Contains(body, test.message) || !strings.Contains(body, `class="toast-region"`) {
				t.Fatalf("status toast = %d %s", response.Code, body)
			}
			if strings.Contains(body, `id="update-notification"`) || strings.Contains(body, `hx-post="/ui/updates/install"`) {
				t.Fatalf("status toast unexpectedly offered an update: %s", body)
			}
		})
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
		`data-updated-version="v9.9.9"`,
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

func TestReplicaChecksForUpdatesAndRemembersItsLocalReleaseChannel(t *testing.T) {
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
	controller := &testUpdateController{status: update.Status{
		Phase: update.PhaseIdle, CurrentVersion: "0.7.0-rc.1", LatestVersion: "0.7.0-rc.2",
		Available: true, PreRelease: true, IncludePreRelease: true, CheckedAt: time.Now(),
	}}
	server.SetUpdateController(controller)
	server.SetClusterController(testReplicaClusterController{})

	response := serveUpdateForm(server, "/ui/updates/check", url.Values{"pre_release": {"true"}})
	if response.Code != http.StatusOK {
		t.Fatalf("replica check status = %d, body = %s", response.Code, response.Body.String())
	}
	if controller.checks != 1 || !controller.preRelease {
		t.Fatalf("replica checks = %d, pre-release = %v", controller.checks, controller.preRelease)
	}
	if !configuration.snapshot.Config.Updates.PreRelease {
		t.Fatal("replica did not persist its local release channel")
	}
	restarted := update.NewManager(update.Options{PreRelease: configuration.snapshot.Config.Updates.PreRelease})
	if !restarted.Status().IncludePreRelease {
		t.Fatal("replica lost its release channel after restarting")
	}
	response = serveUpdateForm(server, "/ui/updates/command-check", nil)
	if response.Code != http.StatusOK || !controller.preRelease {
		t.Fatalf("replica command check ignored the local release channel: %d %s", response.Code, response.Body.String())
	}
}

func TestReplicaCanInstallAnUpdateLocally(t *testing.T) {
	t.Parallel()
	controller := &testUpdateController{status: update.Status{
		Phase: update.PhaseIdle, CurrentVersion: "1.0.0-rc.10", LatestVersion: "1.0.0-rc.11",
		Available: true, IncludePreRelease: true, CheckedAt: time.Now(),
	}}
	server := updateTestServer(t, controller)
	server.SetClusterController(testReplicaClusterController{})
	response := serveUpdateForm(server, "/ui/updates/install", url.Values{"pre_release": {"true"}})
	if response.Code != http.StatusOK || controller.installs != 1 || !controller.preRelease {
		t.Fatalf("replica install = %d %s, installs = %d", response.Code, response.Body.String(), controller.installs)
	}
}

func TestUpdateReaderCannotPersistTheReleaseChannel(t *testing.T) {
	t.Parallel()
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}}
	server := updateTestServer(t, &testUpdateController{})
	server.config = configuration
	server.SetClusterController(testReplicaClusterController{})
	request := httptest.NewRequest(http.MethodPost, "/ui/updates/check", nil)
	reader := auth.Principal{UserID: 2, Permissions: []string{auth.PermissionUpdatesRead}}
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, reader))
	server.rememberReleaseChannel(request, true)
	if configuration.snapshot.Config.Updates.PreRelease || configuration.snapshot.Revision != 1 {
		t.Fatal("an update reader persisted the release channel")
	}
}

func TestReplicaCanRestartAfterAnUpdate(t *testing.T) {
	t.Parallel()
	server := updateTestServer(t, &testUpdateController{status: update.Status{Phase: update.PhaseInstalled, Installed: true}})
	server.SetClusterController(testReplicaClusterController{})
	restarts := 0
	server.SetRestartController(func() { restarts++ })
	response := serveUpdateForm(server, "/ui/updates/restart", nil)
	if response.Code != http.StatusAccepted || restarts != 1 {
		t.Fatalf("replica restart = %d %s, restarts = %d", response.Code, response.Body.String(), restarts)
	}
}

func (controller *testUpdateController) CheckAutomatically(ctx context.Context, preRelease bool) (update.Status, error) {
	return controller.Check(ctx, preRelease)
}

func TestAutomaticUpdateNoticeHonorsPreferenceAndDevelopmentBuilds(t *testing.T) {
	for _, scenario := range []string{"available", "disabled", "development", "current", "failure"} {
		t.Run(scenario, func(t *testing.T) {
			controller := &testUpdateController{status: update.Status{Available: true, LatestVersion: "1.2.0", ReleaseNotes: "Fix DNS <script>alert(1)</script>"}}
			server := updateTestServer(t, controller)
			configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults()}}
			server.config = configuration
			switch scenario {
			case "disabled":
				configuration.snapshot.Config.Updates.CheckOnLogin = false
			case "development":
				controller.status.Development = true
			case "current":
				controller.status.Available = false
			case "failure":
				controller.status.Error = "GitHub unavailable"
			}
			response := serveUpdateForm(server, "/ui/updates/automatic-check", nil)
			if scenario == "available" {
				if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `hx-post="/ui/updates/install"`) || !strings.Contains(response.Body.String(), `data-dialog-open="notification-release-notes-dialog"`) || strings.Contains(response.Body.String(), "<script>") {
					t.Fatalf("notification = %d %s", response.Code, response.Body.String())
				}
			} else if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
				t.Fatalf("quiet check = %d %s", response.Code, response.Body.String())
			}
			if (scenario == "disabled" || scenario == "development") && controller.checks != 0 {
				t.Fatal("disabled check reached the updater")
			}
		})
	}
}

func TestNotificationInstallTracksDownloadAndOffersRestart(t *testing.T) {
	controller := &testUpdateController{status: update.Status{Available: true, CurrentVersion: "1.1.0", LatestVersion: "1.2.0-rc.1"}}
	server := updateTestServer(t, controller)
	server.SetRestartController(func() {})
	response := serveUpdateForm(server, "/ui/updates/install", url.Values{"notification": {"true"}, "pre_release": {"true"}})
	if response.Code != http.StatusOK || response.Header().Get("HX-Redirect") != "" {
		t.Fatalf("notification install = %d, redirect %q", response.Code, response.Header().Get("HX-Redirect"))
	}
	for _, expected := range []string{`id="update-notification"`, "Installing Sable v1.2.0-rc.1", "Downloading sable_9.9.9_linux_amd64.tar.gz", `hx-get="/ui/updates?notification=true"`, "every 2s", "update-install-progress"} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("download notification is missing %q: %s", expected, response.Body.String())
		}
	}
	if strings.Contains(response.Body.String(), "data-sable-restart-button") || response.Header().Get("HX-Trigger") != "sableUpdateChanged" {
		t.Fatal("download offered an early restart or failed to synchronize other update controls")
	}
	if controller.installs != 1 || !controller.preRelease {
		t.Fatalf("installs = %d, pre-release = %v", controller.installs, controller.preRelease)
	}
	controller.status = update.Status{Phase: update.PhaseInstalled, Installed: true, CurrentVersion: "1.1.0", LatestVersion: "1.2.0-rc.1"}
	response = serveRequest(server, http.MethodGet, "/ui/updates?notification=true")
	for _, expected := range []string{`id="update-notification"`, "Sable v1.2.0-rc.1 is installed", "data-sable-restart-button", `data-restart-url="/ui/updates/restart"`, `data-updated-version="v1.2.0-rc.1"`} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("installed notification is missing %q: %s", expected, response.Body.String())
		}
	}
	if strings.Contains(response.Body.String(), "every 2s") || strings.Contains(response.Body.String(), "update-install-progress") || controller.checks != 0 {
		t.Fatal("installed notification kept polling, showed download progress, or checked for another release")
	}
	controller.status.ClusterUpdate = true
	response = serveRequest(server, http.MethodGet, "/ui/updates?notification=true")
	if strings.Contains(response.Body.String(), "data-sable-restart-button") {
		t.Fatal("notification offered a separate restart during a cluster rollout")
	}
}

func TestNotificationInstallReportsFailureWithoutNavigating(t *testing.T) {
	controller := &testUpdateController{status: update.Status{Available: true, LatestVersion: "1.2.0"}, installError: update.ErrUpdateInProgress}
	server := updateTestServer(t, controller)
	response := serveUpdateForm(server, "/ui/updates/install", url.Values{"notification": {"true"}})
	if response.Header().Get("HX-Redirect") != "" || controller.installs != 0 {
		t.Fatal("failed installation redirected or started an update")
	}
	if !strings.Contains(response.Body.String(), "toast-update-failed") || !strings.Contains(response.Body.String(), update.ErrUpdateInProgress.Error()) || !strings.Contains(response.Body.String(), `hx-post="/ui/updates/install"`) {
		t.Fatalf("notification error = %s", response.Body.String())
	}
}

func TestReplicaCanPersistAutomaticUpdatePreference(t *testing.T) {
	server := updateTestServer(t, &testUpdateController{})
	configuration := &editableTestConfiguration{snapshot: config.Snapshot{Config: config.Defaults()}}
	server.config = configuration
	server.SetClusterController(testReplicaClusterController{})
	if !configuration.snapshot.Config.Updates.CheckOnLogin {
		t.Fatal("automatic checks are not enabled by default")
	}
	for _, enabled := range []bool{false, true} {
		values := url.Values{}
		if enabled {
			values.Set("check_on_login", "true")
		}
		response := serveUpdateForm(server, "/ui/settings/updates", values)
		if response.Code != http.StatusOK || configuration.snapshot.Config.Updates.CheckOnLogin != enabled {
			t.Fatalf("preference = %d %s", response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `id="settings-update-preferences"`) || strings.Contains(response.Body.String(), `id="about-update"`) {
			t.Fatal("saving the preference did not return the Settings control")
		}
	}
}

func TestUpdateEndpointsRequireAppropriatePermissions(t *testing.T) {
	for path, permission := range map[string]string{
		"/ui/updates/automatic-check": auth.PermissionUpdatesRead,
		"/ui/settings/updates":        auth.PermissionSettingsWrite,
		"/ui/updates/cluster":         auth.PermissionUpdatesApply,
		"/ui/updates/cluster/stop":    auth.PermissionUpdatesApply,
	} {
		if got := requiredPermission(httptest.NewRequest(http.MethodPost, path, nil)); got != permission {
			t.Errorf("%s permission = %s", path, got)
		}
	}
	server := updateTestServer(t, nil)
	server.securityEnabled = true
	for _, permissions := range [][]string{{auth.PermissionUpdatesApply}, {auth.PermissionClusterWrite}, {auth.PermissionUpdatesApply, auth.PermissionClusterWrite}} {
		request := httptest.NewRequest(http.MethodPost, "/ui/updates/cluster", nil)
		request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, auth.Principal{Permissions: permissions}))
		if got := server.canManageClusterUpdate(request); got != (len(permissions) == 2) {
			t.Fatalf("permissions %v allowed = %v", permissions, got)
		}
	}
	if !writeRequiresPrimary(cluster.State{Initialized: true, LocalRole: cluster.RoleReplica}, http.MethodPost, "/ui/updates/cluster") {
		t.Fatal("replica can start a cluster rollout")
	}
}

func TestRollingUpdateReservationBlocksManualRestart(t *testing.T) {
	server := updateTestServer(t, &testUpdateController{status: update.Status{ClusterUpdate: true, Installed: true}})
	server.SetRestartController(func() { t.Fatal("manual restart bypassed rolling update") })
	if response := serveUpdateForm(server, "/ui/updates/restart", nil); response.Code != http.StatusConflict {
		t.Fatalf("restart = %d", response.Code)
	}
}

func TestAutomaticUpdateNoticeWaitsForAnExistingCheck(t *testing.T) {
	server := updateTestServer(t, &testUpdateController{status: update.Status{Phase: update.PhaseChecking}})
	response := serveUpdateForm(server, "/ui/updates/automatic-check", nil)
	if response.Code != http.StatusAccepted || response.Header().Get("Retry-After") == "" || response.Body.Len() != 0 {
		t.Fatalf("pending lookup = %d %s", response.Code, response.Body.String())
	}
}
