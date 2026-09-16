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

	"github.com/drudge/sable/internal/backup"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
)

type lifecycleBackupController struct {
	backupStarted, backupRelease, backupFinished    chan struct{}
	restoreStarted, restoreRelease, restoreFinished chan struct{}
	backupContexts, restoreContexts                 chan context.Context
	backupReleaseOnce, restoreReleaseOnce           sync.Once
	ignoreContext                                   bool
}

func newLifecycleBackupController() *lifecycleBackupController {
	return &lifecycleBackupController{
		backupStarted: make(chan struct{}), backupRelease: make(chan struct{}), backupFinished: make(chan struct{}),
		restoreStarted: make(chan struct{}), restoreRelease: make(chan struct{}), restoreFinished: make(chan struct{}),
		backupContexts: make(chan context.Context, 1), restoreContexts: make(chan context.Context, 1),
	}
}

func (controller *lifecycleBackupController) wait(ctx context.Context, contexts chan context.Context, started, release, finished chan struct{}) error {
	contexts <- ctx
	close(started)
	defer close(finished)
	if controller.ignoreContext {
		<-release
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-release:
		return nil
	}
}

func (controller *lifecycleBackupController) releaseBackup() {
	controller.backupReleaseOnce.Do(func() { close(controller.backupRelease) })
}

func (controller *lifecycleBackupController) releaseRestore() {
	controller.restoreReleaseOnce.Do(func() { close(controller.restoreRelease) })
}

func (controller *lifecycleBackupController) CreateBackup(ctx context.Context, _ string, _ func(backup.Progress)) ([]byte, error) {
	if err := controller.wait(ctx, controller.backupContexts, controller.backupStarted, controller.backupRelease, controller.backupFinished); err != nil {
		return nil, err
	}
	return []byte("archive"), nil
}

func (controller *lifecycleBackupController) StageRestore(ctx context.Context, _ []byte, _ string, _ bool, _ func(backup.Progress)) (backup.RestoreSummary, error) {
	if err := controller.wait(ctx, controller.restoreContexts, controller.restoreStarted, controller.restoreRelease, controller.restoreFinished); err != nil {
		return backup.RestoreSummary{}, err
	}
	return backup.RestoreSummary{}, nil
}

func newLifecycleBackupServer(t *testing.T, controller *lifecycleBackupController) *Server {
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
	server.SetBackupController(controller)
	t.Cleanup(func() {
		controller.releaseBackup()
		controller.releaseRestore()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Close(ctx); err != nil {
			t.Errorf("cleanup Close() error = %v", err)
		}
	})
	return server
}

func acceptBackupRequest(t *testing.T, server *Server) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, postForm("http://sable.test/ui/backup/download", backupPassphraseForm()))
	if response.Code != http.StatusAccepted {
		t.Fatalf("backup response status = %d, want 202: %s", response.Code, response.Body.String())
	}
	return response
}

func backupPassphraseForm() url.Values {
	return url.Values{
		"passphrase":              {"a long enough passphrase"},
		"passphrase_confirmation": {"a long enough passphrase"},
	}
}

func closeLifecycleServer(t *testing.T, server *Server, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return server.Close(ctx)
}

func TestBackupJobIsCanceledAndJoinedByClose(t *testing.T) {
	controller := newLifecycleBackupController()
	server := newLifecycleBackupServer(t, controller)
	acceptBackupRequest(t, server)
	select {
	case <-controller.backupStarted:
	case <-time.After(time.Second):
		t.Fatal("backup job did not start")
	}
	if err := closeLifecycleServer(t, server, time.Second); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-controller.backupFinished:
	case <-time.After(time.Second):
		t.Fatal("Close() returned before backup job joined")
	}
}

func TestRestoreJobIsCanceledAndJoinedByClose(t *testing.T) {
	controller := newLifecycleBackupController()
	server := newLifecycleBackupServer(t, controller)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, restoreUpload(t, sealedArchive(t), url.Values{
		"passphrase": {"a long enough passphrase"},
	}))
	if response.Code != http.StatusAccepted {
		t.Fatalf("restore response status = %d, want 202: %s", response.Code, response.Body.String())
	}
	select {
	case <-controller.restoreStarted:
	case <-time.After(time.Second):
		t.Fatal("restore job did not start")
	}
	if err := closeLifecycleServer(t, server, time.Second); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-controller.restoreFinished:
	case <-time.After(time.Second):
		t.Fatal("Close() returned before restore job joined")
	}
}

func TestContextIgnoringBackupReturnsDeadlineThenCanDrain(t *testing.T) {
	controller := newLifecycleBackupController()
	controller.ignoreContext = true
	server := newLifecycleBackupServer(t, controller)
	acceptBackupRequest(t, server)
	select {
	case <-controller.backupStarted:
	case <-time.After(time.Second):
		t.Fatal("backup job did not start")
	}
	if err := closeLifecycleServer(t, server, 50*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close() error = %v, want deadline exceeded", err)
	}
	select {
	case <-controller.backupFinished:
		t.Fatal("context-ignoring backup finished before release")
	default:
	}
	controller.releaseBackup()
	select {
	case <-controller.backupFinished:
	case <-time.After(time.Second):
		t.Fatal("backup job did not drain after release")
	}
	if err := closeLifecycleServer(t, server, time.Second); err != nil {
		t.Fatalf("retry Close() error = %v", err)
	}
}

func TestBackupRequestCancellationDoesNotCancelJob(t *testing.T) {
	controller := newLifecycleBackupController()
	server := newLifecycleBackupServer(t, controller)
	request := postForm("http://sable.test/ui/backup/download", backupPassphraseForm())
	requestContext, cancelRequest := context.WithCancel(request.Context())
	defer cancelRequest()
	request = request.WithContext(requestContext)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("backup response status = %d, want 202: %s", response.Code, response.Body.String())
	}
	select {
	case jobContext := <-controller.backupContexts:
		cancelRequest()
		if err := jobContext.Err(); err != nil {
			t.Fatalf("request cancellation canceled the backup job context: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("backup job did not start")
	}
	if err := closeLifecycleServer(t, server, time.Second); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-controller.backupFinished:
	case <-time.After(time.Second):
		t.Fatal("server close did not cancel and join the backup job")
	}
}

func TestBackupAdmissionRejectsAfterClose(t *testing.T) {
	controller := newLifecycleBackupController()
	server := newLifecycleBackupServer(t, controller)
	if err := closeLifecycleServer(t, server, time.Second); err != nil {
		t.Fatalf("initial Close() error = %v", err)
	}
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, postForm("http://sable.test/ui/backup/download", backupPassphraseForm()))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("post-close backup response status = %d, want 503: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "shutting down") {
		t.Fatalf("post-close response does not explain shutdown: %s", response.Body.String())
	}
}

func TestBackupAdmissionAndCloseRace(t *testing.T) {
	for iteration := 0; iteration < 4; iteration++ {
		controller := newLifecycleBackupController()
		server := newLifecycleBackupServer(t, controller)
		launch := make(chan struct{})
		handlerReady := make(chan struct{})
		closeReady := make(chan struct{})
		responseDone := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			close(handlerReady)
			<-launch
			response := httptest.NewRecorder()
			server.httpServer.Handler.ServeHTTP(response, postForm("http://sable.test/ui/backup/download", backupPassphraseForm()))
			responseDone <- response
		}()
		closeDone := make(chan error, 1)
		go func() {
			close(closeReady)
			<-launch
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			closeDone <- server.Close(ctx)
		}()
		for name, ready := range map[string]chan struct{}{"handler": handlerReady, "close": closeReady} {
			select {
			case <-ready:
			case <-time.After(time.Second):
				t.Fatalf("%s goroutine did not become ready", name)
			}
		}
		close(launch)
		var response *httptest.ResponseRecorder
		select {
		case response = <-responseDone:
		case <-time.After(time.Second):
			t.Fatal("backup handler did not finish after lifecycle race")
		}
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("Close() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Close() did not finish after lifecycle race")
		}
		switch response.Code {
		case http.StatusAccepted:
			select {
			case <-controller.backupFinished:
			case <-time.After(time.Second):
				t.Fatal("accepted backup did not join after lifecycle race")
			}
		case http.StatusServiceUnavailable:
		case http.StatusConflict:
			t.Fatalf("race response unexpectedly reported a running backup: %s", response.Body.String())
		default:
			t.Fatalf("race response status = %d, want 202 or 503: %s", response.Code, response.Body.String())
		}
	}
}
