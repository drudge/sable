package web

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/backup"
	"github.com/drudge/sable/internal/web/pages"
)

type stubBackups struct {
	contents   []byte
	createErr  error
	restoreErr error
	summary    BackupSummary
	// stages, when set, are reported before the operation returns.
	stages []BackupProgress
	// release, when set, blocks the operation until it is closed, which is how
	// a test observes a job while it is still running.
	release chan struct{}

	mu             sync.Mutex
	lastPassphrase string
	keptLocal      bool
	restored       []byte
}

type stubLocalBackups struct {
	*stubBackups
	archives         []LocalBackup
	files            map[string][]byte
	storedPassphrase string
	scheduleUpdate   BackupScheduleUpdate
}

func (stub *stubLocalBackups) BackupSchedule(context.Context) (BackupSchedule, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return BackupSchedule{
		Directory: "data/backups", Interval: 24 * time.Hour, RunAt: "02:00", RetentionCount: 7,
		PassphraseStored: stub.storedPassphrase != "",
	}, nil
}

func (stub *stubLocalBackups) UpdateBackupSchedule(_ context.Context, update BackupScheduleUpdate) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.scheduleUpdate = update
	return nil
}

func (stub *stubLocalBackups) CreateLocalBackup(_ context.Context, passphrase string, progress func(BackupProgress)) (LocalBackup, error) {
	stub.mu.Lock()
	if passphrase == "" {
		passphrase = stub.storedPassphrase
	}
	stub.lastPassphrase = passphrase
	stub.mu.Unlock()
	stub.run(progress)
	archive := LocalBackup{Name: "sable-backup-ns1-20260901.sablebackup", CreatedAt: time.Now(), Size: 6}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.archives = append([]LocalBackup{archive}, stub.archives...)
	if stub.files == nil {
		stub.files = map[string][]byte{}
	}
	stub.files[archive.Name] = []byte("sealed")
	return archive, nil
}

func (stub *stubLocalBackups) LocalBackups(context.Context) ([]LocalBackup, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return append([]LocalBackup(nil), stub.archives...), nil
}

func (stub *stubLocalBackups) LocalBackupContents(_ context.Context, name string) ([]byte, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	contents, ok := stub.files[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), contents...), nil
}

func (stub *stubLocalBackups) DeleteLocalBackup(_ context.Context, name string) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if _, ok := stub.files[name]; !ok {
		return errors.New("not found")
	}
	delete(stub.files, name)
	for index, archive := range stub.archives {
		if archive.Name == name {
			stub.archives = append(stub.archives[:index], stub.archives[index+1:]...)
			break
		}
	}
	return nil
}

func (stub *stubLocalBackups) LocalBackupForRestore(ctx context.Context, name, passphrase string) ([]byte, string, error) {
	contents, err := stub.LocalBackupContents(ctx, name)
	return contents, passphrase, err
}

func (stub *stubBackups) run(progress func(BackupProgress)) {
	for _, stage := range stub.stages {
		progress(stage)
	}
	if stub.release != nil {
		<-stub.release
	}
}

func (stub *stubBackups) CreateBackup(_ context.Context, passphrase string, progress func(BackupProgress)) ([]byte, error) {
	stub.mu.Lock()
	stub.lastPassphrase = passphrase
	stub.mu.Unlock()
	stub.run(progress)
	if stub.createErr != nil {
		return nil, stub.createErr
	}
	return stub.contents, nil
}

func (stub *stubBackups) StageRestore(_ context.Context, contents []byte, passphrase string, keepConfiguration bool, progress func(BackupProgress)) (BackupSummary, error) {
	stub.mu.Lock()
	stub.restored, stub.lastPassphrase, stub.keptLocal = contents, passphrase, keepConfiguration
	stub.mu.Unlock()
	stub.run(progress)
	if stub.restoreErr != nil {
		return BackupSummary{}, stub.restoreErr
	}
	return stub.summary, nil
}

func (stub *stubBackups) passphrase() string {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.lastPassphrase
}

func (stub *stubBackups) restoredContents() []byte {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.restored
}

func (stub *stubBackups) keptConfiguration() bool {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return stub.keptLocal
}

func newBackupServer(stub *stubBackups) *Server {
	return &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), backups: stub}
}

func postForm(target string, values url.Values) *http.Request {
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func restoreUpload(t *testing.T, archive []byte, values url.Values) *http.Request {
	t.Helper()
	body := &bytes.Buffer{}
	form := multipart.NewWriter(body)
	part, err := form.CreateFormFile("archive", "sable-backup.sablebackup")
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := part.Write(archive); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	for field, entries := range values {
		for _, entry := range entries {
			_ = form.WriteField(field, entry)
		}
	}
	form.Close()
	request := httptest.NewRequest(http.MethodPost, "http://sable.test/ui/backup/restore", body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	return request
}

// sealedArchive is a real sealed backup, because the restore handler rejects a
// file that is not one before it starts a job.
func sealedArchive(t *testing.T) []byte {
	t.Helper()
	contents, err := backup.Encode(backup.Archive{
		Manifest: backup.Manifest{FormatVersion: backup.FormatVersion, Sections: []string{backup.SectionZones}},
	}, "a long enough passphrase")
	if err != nil {
		t.Fatalf("backup.Encode() error = %v", err)
	}
	return contents
}

// pollBackupPanel drives the console's own polling loop until the job clears.
func pollBackupPanel(t *testing.T, server *Server) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		recorder := httptest.NewRecorder()
		server.backupProgress(recorder, httptest.NewRequest(http.MethodGet, "http://sable.test/ui/backup/progress", nil))
		body := recorder.Body.String()
		if !strings.Contains(body, `hx-get="/ui/backup/progress"`) {
			return body
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the backup job never finished")
	return ""
}

var downloadLinkPattern = regexp.MustCompile(`/ui/backup/download/([A-Za-z0-9_-]+)`)

func TestBackupDownloadStagesASingleUseLink(t *testing.T) {
	stub := &stubBackups{contents: []byte("sealed archive contents")}
	server := newBackupServer(stub)

	recorder := httptest.NewRecorder()
	server.downloadBackup(recorder, postForm("http://sable.test/ui/backup/download", url.Values{
		"passphrase":              {"a long enough passphrase"},
		"passphrase_confirmation": {"a long enough passphrase"},
	}))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `hx-get="/ui/backup/progress"`) {
		t.Fatalf("the panel does not poll for progress:\n%s", recorder.Body.String())
	}

	finished := pollBackupPanel(t, server)
	if stub.passphrase() != "a long enough passphrase" {
		t.Fatalf("passphrase = %q", stub.passphrase())
	}
	match := downloadLinkPattern.FindStringSubmatch(finished)
	if match == nil {
		t.Fatalf("finished panel has no download link:\n%s", finished)
	}

	download := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://sable.test/ui/backup/download/"+match[1], nil)
	request.SetPathValue("token", match[1])
	server.sendBackup(download, request)
	if download.Code != http.StatusOK {
		t.Fatalf("download status = %d, want 200", download.Code)
	}
	if download.Body.String() != "sealed archive contents" {
		t.Fatalf("download body = %q", download.Body.String())
	}
	if disposition := download.Header().Get("Content-Disposition"); !strings.Contains(disposition, "attachment") {
		t.Fatalf("content disposition = %q", disposition)
	}
	if cacheControl := download.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("cache control = %q, want no-store", cacheControl)
	}

	// The link is spent, so a replay from history or a proxy gets nothing.
	replay := httptest.NewRecorder()
	replayRequest := httptest.NewRequest(http.MethodGet, "http://sable.test/ui/backup/download/"+match[1], nil)
	replayRequest.SetPathValue("token", match[1])
	server.sendBackup(replay, replayRequest)
	if replay.Code != http.StatusGone {
		t.Fatalf("replay status = %d, want 410", replay.Code)
	}
}

func TestRunBackupNowCreatesALocalArchive(t *testing.T) {
	stub := &stubLocalBackups{stubBackups: &stubBackups{}, files: map[string][]byte{}}
	server := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), backups: stub}
	recorder := httptest.NewRecorder()
	server.downloadBackup(recorder, postForm("http://sable.test/ui/backup/run", url.Values{
		"passphrase":              {"a long enough passphrase"},
		"passphrase_confirmation": {"a long enough passphrase"},
	}))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	finished := pollBackupPanel(t, server)
	if !strings.Contains(finished, "Created local backup sable-backup-ns1-20260901.sablebackup") {
		t.Fatalf("finished panel does not report the local archive:\n%s", finished)
	}
	if downloadLinkPattern.MatchString(finished) {
		t.Fatalf("run-now backup still created a staged in-memory link:\n%s", finished)
	}
	if stub.passphrase() != "a long enough passphrase" {
		t.Fatalf("passphrase = %q", stub.passphrase())
	}
}

func TestUpdateBackupScheduleStoresTheWallClockAnchor(t *testing.T) {
	stub := &stubLocalBackups{stubBackups: &stubBackups{}, files: map[string][]byte{}}
	server := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), backups: stub}
	recorder := httptest.NewRecorder()
	server.updateBackupSchedule(recorder, postForm("http://sable.test/ui/backup/schedule", url.Values{
		"directory":       {"data/backups"},
		"interval":        {"1d"},
		"run_at":          {"14:30"},
		"retention_count": {"7"},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if stub.scheduleUpdate.RunAt != "14:30" || stub.scheduleUpdate.Interval != 24*time.Hour {
		t.Fatalf("schedule update = %+v", stub.scheduleUpdate)
	}
}

func TestUpdateBackupScheduleRejectsAnInvalidWallClockAnchor(t *testing.T) {
	stub := &stubLocalBackups{stubBackups: &stubBackups{}, files: map[string][]byte{}}
	server := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), backups: stub}
	recorder := httptest.NewRecorder()
	server.updateBackupSchedule(recorder, postForm("http://sable.test/ui/backup/schedule", url.Values{
		"directory":       {"data/backups"},
		"interval":        {"1d"},
		"run_at":          {"2:30 PM"},
		"retention_count": {"7"},
	}))
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRunBackupNowUsesTheStoredLocalPassphrase(t *testing.T) {
	stub := &stubLocalBackups{
		stubBackups: &stubBackups{}, files: map[string][]byte{}, storedPassphrase: "the vaulted backup passphrase",
	}
	server := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), backups: stub}
	recorder := httptest.NewRecorder()
	server.downloadBackup(recorder, postForm("http://sable.test/ui/backup/run", url.Values{
		"use_stored_passphrase": {"on"},
	}))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	pollBackupPanel(t, server)
	if stub.passphrase() != "the vaulted backup passphrase" {
		t.Fatalf("passphrase = %q, want the vaulted value", stub.passphrase())
	}
}

func TestRunBackupNowRejectsAStoredPassphraseRequestWhenNoneExists(t *testing.T) {
	stub := &stubLocalBackups{stubBackups: &stubBackups{}, files: map[string][]byte{}}
	server := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), backups: stub}
	recorder := httptest.NewRecorder()
	server.downloadBackup(recorder, postForm("http://sable.test/ui/backup/run", url.Values{
		"use_stored_passphrase": {"on"},
	}))
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "No local-backup passphrase is stored") {
		t.Fatalf("response does not explain the missing vault value:\n%s", recorder.Body.String())
	}
}

func TestLocalBackupCanBeDownloadedFromHistory(t *testing.T) {
	name := "sable-backup-ns1-20260901.sablebackup"
	stub := &stubLocalBackups{stubBackups: &stubBackups{}, files: map[string][]byte{name: []byte("sealed archive")}}
	server := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), backups: stub}
	recorder := httptest.NewRecorder()
	server.downloadLocalBackup(recorder, httptest.NewRequest(http.MethodGet, "http://sable.test/ui/backup/local?name="+name, nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "sealed archive" {
		t.Fatalf("download = status %d body %q", recorder.Code, recorder.Body.String())
	}
	if disposition := recorder.Header().Get("Content-Disposition"); !strings.Contains(disposition, name) {
		t.Fatalf("content disposition = %q", disposition)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache control = %q", recorder.Header().Get("Cache-Control"))
	}
}

func TestLocalBackupCanBeDeletedFromHistory(t *testing.T) {
	name := "sable-backup-ns1-20260901.sablebackup"
	stub := &stubLocalBackups{
		stubBackups: &stubBackups{}, files: map[string][]byte{name: []byte("sealed archive")},
		archives: []LocalBackup{{Name: name, CreatedAt: time.Now(), Size: 14}},
	}
	server := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), backups: stub}
	recorder := httptest.NewRecorder()
	server.deleteLocalBackup(recorder, postForm("http://sable.test/ui/backup/delete-local", url.Values{"name": {name}}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if _, ok := stub.files[name]; ok {
		t.Fatal("deleted local backup is still stored")
	}
	if !strings.Contains(recorder.Body.String(), "Deleted local backup "+name) {
		t.Fatalf("response does not confirm deletion:\n%s", recorder.Body.String())
	}
}

// The name shown in the console has to be the name the browser finally saves,
// or an operator ends up with a file they cannot match to what they asked for.
func TestBackupDownloadNameMatchesTheStagedFile(t *testing.T) {
	server := newBackupServer(&stubBackups{contents: []byte("sealed")})
	recorder := httptest.NewRecorder()
	server.downloadBackup(recorder, postForm("http://sable.test/ui/backup/download", url.Values{
		"passphrase":              {"a long enough passphrase"},
		"passphrase_confirmation": {"a long enough passphrase"},
	}))
	finished := pollBackupPanel(t, server)

	shown := regexp.MustCompile(`sable-backup-\d{8}-\d{6}\.sablebackup`).FindString(finished)
	if shown == "" {
		t.Fatalf("finished panel names no file:\n%s", finished)
	}
	match := downloadLinkPattern.FindStringSubmatch(finished)
	download := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://sable.test/ui/backup/download/"+match[1], nil)
	request.SetPathValue("token", match[1])
	server.sendBackup(download, request)
	if disposition := download.Header().Get("Content-Disposition"); !strings.Contains(disposition, shown) {
		t.Fatalf("content disposition = %q, want the shown name %q", disposition, shown)
	}
}

func TestBackupProgressReportsRealStages(t *testing.T) {
	release := make(chan struct{})
	stub := &stubBackups{
		contents: []byte("sealed"),
		stages:   []BackupProgress{{Stage: "Collecting zones and records", Step: 2, Total: 8}},
		release:  release,
	}
	server := newBackupServer(stub)

	recorder := httptest.NewRecorder()
	server.downloadBackup(recorder, postForm("http://sable.test/ui/backup/download", url.Values{
		"passphrase":              {"a long enough passphrase"},
		"passphrase_confirmation": {"a long enough passphrase"},
	}))

	// Poll until the reported stage lands, while the operation is still held.
	var body string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		progress := httptest.NewRecorder()
		server.backupProgress(progress, httptest.NewRequest(http.MethodGet, "http://sable.test/ui/backup/progress", nil))
		body = progress.Body.String()
		if strings.Contains(body, "Collecting zones and records") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(body, "Collecting zones and records") {
		t.Fatalf("panel never showed the reported stage:\n%s", body)
	}
	// 2 of 8 stages finished is 25%, and the operator sees step 3 under way.
	if !strings.Contains(body, "25%") {
		t.Fatalf("panel does not show the computed percentage:\n%s", body)
	}
	if !strings.Contains(body, "Step 3 of 8") {
		t.Fatalf("panel does not show the step count:\n%s", body)
	}
	if !strings.Contains(body, `aria-valuenow="25"`) {
		t.Fatalf("progress bar is not exposed to assistive technology:\n%s", body)
	}
	close(release)
	pollBackupPanel(t, server)
}

func TestBackupRefusesASecondJobWhileOneRuns(t *testing.T) {
	release := make(chan struct{})
	server := newBackupServer(&stubBackups{contents: []byte("sealed"), release: release})

	first := httptest.NewRecorder()
	server.downloadBackup(first, postForm("http://sable.test/ui/backup/download", url.Values{
		"passphrase":              {"a long enough passphrase"},
		"passphrase_confirmation": {"a long enough passphrase"},
	}))
	if first.Code != http.StatusAccepted {
		t.Fatalf("first status = %d, want 202", first.Code)
	}
	second := httptest.NewRecorder()
	server.downloadBackup(second, postForm("http://sable.test/ui/backup/download", url.Values{
		"passphrase":              {"a long enough passphrase"},
		"passphrase_confirmation": {"a long enough passphrase"},
	}))
	if second.Code != http.StatusConflict {
		t.Fatalf("second status = %d, want 409", second.Code)
	}
	close(release)
	pollBackupPanel(t, server)
}

func TestBackupDownloadRejectsAWeakOrMismatchedPassphrase(t *testing.T) {
	for name, values := range map[string]url.Values{
		"missing":    {"passphrase": {""}},
		"too short":  {"passphrase": {"short"}, "passphrase_confirmation": {"short"}},
		"mismatched": {"passphrase": {"a long enough passphrase"}, "passphrase_confirmation": {"a different passphrase"}},
	} {
		t.Run(name, func(t *testing.T) {
			stub := &stubBackups{contents: []byte("never reached")}
			recorder := httptest.NewRecorder()
			newBackupServer(stub).downloadBackup(recorder, postForm("http://sable.test/ui/backup/download", values))
			if recorder.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422", recorder.Code)
			}
			if stub.passphrase() != "" {
				t.Fatal("a rejected passphrase still reached the backup routine")
			}
		})
	}
}

func TestBackupDownloadNeverEchoesThePassphrase(t *testing.T) {
	server := newBackupServer(&stubBackups{createErr: errors.New("database unavailable")})
	recorder := httptest.NewRecorder()
	server.downloadBackup(recorder, postForm("http://sable.test/ui/backup/download", url.Values{
		"passphrase":              {"correct horse battery staple"},
		"passphrase_confirmation": {"correct horse battery staple"},
	}))
	finished := pollBackupPanel(t, server)
	for _, body := range []string{recorder.Body.String(), finished} {
		if strings.Contains(body, "correct horse battery staple") {
			t.Fatalf("the rendered panel echoed the passphrase:\n%s", body)
		}
	}
	if !strings.Contains(finished, "database unavailable") {
		t.Fatalf("the failure is not reported:\n%s", finished)
	}
}

func TestBackupRestoreStagesTheUploadedArchive(t *testing.T) {
	archive := sealedArchive(t)
	stub := &stubBackups{summary: BackupSummary{
		Sections: []string{backup.SectionZones, backup.SectionAuthorization}, Zones: 3, Users: 2,
	}}
	server := newBackupServer(stub)

	recorder := httptest.NewRecorder()
	server.restoreBackup(recorder, restoreUpload(t, archive, url.Values{
		"passphrase":         {"a long enough passphrase"},
		"keep_configuration": {"on"},
	}))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}

	finished := pollBackupPanel(t, server)
	if !bytes.Equal(stub.restoredContents(), archive) {
		t.Fatal("the uploaded archive did not reach the restore routine")
	}
	if !stub.keptConfiguration() {
		t.Fatal("keep_configuration did not reach the restore routine")
	}
	if !strings.Contains(finished, "restart to apply") {
		t.Fatalf("panel does not tell the operator a restart is needed:\n%s", finished)
	}
}

func TestBackupRestoreReportsAWrongPassphrasePlainly(t *testing.T) {
	server := newBackupServer(&stubBackups{restoreErr: backup.ErrWrongPassphrase})
	recorder := httptest.NewRecorder()
	server.restoreBackup(recorder, restoreUpload(t, sealedArchive(t), url.Values{
		"passphrase": {"not the passphrase"},
	}))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", recorder.Code)
	}
	finished := pollBackupPanel(t, server)
	if !strings.Contains(finished, "does not open this backup") {
		t.Fatalf("panel does not explain the failure:\n%s", finished)
	}
}

// A file that was never a backup is caught before a job starts, so nobody
// watches a progress bar run only to be told the upload was junk.
func TestBackupRestoreRejectsAForeignFileUpFront(t *testing.T) {
	stub := &stubBackups{}
	recorder := httptest.NewRecorder()
	newBackupServer(stub).restoreBackup(recorder, restoreUpload(t, []byte("this is not a backup"), url.Values{
		"passphrase": {"a long enough passphrase"},
	}))
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", recorder.Code)
	}
	if stub.restoredContents() != nil {
		t.Fatal("a foreign file reached the restore routine")
	}
}

func TestBackupPathsRequireTheirOwnPermissions(t *testing.T) {
	for path, expected := range map[string]string{
		"/ui/backup":                 auth.PermissionBackupCreate,
		"/ui/backup/progress":        auth.PermissionBackupCreate,
		"/ui/backup/download":        auth.PermissionBackupCreate,
		"/ui/backup/download/abc123": auth.PermissionBackupCreate,
		"/ui/backup/run":             auth.PermissionBackupCreate,
		"/ui/backup/local":           auth.PermissionBackupCreate,
		"/ui/backup/delete-local":    auth.PermissionBackupCreate,
		"/ui/backup/schedule":        auth.PermissionBackupCreate,
		"/ui/backup/restore":         auth.PermissionBackupRestore,
		"/ui/backup/restore-local":   auth.PermissionBackupRestore,
	} {
		request := httptest.NewRequest(http.MethodPost, "http://sable.test"+path, nil)
		if permission := requiredPermission(request); permission != expected {
			t.Fatalf("requiredPermission(%q) = %q, want %q", path, permission, expected)
		}
	}
	// Settings write must not be enough to walk off with every private key.
	settings := httptest.NewRequest(http.MethodPost, "http://sable.test/ui/settings", nil)
	if permission := requiredPermission(settings); permission == auth.PermissionBackupCreate {
		t.Fatal("the settings path grants the backup permission")
	}
}

func TestSettingsPageShowsTheBackupPanel(t *testing.T) {
	view := pages.SettingsPageView{
		ActiveTab: "backup",
		Backup:    pages.SettingsBackupView{Available: true, CanCreate: true, CanRestore: true},
	}
	rendered := &bytes.Buffer{}
	if err := pages.SettingsContent(view).Render(context.Background(), rendered); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	body := rendered.String()
	for _, expected := range []string{
		`data-isotope-panel="backup"`,
		`hx-post="/ui/backup/download"`,
		`hx-post="/ui/backup/restore"`,
		"Download a Backup",
		"Restore a Backup",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("settings page does not contain %q", expected)
		}
	}
	// An idle panel must not poll; the loop only runs while a job does.
	if strings.Contains(body, `hx-get="/ui/backup/progress"`) {
		t.Fatal("an idle backup panel is polling for progress")
	}
	if strings.Contains(body, `data-isotope-tab="backup" aria-selected="true" disabled`) {
		t.Fatal("the backup tab is still disabled")
	}
}

func TestLocalBackupRestorePassphraseLivesInTheRestoreDialog(t *testing.T) {
	view := pages.SettingsBackupView{
		Available: true, LocalAvailable: true, CanCreate: true, CanRestore: true,
		ScheduleResolvedDirectory: "/srv/sable/backups", ScheduleRunAt: "14:30", SchedulePassphraseStored: true,
		ScheduleNextRun: "Sep 2, 2026 at 5:54 PM EDT", ScheduleNextRunCompact: "Sep 2 · 5:54 PM EDT",
		ScheduleLastSuccess: "Sep 1, 2026 at 5:54 PM EDT", ScheduleLastSuccessCompact: "Sep 1 · 5:54 PM EDT",
		LocalBackups: []pages.SettingsLocalBackupView{{
			Name: "sable-scheduled-ns1-20260901.sablebackup", Created: "Sep 1, 2026", Size: "12.0 KiB", Scheduled: true,
		}},
	}
	panel := &bytes.Buffer{}
	if err := pages.SettingsBackupPanel(view).Render(context.Background(), panel); err != nil {
		t.Fatalf("SettingsBackupPanel.Render() error = %v", err)
	}
	panelBody := panel.String()
	if !strings.Contains(panelBody, `data-local-backup-name="sable-scheduled-ns1-20260901.sablebackup"`) {
		t.Fatalf("local backup row has no restore button:\n%s", panelBody)
	}
	for _, expected := range []string{`type="time" name="run_at" value="14:30"`, `Your browser uses your preferred 12- or 24-hour display.`, `class="backup-schedule-status"`, `class="backup-schedule-timestamps"`, `>Next backup<`, `class="backup-schedule-time-full"`, `class="backup-schedule-time-compact"`, `Sep 2 · 5:54 PM EDT`, `>Save Schedule<`, `class="backup-history-header-actions"`, `data-local-backup-run-stored-form`, `name="use_stored_passphrase" value="on"`, `data-run-local-backup`, `>Use a different passphrase…<`, `data-upload-backup-restore`, `>Local Backups<`, `Encrypted backups stored on this node, ready to download or restore.`, `>Backup Now<`, `>Restore from File…<`, `hx-post="/ui/backup/delete-local"`, `data-confirm-action="Delete Backup"`, `icon-trash`, `>Delete<`, `icon-rotate-ccw`, `class="backup-local-restore-note"`, `class="backup-history-footer"`, `/srv/sable/backups`} {
		if !strings.Contains(panelBody, expected) {
			t.Fatalf("local backups card does not contain %q:\n%s", expected, panelBody)
		}
	}
	restoreFromFile := strings.Index(panelBody, `>Restore from File…<`)
	backupNow := strings.Index(panelBody, `>Backup Now<`)
	if restoreFromFile < 0 || backupNow < 0 || restoreFromFile > backupNow {
		t.Fatalf("Restore from File must appear before Backup Now:\n%s", panelBody)
	}
	if strings.Contains(panelBody, `Local Backup History`) || strings.Contains(panelBody, `class="backup-local-path"`) {
		t.Fatalf("local backups card still contains its old title or path placement:\n%s", panelBody)
	}
	if strings.Contains(panelBody, `class="backup-local-restore"`) || strings.Contains(panelBody, `placeholder="Passphrase (if different)"`) {
		t.Fatalf("local backup row still contains restore credentials:\n%s", panelBody)
	}

	dialog := &bytes.Buffer{}
	if err := pages.LocalBackupRestoreDialog().Render(context.Background(), dialog); err != nil {
		t.Fatalf("LocalBackupRestoreDialog.Render() error = %v", err)
	}
	for _, expected := range []string{`data-local-backup-restore-form`, `name="passphrase"`, `name="keep_configuration"`, "Restore Backup"} {
		if !strings.Contains(dialog.String(), expected) {
			t.Fatalf("restore dialog does not contain %q:\n%s", expected, dialog.String())
		}
	}

	upload := &bytes.Buffer{}
	if err := pages.UploadBackupRestoreDialog().Render(context.Background(), upload); err != nil {
		t.Fatalf("UploadBackupRestoreDialog.Render() error = %v", err)
	}
	for _, expected := range []string{`data-upload-backup-restore-form`, `name="archive"`, `name="passphrase"`, `name="keep_configuration"`, "Restore Backup"} {
		if !strings.Contains(upload.String(), expected) {
			t.Fatalf("upload restore dialog does not contain %q:\n%s", expected, upload.String())
		}
	}
}

// Reloading the settings page must not strand a finished archive. The row is
// driven by the staged file itself, so it stays offered until it is saved or
// expires rather than vanishing with the render that announced it.
func TestBackupDownloadLinkSurvivesAReload(t *testing.T) {
	server := newBackupServer(&stubBackups{contents: []byte("sealed archive contents")})
	recorder := httptest.NewRecorder()
	server.downloadBackup(recorder, postForm("http://sable.test/ui/backup/download", url.Values{
		"passphrase":              {"a long enough passphrase"},
		"passphrase_confirmation": {"a long enough passphrase"},
	}))
	finished := pollBackupPanel(t, server)
	if !strings.Contains(finished, "Backup ready") {
		t.Fatalf("finished panel does not announce the backup:\n%s", finished)
	}

	// A plain reload of the panel, as a browser refresh would produce.
	reload := httptest.NewRecorder()
	server.backupPanel(reload, httptest.NewRequest(http.MethodGet, "http://sable.test/ui/backup", nil))
	body := reload.Body.String()
	match := downloadLinkPattern.FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("the download link did not survive a reload:\n%s", body)
	}
	// The one-shot toast is spent, but the file is still there to save.
	if strings.Contains(body, "Backup ready") {
		t.Fatal("the completion toast repeated after a reload")
	}
	if !strings.Contains(body, "expires in") {
		t.Fatalf("the reloaded row does not say how long the link lasts:\n%s", body)
	}

	download := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://sable.test/ui/backup/download/"+match[1], nil)
	request.SetPathValue("token", match[1])
	server.sendBackup(download, request)
	if download.Body.String() != "sealed archive contents" {
		t.Fatalf("the reloaded link served %q", download.Body.String())
	}

	// Once saved, the row is gone for good.
	after := httptest.NewRecorder()
	server.backupPanel(after, httptest.NewRequest(http.MethodGet, "http://sable.test/ui/backup", nil))
	if downloadLinkPattern.MatchString(after.Body.String()) {
		t.Fatal("a spent download link is still offered")
	}
}

func TestBackupExpiryReadsPlainly(t *testing.T) {
	for remaining, expected := range map[time.Duration]string{
		5 * time.Minute:  "expires in 5 minutes, or when Sable restarts",
		90 * time.Second: "expires in 2 minutes, or when Sable restarts",
		20 * time.Second: "expires in under a minute, or when Sable restarts",
		0:                "expired",
		-time.Second:     "expired",
	} {
		if actual := humanBackupExpiry(remaining); actual != expected {
			t.Fatalf("humanBackupExpiry(%s) = %q, want %q", remaining, actual, expected)
		}
	}
}

// toastRegion slices out just the notice, because the restore card carries its
// own restart button and a whole-panel match would find that one instead.
func toastRegion(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `<div class="toast-region"`)
	if start < 0 {
		return ""
	}
	end := strings.Index(body[start:], "<section")
	if end < 0 {
		return body[start:]
	}
	return body[start : start+end]
}

// A restored deployment only takes over on restart, so the notice reporting it
// carries the restart button and must not count itself down out from under the
// operator before they can reach it.
func TestRestoreNoticeCarriesARestartButton(t *testing.T) {
	server := newBackupServer(&stubBackups{summary: BackupSummary{Sections: []string{backup.SectionZones}, Zones: 3}})
	server.restart = func() {}

	recorder := httptest.NewRecorder()
	server.restoreBackup(recorder, restoreUpload(t, sealedArchive(t), url.Values{
		"passphrase": {"a long enough passphrase"},
	}))
	finished := pollBackupPanel(t, server)

	notice := toastRegion(t, finished)
	for _, expected := range []string{
		`hx-post="/ui/backup/restart"`,
		"Restart Sable",
		`data-toast-duration="0"`,
		"toast-persistent",
		"toast-actions",
	} {
		if !strings.Contains(notice, expected) {
			t.Fatalf("restore notice does not contain %q:\n%s", expected, notice)
		}
	}
	// A toast that waits for a decision must not also run a countdown bar.
	if strings.Contains(notice, "toast-timer") {
		t.Fatalf("the persistent notice still counts itself down:\n%s", notice)
	}
}

// A node with no managed restart must not offer a button that cannot work.
func TestRestoreNoticeOmitsRestartWithoutAController(t *testing.T) {
	server := newBackupServer(&stubBackups{summary: BackupSummary{Sections: []string{backup.SectionZones}}})
	recorder := httptest.NewRecorder()
	server.restoreBackup(recorder, restoreUpload(t, sealedArchive(t), url.Values{
		"passphrase": {"a long enough passphrase"},
	}))
	notice := toastRegion(t, pollBackupPanel(t, server))
	if strings.Contains(notice, "toast-actions") {
		t.Fatalf("a node without a restart controller offered the button:\n%s", notice)
	}
	if !strings.Contains(notice, "restart to apply") {
		t.Fatalf("the notice does not say a restart is still needed:\n%s", notice)
	}
}

// A finished backup needs no restart, so its notice behaves like any other and
// clears itself.
func TestBackupNoticeDoesNotOfferARestart(t *testing.T) {
	server := newBackupServer(&stubBackups{contents: []byte("sealed")})
	server.restart = func() {}
	recorder := httptest.NewRecorder()
	server.downloadBackup(recorder, postForm("http://sable.test/ui/backup/download", url.Values{
		"passphrase":              {"a long enough passphrase"},
		"passphrase_confirmation": {"a long enough passphrase"},
	}))
	notice := toastRegion(t, pollBackupPanel(t, server))
	if strings.Contains(notice, "toast-actions") {
		t.Fatalf("the backup notice offered a restart:\n%s", notice)
	}
	if !strings.Contains(notice, `data-toast-duration="4500"`) {
		t.Fatalf("the backup notice is not a normal self-clearing toast:\n%s", notice)
	}
}

func TestRestoreMessageReadsAsASentence(t *testing.T) {
	message := restoreMessage(BackupSummary{
		Sections: []string{
			backup.SectionConfiguration, backup.SectionAuthorization,
			backup.SectionTrustAnchors, backup.SectionCertificates, backup.SectionCluster,
		},
		Zones: 1, Users: 1, Roles: 5, Files: 1,
	})
	for _, unwanted := range []string{"trust_anchors", "1 zones", "1 users", "1 files"} {
		if strings.Contains(message, unwanted) {
			t.Fatalf("message contains %q: %s", unwanted, message)
		}
	}
	for _, expected := range []string{
		"users and roles", "trust anchors", "TLS material", "cluster state",
		"1 zone", "1 user", "5 roles", "1 file",
	} {
		if !strings.Contains(message, expected) {
			t.Fatalf("message does not contain %q: %s", expected, message)
		}
	}
}

// A failure names what went wrong and what to do about it, so it waits to be
// dismissed instead of clearing itself while the operator is still reading.
func TestBackupFailuresWaitToBeDismissed(t *testing.T) {
	t.Run("wrong passphrase on restore", func(t *testing.T) {
		server := newBackupServer(&stubBackups{restoreErr: backup.ErrWrongPassphrase})
		recorder := httptest.NewRecorder()
		server.restoreBackup(recorder, restoreUpload(t, sealedArchive(t), url.Values{
			"passphrase": {"not the passphrase"},
		}))
		assertStickyError(t, toastRegion(t, pollBackupPanel(t, server)), "does not open this backup")
	})

	t.Run("failed backup", func(t *testing.T) {
		server := newBackupServer(&stubBackups{createErr: errors.New("database unavailable")})
		recorder := httptest.NewRecorder()
		server.downloadBackup(recorder, postForm("http://sable.test/ui/backup/download", url.Values{
			"passphrase":              {"a long enough passphrase"},
			"passphrase_confirmation": {"a long enough passphrase"},
		}))
		assertStickyError(t, toastRegion(t, pollBackupPanel(t, server)), "database unavailable")
	})

	t.Run("rejected passphrase", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		newBackupServer(&stubBackups{}).downloadBackup(recorder, postForm("http://sable.test/ui/backup/download", url.Values{
			"passphrase":              {"short"},
			"passphrase_confirmation": {"short"},
		}))
		assertStickyError(t, toastRegion(t, recorder.Body.String()), "at least 12 characters")
	})

	t.Run("foreign upload", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		newBackupServer(&stubBackups{}).restoreBackup(recorder, restoreUpload(t, []byte("not a backup"), url.Values{
			"passphrase": {"a long enough passphrase"},
		}))
		assertStickyError(t, toastRegion(t, recorder.Body.String()), "not a Sable backup")
	})
}

func assertStickyError(t *testing.T, notice, expected string) {
	t.Helper()
	if !strings.Contains(notice, expected) {
		t.Fatalf("notice does not explain the failure %q:\n%s", expected, notice)
	}
	if !strings.Contains(notice, "toast-error") {
		t.Fatalf("the failure is not reported as an error:\n%s", notice)
	}
	if !strings.Contains(notice, `data-toast-duration="0"`) {
		t.Fatalf("the failure counts itself down:\n%s", notice)
	}
	if strings.Contains(notice, "toast-timer") {
		t.Fatalf("the failure still shows a countdown bar:\n%s", notice)
	}
	if !strings.Contains(notice, `role="alert"`) {
		t.Fatalf("the failure is not announced as an alert:\n%s", notice)
	}
}

// The restore card is styled apart from the download card on purpose, and the
// stray restart button that used to sit in its form is gone: a restart belongs
// with a finished restore, not beside a form nobody has submitted.
func TestRestoreCardIsMarkedDangerous(t *testing.T) {
	rendered := &bytes.Buffer{}
	view := pages.SettingsBackupView{Available: true, CanCreate: true, CanRestore: true}
	if err := pages.SettingsBackupPanel(view).Render(context.Background(), rendered); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	body := rendered.String()
	if !strings.Contains(body, "settings-danger-card") {
		t.Fatalf("the restore card is not marked dangerous:\n%s", body)
	}
	if strings.Contains(body, `hx-post="/ui/backup/restart"`) {
		t.Fatal("an idle panel still offers a restart button")
	}
	// The file the operator picks identifies itself before they commit to it.
	if !strings.Contains(body, "data-backup-archive-preview") {
		t.Fatal("the restore card cannot preview the chosen archive")
	}
	// The passphrase pair is checked in the browser rather than after sealing.
	for _, expected := range []string{"data-passphrase-pair", "data-passphrase-confirmation", "data-passphrase-note"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("the create form is missing %q", expected)
		}
	}
	// The long inventory is available but no longer blocks the controls.
	if !strings.Contains(body, "What the archive contains") {
		t.Fatal("the archive inventory is gone entirely")
	}
}

// The countdown needs the deadline itself, not just the sentence that was true
// when the panel happened to render.
func TestStagedDownloadCarriesItsDeadline(t *testing.T) {
	server := newBackupServer(&stubBackups{contents: []byte("sealed")})
	recorder := httptest.NewRecorder()
	server.downloadBackup(recorder, postForm("http://sable.test/ui/backup/download", url.Values{
		"passphrase":              {"a long enough passphrase"},
		"passphrase_confirmation": {"a long enough passphrase"},
	}))
	finished := pollBackupPanel(t, server)
	stamp := regexp.MustCompile(`data-expires-at="(\d+)"`).FindStringSubmatch(finished)
	if stamp == nil {
		t.Fatalf("the staged download carries no deadline:\n%s", finished)
	}
	deadline, err := strconv.ParseInt(stamp[1], 10, 64)
	if err != nil {
		t.Fatalf("ParseInt() error = %v", err)
	}
	remaining := time.Until(time.UnixMilli(deadline))
	if remaining <= 0 || remaining > backupDownloadTTL {
		t.Fatalf("deadline is %s away, want within %s", remaining, backupDownloadTTL)
	}
}
