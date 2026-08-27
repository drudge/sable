package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/backup"
	"github.com/drudge/sable/internal/web/pages"
)

// maximumBackupUploadBytes bounds a restore upload. A backup is configuration
// and keys rather than bulk data, so anything past this is not one of ours.
const maximumBackupUploadBytes = 64 << 20

// backupDownloadTTL bounds how long a sealed archive waits in memory for the
// operator to click through to it.
const backupDownloadTTL = 5 * time.Minute

// backupJobTTL bounds how long a finished job's result stays available. It only
// has to outlive the poll that collects it.
const backupJobTTL = 10 * time.Minute

const (
	backupJobKindBackup  = "backup"
	backupJobKindRestore = "restore"
)

// pendingBackup is the single staged archive waiting to be downloaded.
type pendingBackup struct {
	token     string
	name      string
	contents  []byte
	expiresAt time.Time
}

// backupJob tracks one running or just-finished operation. Backup and restore
// both run past the request that started them, so the console polls this rather
// than holding a connection open for the whole operation.
type backupJob struct {
	kind      string
	stage     string
	step      int
	total     int
	finished  bool
	failure   string
	message   string
	startedAt time.Time
	endedAt   time.Time
}

type backupStaging struct {
	mu      sync.Mutex
	pending pendingBackup
	job     *backupJob
}

// BackupSummary reports what a restore applied. It lives here rather than in
// the application package so the console does not depend on the wiring that
// drives it.
type BackupSummary struct {
	Sections              []string
	Zones                 int
	Users                 int
	Roles                 int
	Tokens                int
	Secrets               int
	TrustAnchors          int
	Files                 int
	ConfigurationBackedUp string
}

// BackupProgress is one stage report from a running operation.
type BackupProgress struct {
	Stage string
	Step  int
	Total int
}

// backupController captures deployment backups and stages restores for the next
// controlled restart. Both calls report their stages so the console can show
// real movement instead of a spinner.
type backupController interface {
	CreateBackup(ctx context.Context, passphrase string, progress func(BackupProgress)) ([]byte, error)
	StageRestore(ctx context.Context, contents []byte, passphrase string, keepConfiguration bool, progress func(BackupProgress)) (BackupSummary, error)
}

// SetBackupController wires backup and restore into the console.
func (server *Server) SetBackupController(controller backupController) {
	server.backups = controller
}

// backupPanel re-renders the console panel on its own, which is how the page
// clears a stale result without reloading every other settings tab.
func (server *Server) backupPanel(writer http.ResponseWriter, request *http.Request) {
	server.renderBackupPanel(writer, request, http.StatusOK, "", "")
}

// backupProgress answers the console's poll while an operation runs. The
// rendered panel carries the next poll only while there is still work left, so
// the loop ends on its own when the job finishes.
func (server *Server) backupProgress(writer http.ResponseWriter, request *http.Request) {
	server.renderBackupPanel(writer, request, http.StatusOK, "", "")
}

func (server *Server) downloadBackup(writer http.ResponseWriter, request *http.Request) {
	if server.backups == nil {
		server.renderBackupPanel(writer, request, http.StatusServiceUnavailable, "", "Backups are unavailable on this node.")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderBackupPanel(writer, request, http.StatusBadRequest, "", "Invalid backup form.")
		return
	}
	passphrase := request.FormValue("passphrase")
	if message := validateBackupPassphrase(passphrase, request.FormValue("passphrase_confirmation")); message != "" {
		server.renderBackupPanel(writer, request, http.StatusUnprocessableEntity, "", message)
		return
	}
	if !server.startBackupJob(backupJobKindBackup, "Preparing") {
		server.renderBackupPanel(writer, request, http.StatusConflict, "", "Another backup operation is already running on this node.")
		return
	}
	server.recordControlPlaneAudit(request, "backup.create", "started a deployment backup")

	// The operation outlives the request that started it, so it runs on a
	// background context; a browser that navigates away must not abort a
	// restore halfway through.
	go server.runBackupJob(passphrase)
	server.renderBackupPanel(writer, request, http.StatusAccepted, "", "")
}

func (server *Server) runBackupJob(passphrase string) {
	contents, err := server.backups.CreateBackup(context.Background(), passphrase, server.reportBackupProgress)
	if err != nil {
		server.logger.Error("create backup", "error", err)
		server.failBackupJob("Could not create the backup: " + err.Error())
		return
	}
	// The name is fixed once, here, so the row the console shows and the file
	// the browser finally saves cannot disagree about it.
	name := backupFileName()
	if err := server.stashBackup(contents, name); err != nil {
		server.logger.Error("stage backup download", "error", err)
		server.failBackupJob("Could not stage the backup for download.")
		return
	}
	server.finishBackupJob(func(job *backupJob) {
		job.message = "Backup ready. Save the file and store the passphrase with it."
	})
}

func (server *Server) restoreBackup(writer http.ResponseWriter, request *http.Request) {
	if server.backups == nil {
		server.renderBackupPanel(writer, request, http.StatusServiceUnavailable, "", "Restore is unavailable on this node.")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumBackupUploadBytes)
	if err := request.ParseMultipartForm(maximumBackupUploadBytes); err != nil {
		server.renderBackupPanel(writer, request, http.StatusBadRequest, "", "Invalid restore form.")
		return
	}
	file, header, err := request.FormFile("archive")
	if err != nil {
		server.renderBackupPanel(writer, request, http.StatusUnprocessableEntity, "", "Choose a backup file to restore.")
		return
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maximumBackupUploadBytes+1))
	if err != nil || len(contents) > maximumBackupUploadBytes {
		server.renderBackupPanel(writer, request, http.StatusUnprocessableEntity, "", "That backup file is too large to read.")
		return
	}
	passphrase := request.FormValue("passphrase")
	if strings.TrimSpace(passphrase) == "" {
		server.renderBackupPanel(writer, request, http.StatusUnprocessableEntity, "", "Enter the passphrase this backup was sealed with.")
		return
	}
	// Reject an obviously foreign upload before an operator watches a progress
	// bar run only to be told the file was never a backup.
	if _, err := backup.Inspect(contents); err != nil {
		server.renderBackupPanel(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	if !server.startBackupJob(backupJobKindRestore, "Preparing") {
		server.renderBackupPanel(writer, request, http.StatusConflict, "", "Another backup operation is already running on this node.")
		return
	}
	keepConfiguration := request.FormValue("keep_configuration") == "on"
	server.recordControlPlaneAudit(request, "backup.restore", "started a restore from "+header.Filename)

	go server.runRestoreJob(contents, passphrase, keepConfiguration, header.Filename)
	server.renderBackupPanel(writer, request, http.StatusAccepted, "", "")
}

func (server *Server) runRestoreJob(contents []byte, passphrase string, keepConfiguration bool, filename string) {
	summary, err := server.backups.StageRestore(
		context.Background(), contents, passphrase, keepConfiguration, server.reportBackupProgress,
	)
	if err != nil {
		if errors.Is(err, backup.ErrWrongPassphrase) || errors.Is(err, backup.ErrNotBackup) {
			server.failBackupJob(err.Error())
			return
		}
		server.logger.Error("restore backup", "error", err, "file", filename)
		server.failBackupJob("Could not restore the backup: " + err.Error())
		return
	}
	server.logger.Warn("staged deployment backup restore", "file", filename, "sections", strings.Join(summary.Sections, ","))
	server.finishBackupJob(func(job *backupJob) { job.message = restoreMessage(summary) })
}

// startBackupJob claims the single job slot. One operation at a time keeps a
// restore from racing a backup over the same files.
func (server *Server) startBackupJob(kind, stage string) bool {
	server.backupStaging.mu.Lock()
	defer server.backupStaging.mu.Unlock()
	if running := server.backupStaging.job; running != nil && !running.finished {
		return false
	}
	server.backupStaging.job = &backupJob{kind: kind, stage: stage, total: 1, startedAt: time.Now()}
	return true
}

func (server *Server) reportBackupProgress(progress BackupProgress) {
	server.backupStaging.mu.Lock()
	defer server.backupStaging.mu.Unlock()
	job := server.backupStaging.job
	if job == nil || job.finished {
		return
	}
	job.stage = progress.Stage
	job.step = progress.Step
	if progress.Total > 0 {
		job.total = progress.Total
	}
}

func (server *Server) finishBackupJob(complete func(*backupJob)) {
	server.backupStaging.mu.Lock()
	defer server.backupStaging.mu.Unlock()
	job := server.backupStaging.job
	if job == nil {
		return
	}
	job.finished, job.endedAt, job.step = true, time.Now(), job.total
	complete(job)
}

func (server *Server) failBackupJob(message string) {
	server.finishBackupJob(func(job *backupJob) { job.failure = message })
}

// takeBackupJob reports the current job to the renderer. A finished job is
// handed over once and then cleared, so its result is shown exactly once and
// the panel returns to its resting state.
func (server *Server) takeBackupJob() (running *pages.SettingsBackupJobView, completed *backupJob) {
	server.backupStaging.mu.Lock()
	defer server.backupStaging.mu.Unlock()
	job := server.backupStaging.job
	if job == nil {
		return nil, nil
	}
	if job.finished {
		server.backupStaging.job = nil
		if time.Since(job.endedAt) > backupJobTTL {
			return nil, nil
		}
		return nil, job
	}
	return &pages.SettingsBackupJobView{
		Kind:    job.kind,
		Title:   backupJobTitle(job.kind),
		Stage:   job.stage,
		Step:    job.step,
		Total:   job.total,
		Percent: backupJobPercent(job.step, job.total),
	}, nil
}

func backupJobTitle(kind string) string {
	if kind == backupJobKindRestore {
		return "Restoring backup"
	}
	return "Creating backup"
}

func backupJobPercent(step, total int) int {
	if total <= 0 {
		return 0
	}
	percent := step * 100 / total
	return min(max(percent, 0), 100)
}

// sendBackup hands over a staged archive exactly once.
func (server *Server) sendBackup(writer http.ResponseWriter, request *http.Request) {
	pending, ok := server.takeBackup(request.PathValue("token"))
	if !ok {
		http.Error(writer, "this download link has already been used or has expired", http.StatusGone)
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", strconv.Itoa(len(pending.contents)))
	writer.Header().Set("Content-Disposition", `attachment; filename="`+pending.name+`"`)
	// The archive holds the secret vault key; no cache anywhere may keep it.
	writer.Header().Set("Cache-Control", "no-store")
	if _, err := writer.Write(pending.contents); err != nil {
		server.logger.Warn("send backup", "error", err)
	}
}

// stashBackup holds one staged archive at a time. A second backup replaces the
// first, so a console session can never pile sealed archives up in memory.
func (server *Server) stashBackup(contents []byte, name string) error {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	server.backupStaging.mu.Lock()
	defer server.backupStaging.mu.Unlock()
	server.backupStaging.pending = pendingBackup{
		token:     base64.RawURLEncoding.EncodeToString(token),
		name:      name,
		contents:  contents,
		expiresAt: time.Now().Add(backupDownloadTTL),
	}
	return nil
}

// peekBackup describes the archive waiting to be downloaded without handing it
// over. The row it drives has to survive a page reload: otherwise an operator
// who refreshes before saving strands a finished archive in memory and has to
// build another one.
func (server *Server) peekBackup() (pendingBackup, bool) {
	server.backupStaging.mu.Lock()
	defer server.backupStaging.mu.Unlock()
	pending := server.backupStaging.pending
	if pending.token == "" || time.Now().After(pending.expiresAt) {
		return pendingBackup{}, false
	}
	return pending, true
}

func (server *Server) takeBackup(token string) (pendingBackup, bool) {
	server.backupStaging.mu.Lock()
	defer server.backupStaging.mu.Unlock()
	pending := server.backupStaging.pending
	server.backupStaging.pending = pendingBackup{}
	if pending.token == "" || len(token) != len(pending.token) ||
		subtle.ConstantTimeCompare([]byte(pending.token), []byte(token)) != 1 {
		return pendingBackup{}, false
	}
	if time.Now().After(pending.expiresAt) {
		return pendingBackup{}, false
	}
	return pending, true
}

func humanBackupSize(size int) string {
	switch {
	case size >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(size)/(1<<20))
	case size >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(size)/(1<<10))
	default:
		return fmt.Sprintf("%d bytes", size)
	}
}

// sectionLabels give each archive section a name fit for a sentence. The keys
// are a wire format and reading "trust_anchors" back to an operator is sloppy.
var sectionLabels = map[string]string{
	backup.SectionConfiguration: "configuration",
	backup.SectionZones:         "zones",
	backup.SectionAuthorization: "users and roles",
	backup.SectionSecrets:       "secrets",
	backup.SectionTrustAnchors:  "trust anchors",
	backup.SectionCertificates:  "TLS material",
	backup.SectionCluster:       "cluster state",
}

// restoreMessage tells an operator what is staged and that the node is still
// running the previous state until a controlled restart applies it.
func restoreMessage(summary BackupSummary) string {
	sections := make([]string, 0, len(summary.Sections))
	for _, section := range summary.Sections {
		if label, ok := sectionLabels[section]; ok {
			sections = append(sections, label)
			continue
		}
		sections = append(sections, strings.ReplaceAll(section, "_", " "))
	}
	parts := []string{}
	for _, counted := range []struct {
		count    int
		singular string
		plural   string
	}{
		{summary.Zones, "zone", "zones"},
		{summary.Users, "user", "users"},
		{summary.Roles, "role", "roles"},
		{summary.Secrets, "secret", "secrets"},
		{summary.Files, "file", "files"},
	} {
		if counted.count > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counted.count, pluralize(counted.count, counted.singular, counted.plural)))
		}
	}
	restored := strings.Join(sections, ", ")
	if len(parts) > 0 {
		restored += " (" + strings.Join(parts, ", ") + ")"
	}
	// The restart is offered as a button beside this notice, so the sentence
	// states what is true rather than repeating the instruction.
	return "Staged " + restored + ". Sable keeps serving the old state; restart to apply the restore."
}

func pluralize(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func validateBackupPassphrase(passphrase, confirmation string) string {
	if strings.TrimSpace(passphrase) == "" {
		return "A backup passphrase is required; the archive holds every private key on this node."
	}
	if len([]rune(passphrase)) < 12 {
		return "Use a passphrase of at least 12 characters."
	}
	if confirmation != "" && confirmation != passphrase {
		return "The passphrases do not match."
	}
	return ""
}

func backupFileName() string {
	return "sable-backup-" + time.Now().UTC().Format("20060102-150405") + ".sablebackup"
}

func (server *Server) renderBackupPanel(writer http.ResponseWriter, request *http.Request, status int, message, errorMessage string) {
	writeFragmentStatus(writer, status)
	_ = pages.SettingsBackupPanel(server.backupView(request, message, errorMessage)).Render(request.Context(), writer)
}

func (server *Server) backupView(request *http.Request, message, errorMessage string) pages.SettingsBackupView {
	view := pages.SettingsBackupView{
		Available:  server.backups != nil,
		CanCreate:  server.allowsBackup(request, auth.PermissionBackupCreate),
		CanRestore: server.allowsBackup(request, auth.PermissionBackupRestore),
		Message:    message,
		Error:      errorMessage,
	}
	running, completed := server.takeBackupJob()
	view.Job = running
	if completed != nil {
		if view.Message == "" {
			view.Message = completed.message
		}
		if view.Error == "" {
			view.Error = completed.failure
		}
		// A restored deployment only takes over on restart, so the notice that
		// reports it carries the restart rather than leaving the operator to
		// go find the button.
		view.OfferRestart = completed.kind == backupJobKindRestore &&
			completed.failure == "" && view.CanRestore && server.restart != nil
	}
	// A staged archive is offered on every render until it is saved or expires,
	// not only on the render that finished building it.
	if pending, ok := server.peekBackup(); ok && view.CanCreate {
		view.DownloadToken = pending.token
		view.DownloadName = pending.name
		view.DownloadSize = humanBackupSize(len(pending.contents))
		view.DownloadExpiry = humanBackupExpiry(time.Until(pending.expiresAt))
		view.DownloadExpiresAt = pending.expiresAt.UnixMilli()
	}
	return view
}

// humanBackupExpiry says how much longer the staged link works. The archive is
// only ever held in memory, so it names the restart as well; a row that simply
// vanished after one would read as a fault rather than as the design.
func humanBackupExpiry(remaining time.Duration) string {
	switch minutes := int(remaining.Round(time.Minute) / time.Minute); {
	case remaining <= 0:
		return "expired"
	case minutes <= 1:
		return "expires in under a minute, or when Sable restarts"
	default:
		return fmt.Sprintf("expires in %d minutes, or when Sable restarts", minutes)
	}
}

func (server *Server) allowsBackup(request *http.Request, permission string) bool {
	if !server.securityEnabled {
		return true
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	return auth.Authorize(principal, permission, "", "")
}
