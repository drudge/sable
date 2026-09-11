package update

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/version"
	"golang.org/x/mod/semver"
)

// Phase names the stage a console-driven update has reached.
type Phase string

const (
	PhaseIdle       Phase = "idle"
	PhaseChecking   Phase = "checking"
	PhaseInstalling Phase = "installing"
	PhaseInstalled  Phase = "installed"
	PhaseFailed     Phase = "failed"
)

// installTimeout bounds a background installation. It is longer than the
// download timeout so that a slow mirror fails on its own terms first.
const installTimeout = 15 * time.Minute

const (
	automaticCheckInterval = 6 * time.Hour
	automaticCheckTimeout  = 15 * time.Second
)

// Status is what the console knows about available updates right now.
type Status struct {
	ClusterUpdate bool
	Phase         Phase
	// CurrentVersion is the release this process is running.
	CurrentVersion string
	// Development disables release operations for local builds.
	Development bool
	// LatestVersion is the newest release the last check resolved.
	LatestVersion string
	ReleaseURL    string
	ReleaseNotes  string
	AssetName     string
	BinaryPath    string
	// Progress is the most recent line the installer reported.
	Progress string
	Error    string
	// PreRelease reports whether the resolved release is a pre-release, and
	// IncludePreRelease reports whether the operator asked for pre-releases.
	PreRelease        bool
	IncludePreRelease bool
	// Available reports that a newer release can be installed.
	Available bool
	// Installed reports that the executable was replaced and Sable is running
	// the previous build until it restarts.
	Installed bool
	// Blocked explains why this process cannot replace its own executable,
	// and is empty when it can. A hardened service unit or a read-only
	// container image leaves the check working and the installation not.
	Blocked   string
	CheckedAt time.Time
}

// Busy reports whether an update operation is still running.
func (status Status) Busy() bool {
	return status.Phase == PhaseChecking || status.Phase == PhaseInstalling
}

// Checked reports whether a release check has completed at least once.
func (status Status) Checked() bool {
	return !status.CheckedAt.IsZero()
}

// UpToDate reports whether a completed check found nothing newer to install.
func (status Status) UpToDate() bool {
	return !status.Development && status.Checked() && !status.Available && !status.Installed && status.Error == ""
}

// Manager runs release checks and installations for the web console. One
// operation runs at a time, and installations run in the background so the
// console can poll their progress instead of holding a request open for the
// whole download.
type Manager struct {
	options     Options
	mutex       sync.Mutex
	status      Status
	reservation string
}

// NewManager returns a manager that installs releases with the supplied
// options. Restart and CheckOnly are managed per operation and are ignored.
// PreRelease seeds the release channel the first check runs on.
func NewManager(options Options) *Manager {
	build := version.Current()
	blocked := ""
	if build.Development() {
		blocked = ErrDevelopmentBuild.Error()
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	manager := &Manager{
		options: options.withDefaults(),
		status: Status{
			Phase:             PhaseIdle,
			CurrentVersion:    build.Release,
			Development:       build.Development(),
			Blocked:           blocked,
			IncludePreRelease: options.PreRelease,
		},
	}
	manager.restoreRelease()
	return manager
}

// Status returns a snapshot of the current update state.
func (manager *Manager) Status() Status {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	status := manager.status
	status.ClusterUpdate = manager.reservation != ""
	return status
}

// ServiceManaged reports whether a service manager is expected to start Sable
// again after it exits for an update.
func (manager *Manager) ServiceManaged() bool {
	return manager.options.RestartManaged || ServiceManaged()
}

// Check resolves the newest release without installing it. It runs inline
// because it is only a pair of metadata requests.
func (manager *Manager) Check(ctx context.Context, includePreRelease bool) (Status, error) {
	if err := manager.begin(PhaseChecking, includePreRelease); err != nil {
		return manager.Status(), err
	}
	options := manager.options
	options.PreRelease = includePreRelease
	options.CheckOnly = true
	result, err := Apply(ctx, options)
	return manager.finish(result, err), err
}

// CheckAutomatically shares a cached result across console sessions, including
// failed lookups, so signing in cannot exhaust GitHub's unauthenticated quota.
func (manager *Manager) CheckAutomatically(ctx context.Context, includePreRelease bool) (Status, error) {
	manager.mutex.Lock()
	if manager.status.Busy() || manager.status.Installed || manager.reservation != "" ||
		(manager.status.IncludePreRelease == includePreRelease && time.Since(manager.status.CheckedAt) < automaticCheckInterval) {
		status := manager.status
		status.ClusterUpdate = manager.reservation != ""
		manager.mutex.Unlock()
		return status, nil
	}
	if err := manager.beginLocked(PhaseChecking, includePreRelease); err != nil {
		status := manager.status
		manager.mutex.Unlock()
		return status, err
	}
	manager.mutex.Unlock()
	options := manager.options
	options.PreRelease, options.CheckOnly = includePreRelease, true
	ctx, cancel := context.WithTimeout(ctx, automaticCheckTimeout)
	defer cancel()
	result, err := Apply(ctx, options)
	return manager.finish(result, err), err
}

// Reserve prevents local checks and installations from racing a cluster rollout.
func (manager *Manager) Reserve(id string) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.reservation == id && id != "" {
		return nil
	}
	if id == "" || manager.reservation != "" || manager.status.Busy() || manager.status.Installed {
		return ErrUpdateInProgress
	}
	if err := Installable(manager.options.BinaryPath); err != nil {
		return err
	}
	manager.reservation = id
	return nil
}

func (manager *Manager) Release(id string) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.reservation == id {
		manager.reservation = ""
	}
}

func (manager *Manager) Installable() error { return Installable(manager.options.BinaryPath) }

// InstallVersion installs the exact release selected by a reserved rollout.
func (manager *Manager) InstallVersion(id, tag string) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.reservation != id || id == "" {
		return errors.New("cluster update is not reserved")
	}
	if !isNewer(tag, version.Current().Release) {
		return errors.New("cluster updates require a newer release")
	}
	includePreRelease := semver.Prerelease(normalizeTag(tag)) != ""
	if err := manager.beginLocked(PhaseInstalling, includePreRelease); err != nil {
		return err
	}
	manager.startInstall(tag, includePreRelease)
	return nil
}

// Install downloads the newest release, verifies it, and replaces the
// installed executable in the background. Sable keeps running the previous
// build until it restarts.
func (manager *Manager) Install(includePreRelease bool) error {
	if err := manager.begin(PhaseInstalling, includePreRelease); err != nil {
		return err
	}
	if err := Installable(manager.options.BinaryPath); err != nil {
		manager.finish(Result{}, err)
		return err
	}
	manager.startInstall("", includePreRelease)
	return nil
}

func (manager *Manager) startInstall(tag string, includePreRelease bool) {
	options := manager.options
	options.Version, options.PreRelease, options.CheckOnly = tag, includePreRelease, false
	// The console restarts Sable as a separate, confirmed step so that an
	// operator on a host without a service manager is not left with a stopped
	// server.
	options.Restart = false
	options.Output = progressWriter{manager: manager}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
		defer cancel()
		result, err := Apply(ctx, options)
		manager.finish(result, err)
	}()
}

// begin claims the manager for one operation.
func (manager *Manager) begin(phase Phase, includePreRelease bool) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.reservation != "" || manager.status.Installed {
		return ErrUpdateInProgress
	}
	return manager.beginLocked(phase, includePreRelease)
}

func (manager *Manager) beginLocked(phase Phase, includePreRelease bool) error {
	if manager.status.Development {
		return ErrDevelopmentBuild
	}
	if manager.status.Busy() {
		return ErrUpdateInProgress
	}
	manager.status = Status{
		Phase:             phase,
		CurrentVersion:    version.Current().Release,
		LatestVersion:     manager.status.LatestVersion,
		ReleaseURL:        manager.status.ReleaseURL,
		ReleaseNotes:      manager.status.ReleaseNotes,
		IncludePreRelease: includePreRelease,
		CheckedAt:         manager.status.CheckedAt,
	}
	return nil
}

// finish records the outcome of a check or an installation.
func (manager *Manager) finish(result Result, err error) Status {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	status := manager.status
	status.CheckedAt = time.Now()
	status.CurrentVersion = result.CurrentVersion
	if status.CurrentVersion == "" {
		status.CurrentVersion = version.Current().Release
	}
	if err != nil {
		status.Phase = PhaseFailed
		status.Error = blockedReason(err)
		manager.status = status
		return status
	}
	status.LatestVersion = result.LatestVersion
	status.ReleaseURL = result.ReleaseURL
	status.ReleaseNotes = result.ReleaseNotes
	status.AssetName = result.AssetName
	status.BinaryPath = result.BinaryPath
	status.PreRelease = result.PreRelease
	status.Available = !result.UpToDate
	status.Installed = result.Applied
	// Probe only once a release is worth installing, so an idle console does
	// not touch the directory holding the executable on every page load.
	if status.Available && !status.Installed {
		status.Blocked = blockedReason(Installable(manager.options.BinaryPath))
	}
	switch {
	case result.Applied:
		status.Phase = PhaseInstalled
		status.Progress = ""
	default:
		status.Phase = PhaseIdle
	}
	manager.status = status
	manager.saveRelease()
	return status
}

// blockedReason returns the operator-facing sentence for an installation that
// cannot proceed, or an empty string when nothing is wrong.
func blockedReason(err error) string {
	var blocked *BlockedError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &blocked):
		return blocked.Reason
	default:
		return err.Error()
	}
}

// record stores the most recent installer progress line.
func (manager *Manager) record(line string) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	manager.status.Progress = line
}

// progressWriter feeds installer output into the polled status.
type progressWriter struct{ manager *Manager }

func (writer progressWriter) Write(contents []byte) (int, error) {
	for line := range strings.SplitSeq(strings.TrimSpace(string(contents)), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			writer.manager.record(trimmed)
		}
	}
	return len(contents), nil
}
