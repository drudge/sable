package update

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/version"
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

// Status is what the console knows about available updates right now.
type Status struct {
	Phase Phase
	// CurrentVersion is the release this process is running.
	CurrentVersion string
	// LatestVersion is the newest release the last check resolved.
	LatestVersion string
	ReleaseURL    string
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
	return status.Checked() && !status.Available && !status.Installed && status.Error == ""
}

// Manager runs release checks and installations for the web console. One
// operation runs at a time, and installations run in the background so the
// console can poll their progress instead of holding a request open for the
// whole download.
type Manager struct {
	options Options
	mutex   sync.Mutex
	status  Status
}

// NewManager returns a manager that installs releases with the supplied
// options. Restart and CheckOnly are managed per operation and are ignored.
func NewManager(options Options) *Manager {
	return &Manager{
		options: options.withDefaults(),
		status:  Status{Phase: PhaseIdle, CurrentVersion: version.Current().Release},
	}
}

// Status returns a snapshot of the current update state.
func (manager *Manager) Status() Status {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	return manager.status
}

// ServiceManaged reports whether a service manager is expected to start Sable
// again after it exits for an update.
func (manager *Manager) ServiceManaged() bool { return ServiceManaged() }

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
	options := manager.options
	options.PreRelease = includePreRelease
	options.CheckOnly = false
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
	return nil
}

// begin claims the manager for one operation.
func (manager *Manager) begin(phase Phase, includePreRelease bool) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if manager.status.Busy() {
		return ErrUpdateInProgress
	}
	manager.status = Status{
		Phase:             phase,
		CurrentVersion:    version.Current().Release,
		LatestVersion:     manager.status.LatestVersion,
		ReleaseURL:        manager.status.ReleaseURL,
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
