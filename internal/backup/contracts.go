package backup

import "time"

// RestoreSummary reports what a restore applied.
type RestoreSummary struct {
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

// Progress reports how far a backup or restore has advanced.
type Progress struct {
	Stage string
	Step  int
	Total int
}

// Schedule is the node-local archive policy and its current runtime state.
type Schedule struct {
	Enabled           bool
	Directory         string
	ResolvedDirectory string
	Interval          time.Duration
	RunAt             string
	RetentionCount    int
	PassphraseStored  bool
	NextRun           time.Time
	LastSuccess       time.Time
	LastError         string
}

// ScheduleUpdate is an operator's replacement local-backup policy. A blank
// passphrase keeps the encrypted value already in the vault.
type ScheduleUpdate struct {
	Enabled        bool
	Directory      string
	Interval       time.Duration
	RunAt          string
	RetentionCount int
	Passphrase     string
}

// LocalArchive describes one valid archive in the configured local directory.
type LocalArchive struct {
	Name         string
	CreatedAt    time.Time
	Hostname     string
	SableVersion string
	Size         int64
	Scheduled    bool
}
