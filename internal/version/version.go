package version

import (
	"runtime"
	"strings"

	"golang.org/x/mod/semver"
)

var (
	Release = "dev"
	Commit  = "unknown"
	BuiltAt = "unknown"
)

type Info struct {
	Release string `json:"release"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
	Go      string `json:"go"`
}

func Current() Info {
	return Info{Release: Release, Commit: Commit, BuiltAt: BuiltAt, Go: runtime.Version()}
}

// Development identifies unversioned builds and development or snapshot versions.
// Published alpha, beta, and release-candidate versions remain eligible for updates.
func (info Info) Development() bool {
	release := "v" + strings.TrimPrefix(strings.TrimSpace(info.Release), "v")
	if !semver.IsValid(release) {
		return true
	}
	for _, identifier := range strings.FieldsFunc(semver.Prerelease(release), func(r rune) bool { return r == '.' || r == '-' }) {
		switch strings.ToLower(identifier) {
		case "dev", "snapshot":
			return true
		}
	}
	return false
}
