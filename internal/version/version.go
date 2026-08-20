package version

import "runtime"

var (
	Release = "0.9.4-rc.2"
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
