package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/update"
	"github.com/drudge/sable/internal/version"
)

const (
	// mcpVersionCheckFloor is how often get_version may ask GitHub, however
	// often an assistant passes check, so it cannot use up the
	// unauthenticated rate limit the console's own checks share.
	mcpVersionCheckFloor = 5 * time.Minute
	// mcpMaximumNotesBytes caps release notes rolled up across releases.
	mcpMaximumNotesBytes = 8 << 10
)

// mcpServerTools report on the server itself: its version, how DNS is doing,
// Dynamic DNS, and the cluster.
var mcpServerTools = []mcpTool{
	{
		Name:  "get_version",
		Title: "Get Sable's version",
		Description: "Say which Sable version is running, whether a newer release is out on the server's update " +
			"channel, and what changed in every release since the running one. Uses the last saved check unless " +
			"check is true; a fresh check asks GitHub at most once every 5 minutes.",
		InputSchema: mcpObjectSchema(map[string]any{
			"check": map[string]any{"type": "boolean", "description": "Ask GitHub now instead of using the last saved check. Defaults to false."},
			"notes": map[string]any{"type": "boolean", "description": "Include release notes. Defaults to true."},
		}, nil),
		Annotations: mcpToolAnnotations{Title: "Get Sable's version", ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: true},
		call:        (*Server).mcpGetVersion,
		section:     "server",
		grant:       "updates.read",
	},
}

type mcpLatestRelease struct {
	Release        string `json:"release"`
	PreRelease     bool   `json:"pre_release"`
	URL            string `json:"url,omitempty"`
	Notes          string `json:"notes,omitempty"`
	NotesTruncated bool   `json:"notes_truncated,omitempty"`
}

type mcpNodeVersion struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Version string `json:"version"`
}

func (server *Server) mcpGetVersion(request *http.Request, arguments json.RawMessage) (any, error) {
	input := struct {
		Check bool  `json:"check"`
		Notes *bool `json:"notes"`
	}{}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	if !server.mcpHasPermission(request, auth.PermissionUpdatesRead) {
		return nil, errors.New("this token needs updates.read to read Sable's version")
	}
	build := version.Current()
	preRelease := server.config.Current().Config.Updates.PreRelease
	channel := "stable"
	if preRelease {
		channel = "pre-release"
	}
	result := map[string]any{"current": build, "development": build.Development(), "channel": channel}
	if nodes := server.mcpNodeVersions(request); nodes != nil {
		result["nodes"] = nodes
	}
	switch {
	case build.Development():
		result["note"] = "This is a development build, so Sable does not check for releases."
		return result, nil
	case server.updates == nil:
		result["note"] = "This server cannot check for releases."
		return result, nil
	}
	status := server.updates.Status()
	if input.Check {
		status = server.mcpCheckForRelease(request, preRelease, status)
	}
	// A check made on the other channel says nothing about this one.
	if !status.Checked() || status.LatestVersion == "" || status.IncludePreRelease != preRelease {
		result["update_available"] = false
		result["note"] = "Sable has not checked for releases on this channel yet. Pass check true to ask GitHub now."
		if status.Error != "" {
			result["error"] = status.Error
		}
		return result, nil
	}
	latest := mcpLatestRelease{Release: status.LatestVersion, PreRelease: status.PreRelease, URL: status.ReleaseURL}
	if input.Notes == nil || *input.Notes {
		latest.Notes, latest.NotesTruncated = mcpReleaseNotes(status)
	}
	result["latest"] = latest
	result["update_available"] = status.NewerRelease()
	result["checked_at"] = status.CheckedAt
	if status.Error != "" {
		result["error"] = status.Error
	}
	if status.Installed {
		result["note"] = "The newer release is installed. Sable runs it after a restart."
	}
	return result, nil
}

// mcpCheckForRelease asks GitHub unless a check on this channel is newer
// than the floor, and keeps what was known when it cannot.
func (server *Server) mcpCheckForRelease(request *http.Request, preRelease bool, known update.Status) update.Status {
	checker, ok := server.updates.(interface {
		CheckIfStale(context.Context, bool, time.Duration) (update.Status, error)
	})
	if !ok {
		return known
	}
	status, err := checker.CheckIfStale(request.Context(), preRelease, mcpVersionCheckFloor)
	if err != nil && !errors.Is(err, update.ErrUpdateInProgress) {
		server.logger.Warn("check for Sable updates", "error", err, "via", "mcp")
	}
	if status.CheckedAt.After(known.CheckedAt) {
		server.recordControlPlaneAudit(request, "update.check", "checked for a newer Sable release via=mcp")
	}
	return status
}

// mcpReleaseNotes rolls up the notes of every release after the running one,
// newest first, or the latest release's notes when Sable runs it already.
func mcpReleaseNotes(status update.Status) (string, bool) {
	var sections []string
	for _, release := range status.Releases {
		if notes := strings.TrimSpace(release.Notes); notes != "" {
			sections = append(sections, "# "+release.Version+"\n\n"+notes)
		}
	}
	notes := strings.Join(sections, "\n\n")
	if len(sections) < 2 {
		notes = strings.TrimSpace(status.ReleaseNotes)
	}
	if len(notes) <= mcpMaximumNotesBytes {
		return notes, false
	}
	cut := mcpMaximumNotesBytes
	for cut > 0 && !utf8.RuneStart(notes[cut]) {
		cut--
	}
	if line := strings.LastIndexByte(notes[:cut], '\n'); line > 0 {
		cut = line
	}
	return strings.TrimSpace(notes[:cut]), true
}

// mcpNodeVersions lists what each cluster node runs, for a token that may
// read the cluster, or nothing when there is no cluster to list.
func (server *Server) mcpNodeVersions(request *http.Request) []mcpNodeVersion {
	if server.cluster == nil || !server.mcpHasPermission(request, auth.PermissionClusterRead) {
		return nil
	}
	state := server.cluster.Snapshot()
	if !state.Initialized {
		return nil
	}
	nodes := make([]mcpNodeVersion, 0, len(state.Nodes))
	for _, node := range state.Nodes {
		nodes = append(nodes, mcpNodeVersion{Name: node.Name, Role: node.Role, Version: node.Version})
	}
	return nodes
}
