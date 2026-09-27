package store

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
)

func TestMCPUseRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	opened, err := Open(ctx, "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	if use, err := opened.LoadMCPUse(ctx); err != nil || !use.At.IsZero() {
		t.Fatalf("fresh use = %+v, %v", use, err)
	}
	first := MCPUse{At: time.Date(2026, 9, 27, 9, 14, 0, 0, time.UTC), Username: "nick", Client: "claude-code", Tool: "set_records"}
	second := MCPUse{At: first.At.Add(time.Minute), Username: "nick", Client: "codex", Tool: "lookup"}
	for _, use := range []MCPUse{first, second} {
		if err := opened.SaveMCPUse(ctx, use); err != nil {
			t.Fatal(err)
		}
	}
	if use, err := opened.LoadMCPUse(ctx); err != nil || use != second {
		t.Fatalf("loaded use = %+v, %v, want %+v", use, err, second)
	}
}

// The MCP Client group covers the MCP tools through API tokens only, and
// never settings.write, which would also let a token reload configuration.
func TestBuiltInMCPClientIsAPIOnly(t *testing.T) {
	t.Parallel()
	opened, err := Open(context.Background(), "sqlite", filepath.Join(t.TempDir(), "sable.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	roles, err := opened.ListRoles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(roles, func(role auth.Role) bool { return role.Name == "MCP Client" })
	if index < 0 || !roles[index].BuiltIn {
		t.Fatalf("MCP Client role missing from %d roles", len(roles))
	}
	var permissions []string
	for _, grant := range roles[index].Grants {
		if grant.Surface != auth.SurfaceAPI {
			t.Fatalf("grant %+v is not API-only", grant)
		}
		if grant.ResourceType == auth.ResourceZone && grant.ResourceID != auth.ResourceAll {
			t.Fatalf("zone grant %+v is not for all zones", grant)
		}
		permissions = append(permissions, grant.Permission)
	}
	slices.Sort(permissions)
	want := []string{auth.PermissionBlockingRead, auth.PermissionBlockingWrite, auth.PermissionZonesCreate, auth.PermissionZonesRead, auth.PermissionZonesRecords}
	slices.Sort(want)
	if !slices.Equal(permissions, want) {
		t.Fatalf("MCP Client permissions = %v, want %v", permissions, want)
	}
}
