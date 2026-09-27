package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/web/pages"
)

type mcpTestAdministrator struct {
	administrator
	roles     []auth.Role
	users     []auth.ManagedUser
	created   []auth.Grant
	userRoles []string
}

func (admin *mcpTestAdministrator) Administration(context.Context, auth.Principal) (auth.AdministrationSnapshot, error) {
	return auth.AdministrationSnapshot{Roles: admin.roles, Users: admin.users}, nil
}

func (admin *mcpTestAdministrator) CreateRole(_ context.Context, _ auth.Principal, name, description string, grants []auth.Grant, _, _ string) error {
	admin.roles = append(admin.roles, auth.Role{ID: int64(len(admin.roles) + 1), Name: name, Description: description, Grants: grants})
	admin.created = grants
	return nil
}

func (admin *mcpTestAdministrator) SetRoleGrants(_ context.Context, _ auth.Principal, id int64, grants []auth.Grant, _, _ string) error {
	for index := range admin.roles {
		if admin.roles[index].ID == id {
			admin.roles[index].Grants = grants
		}
	}
	return nil
}

func (admin *mcpTestAdministrator) SetUserRoles(_ context.Context, _ auth.Principal, _ int64, roles []string, _, _ string) error {
	admin.userRoles = roles
	return nil
}

func TestMCPGrantCoverage(t *testing.T) {
	t.Parallel()
	needed := mcpGrantsFor([]string{"search_queries", "list_zones", "add_record", "list_records"})
	if strings.Join(needed, ",") != "zones.read,zones.records.write,logs.read" {
		t.Fatalf("needed = %v", needed)
	}
	for _, test := range []struct {
		name    string
		group   string
		granted []string
		want    string
		differ  string
		update  bool
	}{
		{"no group", "", nil, "Create a group with these grants, then make a token that uses it.", "", false},
		{"matches", "Deploy", []string{"zones.read", "zones.records.write", "logs.read"}, "Deploy matches these grants.", "", false},
		{"lacks", "Deploy", []string{"zones.read"}, "Deploy lacks these grants:", "zones.records.write,logs.read", true},
		{"extra", "Deploy", []string{"zones.read", "zones.records.write", "logs.read", "zones.delete"}, "Deploy also grants these, which the tools do not need:", "zones.delete", true},
	} {
		got, differ, update := mcpGrantCoverage(needed, test.group, test.granted)
		if got != test.want || strings.Join(differ, ",") != test.differ || update != test.update {
			t.Errorf("%s: coverage = %q, %v, %t; want %q, %s, %t", test.name, got, differ, update, test.want, test.differ, test.update)
		}
	}
	if got, _, _ := mcpGrantCoverage(nil, "Deploy", nil); got != "Choose at least one tool." {
		t.Fatalf("empty = %q", got)
	}
}

func TestMCPGroupIsCreatedRememberedAndUpdated(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	admin := &mcpTestAdministrator{users: []auth.ManagedUser{{ID: 1, Username: "admin", Roles: []string{"Administrator"}}}}
	server.administrator = admin
	post := func(principal auth.Principal, form string) string {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/ui/integrations/mcp/group", strings.NewReader(form))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal))
		response := httptest.NewRecorder()
		server.saveMCPGroup(response, request)
		return response.Body.String()
	}
	adminPrincipal := auth.Principal{UserID: 1, Username: "admin", Permissions: []string{auth.PermissionAll}}

	body := post(adminPrincipal, "tools=list_zones&tools=add_record&tools=create_zone&tools=search_queries&group_name=Deploy+Bot&join=true")
	if !strings.Contains(body, `id="mcp-access-token" hx-swap-oob="true"`) || !strings.Contains(body, "Deploy Bot matches these grants.") {
		t.Fatalf("create = %s", body)
	}
	want := map[string]auth.Grant{
		auth.PermissionZonesRead:    {Permission: auth.PermissionZonesRead, Surface: auth.SurfaceAPI, ResourceType: auth.ResourceZone, ResourceID: auth.ResourceAll},
		auth.PermissionZonesRecords: {Permission: auth.PermissionZonesRecords, Surface: auth.SurfaceAPI, ResourceType: auth.ResourceZone, ResourceID: auth.ResourceAll},
		auth.PermissionZonesCreate:  {Permission: auth.PermissionZonesCreate, Surface: auth.SurfaceAPI},
		auth.PermissionLogsRead:     {Permission: auth.PermissionLogsRead, Surface: auth.SurfaceAPI},
	}
	if len(admin.created) != len(want) {
		t.Fatalf("grants = %+v", admin.created)
	}
	for _, grant := range admin.created {
		if want[grant.Permission] != grant {
			t.Errorf("grant %+v, want %+v", grant, want[grant.Permission])
		}
	}
	if strings.Join(admin.userRoles, ",") != "Administrator,Deploy Bot" {
		t.Fatalf("user roles = %v", admin.userRoles)
	}
	if configuration.snapshot.Config.MCP.Group != "Deploy Bot" {
		t.Fatalf("remembered group = %q", configuration.snapshot.Config.MCP.Group)
	}

	// With a remembered group, the Access step shows it instead of offering
	// to make another, and asks for an update only when the tools changed.
	request := httptest.NewRequest(http.MethodGet, "/integrations", nil)
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, adminPrincipal))
	view := server.mcpGroupView(request, []string{"list_zones", "add_record", "create_zone", "search_queries"}, "Deploy Bot")
	if view.Name != "Deploy Bot" || view.NeedsUpdate {
		t.Fatalf("remembered view = %+v", view)
	}
	if view = server.mcpGroupView(request, []string{"list_zones"}, "Deploy Bot"); !view.NeedsUpdate {
		t.Fatalf("narrower tools view = %+v", view)
	}

	body = post(adminPrincipal, "tools=list_zones&tools=purge_cache&group_name=Ignored")
	// An update leaves the token section alone, so a token just shown stays.
	if !strings.Contains(body, "Updated Deploy Bot to 2 grants") || strings.Contains(body, "mcp-access-token") || len(admin.roles) != 1 {
		t.Fatalf("update = %s, roles = %+v", body, admin.roles)
	}
	if got := mcpAPIGrants(admin.roles[0]); strings.Join(got, ",") != "zones.read,settings.write" {
		t.Fatalf("updated grants = %v", got)
	}

	// A remembered group that was deleted is forgotten in the view, so the
	// wizard offers to make one again.
	admin.roles = nil
	if view = server.mcpGroupView(request, []string{"list_zones"}, "Deploy Bot"); view.Name != "" {
		t.Fatalf("deleted group view = %+v", view)
	}

	configuration.snapshot.Config.MCP.Group = ""
	admin.roles = []auth.Role{{ID: 9, Name: "Taken"}}
	if body := post(adminPrincipal, "tools=list_zones&group_name=taken"); !strings.Contains(body, "already exists") {
		t.Fatalf("duplicate = %s", body)
	}
	if body := post(adminPrincipal, "group_name=Empty"); !strings.Contains(body, "Choose at least one tool") {
		t.Fatalf("no tools = %s", body)
	}
	operator := auth.Principal{UserID: 2, Username: "operator", Permissions: []string{auth.PermissionSettingsWrite}}
	if body := post(operator, "tools=list_zones"); !strings.Contains(body, "needs users.write") {
		t.Fatalf("without users.write = %s", body)
	}
}

type mcpTokenAuthenticator struct {
	mcpTestAuthenticator
	roles  []string
	groups []string
	tokens []auth.APIToken
}

func (authenticator *mcpTokenAuthenticator) Profile(context.Context, auth.Principal) (auth.ProfileSnapshot, error) {
	return auth.ProfileSnapshot{User: auth.ManagedUser{ID: 1, Roles: authenticator.roles}, Tokens: authenticator.tokens}, nil
}

func (authenticator *mcpTokenAuthenticator) CreateAPIToken(
	_ context.Context, _ auth.Principal, _ int64, _ string, groups []string, _ auth.APITokenExpiration, _, _ string,
) (string, time.Time, error) {
	authenticator.groups = groups
	return "sable_pat_fresh", time.Time{}, nil
}

func TestMCPTokenFromTheAccessStep(t *testing.T) {
	t.Parallel()
	server, configuration := newMCPTestServer(t)
	admin := &mcpTestAdministrator{roles: []auth.Role{{ID: 1, Name: "Deploy Bot", Grants: mcpRoleGrants([]string{"zones.read"})}}}
	server.administrator = admin
	tokens := &mcpTokenAuthenticator{}
	server.auth = tokens
	configuration.snapshot.Config.MCP.Group = "Deploy Bot"
	principal := auth.Principal{UserID: 1, Username: "admin", Permissions: []string{auth.PermissionAll}}
	post := func() string {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/ui/integrations/mcp/token", strings.NewReader("tools=list_zones&token_name=Laptop"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal))
		response := httptest.NewRecorder()
		server.createMCPToken(response, request)
		return response.Body.String()
	}

	// Outside the group there is no button, and a token is refused, because a
	// token can only use its owner's groups.
	request := httptest.NewRequest(http.MethodGet, "/integrations", nil)
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal))
	if view := server.mcpGroupView(request, []string{"list_zones"}, "Deploy Bot"); view.InGroup {
		t.Fatalf("view = %+v, want not in group", view)
	}
	if body := post(); !strings.Contains(body, "Add yourself to Deploy Bot in Administration") || tokens.groups != nil {
		t.Fatalf("outside the group = %s", body)
	}

	tokens.roles = []string{"Administrator", "Deploy Bot"}
	if view := server.mcpGroupView(request, []string{"list_zones"}, "Deploy Bot"); !view.InGroup {
		t.Fatal("member not recognized")
	}
	if body := post(); !strings.Contains(body, "sable_pat_fresh") || strings.Join(tokens.groups, ",") != "Deploy Bot" {
		t.Fatalf("token = %s, groups = %v", body, tokens.groups)
	}

	// A return visit lists the tokens that use the group and folds the form
	// away, instead of asking for another token.
	tokens.tokens = []auth.APIToken{{Name: "Laptop", Groups: []string{"deploy bot"}}, {Name: "Other", Groups: []string{"Readers"}}}
	view := server.mcpGroupView(request, []string{"list_zones"}, "Deploy Bot")
	if len(view.Tokens) != 1 || view.Tokens[0].Name != "Laptop" || view.Tokens[0].LastUsed != "never" {
		t.Fatalf("tokens = %+v", view.Tokens)
	}
	var page strings.Builder
	if err := pages.MCPAccessToken(view, false).Render(context.Background(), &page); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), "data-mcp-new-token") || !strings.Contains(page.String(), "data-mcp-token-form hidden") {
		t.Fatalf("return visit = %s", page.String())
	}
}
