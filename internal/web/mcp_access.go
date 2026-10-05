package web

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
)

const (
	mcpDefaultGroupName = "MCP Server"
	mcpGroupDescription = "API grants for the MCP server's tools, made by its setup wizard"
)

// mcpGrantsFor lists the permissions the given tools ask of a token, once
// each, in the order the console lists the tools.
func mcpGrantsFor(tools []string) []string {
	var grants []string
	for _, name := range config.MCPTools {
		if !slices.Contains(tools, name) {
			continue
		}
		if tool, found := mcpToolByName(name); found && !slices.Contains(grants, tool.grant) {
			grants = append(grants, tool.grant)
		}
	}
	return grants
}

// mcpGrantCoverage compares what the tools need with what the wizard's group
// grants, listing only the grants that differ. The wizard's script writes
// the same sentences as tools change.
func mcpGrantCoverage(needed []string, group string, granted []string) (string, []string, bool) {
	if len(needed) == 0 {
		return "Choose at least one tool.", nil, false
	}
	if group == "" {
		return "Create a group with these grants, then make a token that uses it.", nil, false
	}
	var missing, extra []string
	for _, grant := range needed {
		if !slices.Contains(granted, grant) {
			missing = append(missing, grant)
		}
	}
	for _, grant := range granted {
		if !slices.Contains(needed, grant) {
			extra = append(extra, grant)
		}
	}
	switch {
	case len(missing) > 0:
		return group + " lacks these grants:", missing, true
	case len(extra) > 0:
		return group + " also grants these, which the tools do not need:", extra, true
	default:
		return group + " matches these grants.", nil, false
	}
}

// mcpSelectedTools reads the wizard's tool checkboxes, keeping only tools
// Sable knows, in the order the console lists them.
func mcpSelectedTools(request *http.Request) []string {
	var tools []string
	for _, tool := range config.MCPTools {
		if slices.Contains(request.Form["tools"], tool) {
			tools = append(tools, tool)
		}
	}
	return tools
}

// mcpCanManageGroups reports whether the operator may create or change a
// group from the wizard. With sign-in off there are no accounts to use one.
func (server *Server) mcpCanManageGroups(request *http.Request) bool {
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	return server.administrator != nil && server.securityEnabled && auth.HasPermission(principal, auth.PermissionUsersWrite)
}

// mcpRole finds the group the wizard made, if the operator may see groups
// and it still exists.
func (server *Server) mcpRole(request *http.Request, name string) (auth.Role, bool) {
	if name == "" || server.administrator == nil || !server.securityEnabled {
		return auth.Role{}, false
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	if !auth.HasPermission(principal, auth.PermissionUsersRead) {
		return auth.Role{}, false
	}
	snapshot, err := server.administrator.Administration(request.Context(), principal)
	if err != nil {
		return auth.Role{}, false
	}
	index := slices.IndexFunc(snapshot.Roles, func(role auth.Role) bool { return strings.EqualFold(role.Name, name) })
	if index < 0 {
		return auth.Role{}, false
	}
	return snapshot.Roles[index], true
}

// mcpAPIGrants lists a group's API permissions once each.
func mcpAPIGrants(role auth.Role) []string {
	var grants []string
	for _, grant := range role.Grants {
		if grant.Surface == auth.SurfaceAPI && !slices.Contains(grants, grant.Permission) {
			grants = append(grants, grant.Permission)
		}
	}
	return grants
}

// mcpGroupView describes the Access step's group section for these tools.
func (server *Server) mcpGroupView(request *http.Request, tools []string, groupName string) pages.MCPGroupView {
	view := pages.MCPGroupView{CanManage: server.mcpCanManageGroups(request), Needed: mcpGrantsFor(tools)}
	if role, found := server.mcpRole(request, groupName); found {
		view.Name, view.Grants = role.Name, mcpAPIGrants(role)
		view.InGroup, view.Tokens = server.mcpMembership(request, role.Name)
	}
	view.Coverage, view.CoverageGrants, view.NeedsUpdate = mcpGrantCoverage(view.Needed, view.Name, view.Grants)
	return view
}

// mcpRoleGrants turns permissions into API-only grants, every zone for the
// zone permissions that can be scoped.
func mcpRoleGrants(permissions []string) []auth.Grant {
	grants := make([]auth.Grant, 0, len(permissions))
	for _, permission := range permissions {
		grant := auth.Grant{Permission: permission, Surface: auth.SurfaceAPI}
		if strings.HasPrefix(permission, "zones.") && permission != auth.PermissionZonesCreate {
			grant.ResourceType, grant.ResourceID = auth.ResourceZone, auth.ResourceAll
		}
		grants = append(grants, grant)
	}
	return grants
}

// saveMCPGroup creates the wizard's group, or brings the one it made before
// in line with the chosen tools, and remembers it. It answers with the
// Access step's group section, so the wizard stays open.
func (server *Server) saveMCPGroup(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	tools := mcpSelectedTools(request)
	remembered := server.config.Current().Config.MCP.Group
	created := false
	respond := func(view pages.MCPGroupView, ok bool, message string) {
		view.Result, view.ResultOK = message, ok
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		server.render(writer, request, pages.MCPAccessGroup(view))
		// A new group opens the token section. An update leaves it alone,
		// so a token just shown stays on screen.
		if created {
			server.render(writer, request, pages.MCPAccessToken(view, true))
		}
	}
	fail := func(message string) { respond(server.mcpGroupView(request, tools, remembered), false, message) }
	if !server.mcpCanManageGroups(request) {
		fail("Changing groups needs users.write. Ask an administrator for a group with these grants.")
		return
	}
	grants := mcpGrantsFor(tools)
	if len(grants) == 0 {
		fail("Choose at least one tool first.")
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	clientIP, userAgent := requestClientIP(request), request.UserAgent()
	snapshot, err := server.administrator.Administration(request.Context(), principal)
	if err != nil {
		fail(err.Error())
		return
	}
	ok, message := true, ""
	name := remembered
	if index := slices.IndexFunc(snapshot.Roles, func(role auth.Role) bool { return remembered != "" && strings.EqualFold(role.Name, remembered) }); index >= 0 {
		role := snapshot.Roles[index]
		if err := server.administrator.SetRoleGrants(request.Context(), principal, role.ID, mcpRoleGrants(grants), clientIP, userAgent); err != nil {
			fail(err.Error())
			return
		}
		name = role.Name
		message = fmt.Sprintf("Updated %s to %d grants.", name, len(grants))
	} else {
		name = strings.TrimSpace(request.FormValue("group_name"))
		if name == "" {
			name = mcpDefaultGroupName
		}
		if slices.ContainsFunc(snapshot.Roles, func(role auth.Role) bool { return strings.EqualFold(role.Name, name) }) {
			fail("A group named " + name + " already exists. Choose another name.")
			return
		}
		if err := server.administrator.CreateRole(request.Context(), principal, name, mcpGroupDescription, mcpRoleGrants(grants), clientIP, userAgent); err != nil {
			fail(err.Error())
			return
		}
		created = true
		// The section shows the new group, so only a failed join needs words.
		if request.FormValue("join") == "true" {
			if index := slices.IndexFunc(snapshot.Users, func(user auth.ManagedUser) bool { return user.ID == principal.UserID }); index >= 0 {
				roles := append(slices.Clone(snapshot.Users[index].Roles), name)
				if err := server.administrator.SetUserRoles(request.Context(), principal, principal.UserID, roles, clientIP, userAgent); err != nil {
					ok, message = false, "Sable made "+name+" but could not add you to it: "+err.Error()
				}
			}
		}
	}
	if err := server.updateMCP(request, func(settings *config.MCP) { settings.Group = name }); err != nil {
		server.logger.Warn("remember MCP group", "group", name, "error", err)
	}
	server.logger.Info("MCP group saved", "group", name, "grants", strings.Join(grants, ","), "client", clientIP)
	respond(server.mcpGroupView(request, tools, name), ok, message)
}

// mcpMembership reports whether the operator belongs to the group and
// which of their live tokens use it, from their own profile, which needs
// no administration rights.
func (server *Server) mcpMembership(request *http.Request, group string) (bool, []pages.MCPTokenView) {
	if server.auth == nil {
		return false, nil
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	profile, err := server.auth.Profile(request.Context(), principal)
	if err != nil {
		return false, nil
	}
	sameGroup := func(role string) bool { return strings.EqualFold(role, group) }
	if !slices.ContainsFunc(profile.User.Roles, sameGroup) {
		return false, nil
	}
	display := requestTimeDisplay(request)
	var tokens []pages.MCPTokenView
	for _, token := range profile.Tokens {
		if !slices.ContainsFunc(token.Groups, sameGroup) {
			continue
		}
		view := pages.MCPTokenView{Name: token.Name, LastUsed: "never", Expires: "Never expires"}
		if !token.LastUsedAt.IsZero() {
			view.LastUsed = pages.FormatDateTime(token.LastUsedAt, display)
		}
		if !token.ExpiresAt.IsZero() {
			view.Expires = "Expires " + pages.FormatDateTime(token.ExpiresAt, display)
		}
		tokens = append(tokens, view)
	}
	return true, tokens
}

// createMCPToken makes an API token for the operator that uses the group the
// wizard made, and shows it once in the Access step.
func (server *Server) createMCPToken(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	tools := mcpSelectedTools(request)
	groupName := server.config.Current().Config.MCP.Group
	view := server.mcpGroupView(request, tools, groupName)
	switch {
	case server.auth == nil || !server.securityEnabled:
		view.TokenError = "Sign-in is off on this server, so no token is needed."
	case view.Name == "":
		view.TokenError = "Create the group first."
	case !view.InGroup:
		view.TokenError = "Add yourself to " + view.Name + " first; a token can only use its owner's groups."
	default:
		principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
		name := strings.TrimSpace(request.FormValue("token_name"))
		if name == "" {
			name = mcpDefaultGroupName
		}
		token, expires, err := server.auth.CreateAPIToken(request.Context(), principal, principal.UserID, name,
			[]string{view.Name}, auth.APITokenExpiration{}, requestClientIP(request), request.UserAgent())
		if err != nil {
			view.TokenError = err.Error()
			break
		}
		view.Token = token
		if !expires.IsZero() {
			view.TokenExpires = pages.FormatDateTime(expires, requestTimeDisplay(request))
		}
		server.logger.Info("MCP token created", "group", view.Name, "client", requestClientIP(request))
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	server.render(writer, request, pages.MCPAccessToken(view, false))
}
