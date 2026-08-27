package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/web/pages"
)

type administrator interface {
	Administration(context.Context, auth.Principal) (auth.AdministrationSnapshot, error)
	CreateUser(context.Context, auth.Principal, string, string, string, string, []string, string, string) error
	UpdateUserProfile(context.Context, auth.Principal, int64, string, string, string, string, string) error
	SetUserRoles(context.Context, auth.Principal, int64, []string, string, string) error
	SetUserDisabled(context.Context, auth.Principal, int64, bool, string, string) error
	SetPasswordLogin(context.Context, auth.Principal, int64, bool, string, string) error
	UnlinkIdentity(context.Context, auth.Principal, int64, string, string, string) error
	SetUserPassword(context.Context, auth.Principal, int64, string, string, string) error
	DeleteUser(context.Context, auth.Principal, int64, string, string) error
	CreateRole(context.Context, auth.Principal, string, string, []auth.Grant, string, string) error
	SetRoleGrants(context.Context, auth.Principal, int64, []auth.Grant, string, string) error
	DeleteRole(context.Context, auth.Principal, int64, string, string) error
	RevokeSession(context.Context, auth.Principal, string, string, string) error
	RevokeAPIToken(context.Context, auth.Principal, int64, string, string) error
}

func (server *Server) administrationPage(writer http.ResponseWriter, request *http.Request) {
	if server.administrator == nil {
		http.NotFound(writer, request)
		return
	}
	server.renderAdministration(writer, request, http.StatusOK, "", "")
}

func (server *Server) administrationTokens(writer http.ResponseWriter, request *http.Request) {
	if server.administrator == nil {
		http.Error(writer, "Administration is unavailable.", http.StatusNotImplemented)
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	snapshot, err := server.administrator.Administration(request.Context(), principal)
	if err != nil {
		server.logger.Warn("refresh API tokens", "client", requestClientIP(request), "error", err)
		http.Error(writer, "Unable to refresh API tokens.", http.StatusInternalServerError)
		return
	}
	if requestedUser := request.URL.Query().Get("user_id"); requestedUser != "" {
		userID, err := formID(requestedUser)
		if err != nil {
			http.Error(writer, "User identifier is invalid.", http.StatusBadRequest)
			return
		}
		for _, user := range snapshot.Users {
			if user.ID != userID {
				continue
			}
			view := pages.AdministrationPageView{
				Tokens: snapshot.Tokens, CanManageUsers: auth.HasPermission(principal, auth.PermissionUsersWrite),
			}
			_ = pages.UserTokensFragment(view, user).Render(request.Context(), writer)
			return
		}
		http.Error(writer, "User not found.", http.StatusNotFound)
		return
	}
	_ = pages.TokensPanelFragment(pages.AdministrationPageView{Tokens: snapshot.Tokens}).Render(request.Context(), writer)
}

func (server *Server) createUser(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "User created", func(principal auth.Principal) error {
		if request.FormValue("password") != request.FormValue("confirm_password") {
			return errors.New("passwords do not match")
		}
		return server.administrator.CreateUser(
			request.Context(), principal, request.FormValue("username"), request.FormValue("display_name"),
			request.FormValue("email"), request.FormValue("password"), request.Form["roles"], requestClientIP(request), request.UserAgent(),
		)
	})
}

func (server *Server) updateUserProfile(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "User information updated", func(principal auth.Principal) error {
		userID, err := formID(request.FormValue("user_id"))
		if err != nil {
			return err
		}
		return server.administrator.UpdateUserProfile(
			request.Context(), principal, userID, request.FormValue("username"), request.FormValue("display_name"),
			request.FormValue("email"), requestClientIP(request), request.UserAgent(),
		)
	})
}

func (server *Server) updateUserRoles(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "User roles updated", func(principal auth.Principal) error {
		userID, err := formID(request.FormValue("user_id"))
		if err != nil {
			return err
		}
		return server.administrator.SetUserRoles(request.Context(), principal, userID, request.Form["roles"], requestClientIP(request), request.UserAgent())
	})
}

func (server *Server) updateUserStatus(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "User status updated", func(principal auth.Principal) error {
		userID, err := formID(request.FormValue("user_id"))
		if err != nil {
			return err
		}
		return server.administrator.SetUserDisabled(request.Context(), principal, userID, request.FormValue("disabled") == "true", requestClientIP(request), request.UserAgent())
	})
}

// updateUserPasswordLogin moves one account between password sign-in and
// single sign-on only. It is per account rather than a deployment-wide switch,
// so nobody is forced onto a provider before they are ready.
func (server *Server) updateUserPasswordLogin(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "Sign-in method updated", func(principal auth.Principal) error {
		userID, err := formID(request.FormValue("user_id"))
		if err != nil {
			return err
		}
		return server.administrator.SetPasswordLogin(
			request.Context(), principal, userID, request.FormValue("password_login") == "true",
			requestClientIP(request), request.UserAgent(),
		)
	})
}

func (server *Server) unlinkUserIdentity(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "Identity provider unlinked", func(principal auth.Principal) error {
		userID, err := formID(request.FormValue("user_id"))
		if err != nil {
			return err
		}
		return server.administrator.UnlinkIdentity(
			request.Context(), principal, userID, request.FormValue("provider"),
			requestClientIP(request), request.UserAgent(),
		)
	})
}

func (server *Server) updateUserPassword(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "User password reset", func(principal auth.Principal) error {
		if request.FormValue("password") != request.FormValue("confirm_password") {
			return errors.New("passwords do not match")
		}
		userID, err := formID(request.FormValue("user_id"))
		if err != nil {
			return err
		}
		return server.administrator.SetUserPassword(request.Context(), principal, userID, request.FormValue("password"), requestClientIP(request), request.UserAgent())
	})
}

func (server *Server) deleteUser(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "User deleted", func(principal auth.Principal) error {
		userID, err := formID(request.FormValue("user_id"))
		if err != nil {
			return err
		}
		return server.administrator.DeleteUser(request.Context(), principal, userID, requestClientIP(request), request.UserAgent())
	})
}

func (server *Server) createRole(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "Role created", func(principal auth.Principal) error {
		grants, err := server.administrationGrants(request)
		if err != nil {
			return err
		}
		return server.administrator.CreateRole(
			request.Context(), principal, request.FormValue("name"), request.FormValue("description"),
			grants, requestClientIP(request), request.UserAgent(),
		)
	})
}

func (server *Server) updateRole(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "Group permissions updated", func(principal auth.Principal) error {
		roleID, err := formID(request.FormValue("role_id"))
		if err != nil {
			return err
		}
		grants, err := server.administrationGrants(request)
		if err != nil {
			return err
		}
		return server.administrator.SetRoleGrants(
			request.Context(), principal, roleID, grants, requestClientIP(request), request.UserAgent(),
		)
	})
}

func (server *Server) administrationGrants(request *http.Request) ([]auth.Grant, error) {
	knownZones := make(map[string]struct{})
	for _, current := range server.zones.Current().Zones {
		knownZones[current.ID] = struct{}{}
	}
	grants := make([]auth.Grant, 0)
	for _, surface := range []auth.Surface{auth.SurfaceWeb, auth.SurfaceAPI} {
		prefix := string(surface)
		zoneScope := request.FormValue(prefix + "_zone_scope")
		zoneIDs := request.Form[prefix+"_zone_ids"]
		for _, permission := range request.Form[prefix+"_permissions"] {
			grant := auth.Grant{Permission: permission, Surface: surface}
			if strings.HasPrefix(permission, "zones.") && permission != auth.PermissionZonesCreate {
				grant.ResourceType = auth.ResourceZone
				if zoneScope == "all" {
					grant.ResourceID = auth.ResourceAll
					grants = append(grants, grant)
					continue
				}
				if len(zoneIDs) == 0 {
					return nil, errors.New("select at least one zone for " + strings.ToUpper(prefix) + " zone permissions")
				}
				for _, zoneID := range zoneIDs {
					if _, found := knownZones[zoneID]; !found {
						return nil, errors.New("selected zone no longer exists")
					}
					scoped := grant
					scoped.ResourceID = zoneID
					grants = append(grants, scoped)
				}
				continue
			}
			grants = append(grants, grant)
		}
	}
	return grants, nil
}

func (server *Server) deleteRole(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "Role deleted", func(principal auth.Principal) error {
		roleID, err := formID(request.FormValue("role_id"))
		if err != nil {
			return err
		}
		return server.administrator.DeleteRole(request.Context(), principal, roleID, requestClientIP(request), request.UserAgent())
	})
}

func (server *Server) revokeSession(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "Session signed out", func(principal auth.Principal) error {
		return server.administrator.RevokeSession(request.Context(), principal, request.FormValue("session"), requestClientIP(request), request.UserAgent())
	})
}

func (server *Server) revokeAPIToken(writer http.ResponseWriter, request *http.Request) {
	server.administrationMutation(writer, request, "API token revoked", func(principal auth.Principal) error {
		tokenID, err := formID(request.FormValue("token_id"))
		if err != nil {
			return err
		}
		return server.administrator.RevokeAPIToken(request.Context(), principal, tokenID, requestClientIP(request), request.UserAgent())
	})
}

func (server *Server) administrationMutation(writer http.ResponseWriter, request *http.Request, success string, mutate func(auth.Principal) error) {
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderAdministration(writer, request, http.StatusBadRequest, "", "Invalid administration form.")
		return
	}
	if server.administrator == nil {
		server.renderAdministration(writer, request, http.StatusNotImplemented, "", "Administration is unavailable.")
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	if err := mutate(principal); err != nil {
		server.logger.Warn("administration operation failed", "client", requestClientIP(request), "error", err)
		server.renderAdministration(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	server.logger.Info("administration operation completed", "operation", success, "client", requestClientIP(request), "user_id", principal.UserID)
	server.renderAdministration(writer, request, http.StatusOK, success, "")
}

func (server *Server) renderAdministration(writer http.ResponseWriter, request *http.Request, status int, message, errorMessage string) {
	view := pages.AdministrationPageView{Console: server.consoleView(request), ActiveTab: controlPageTab(request, "users", "users", "groups", "permissions", "sessions", "tokens"), Message: message, Error: errorMessage, Permissions: auth.AllPermissions, DefaultTokenTTL: server.config.Current().Config.Security.APITokenTTL.Duration}
	for _, current := range server.zones.Current().Zones {
		view.Zones = append(view.Zones, pages.AuthorizationZone{ID: current.ID, Name: current.Name})
	}
	if server.administrator == nil {
		view.Error = "Administration is unavailable."
	} else {
		principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
		snapshot, err := server.administrator.Administration(request.Context(), principal)
		if err != nil {
			status, view.Error = http.StatusInternalServerError, err.Error()
		} else {
			view.Users, view.Roles, view.Sessions, view.Tokens, view.Audit = snapshot.Users, snapshot.Roles, snapshot.Sessions, snapshot.Tokens, snapshot.Audit
			view.CurrentUserID = principal.UserID
			view.CanManageUsers = auth.HasPermission(principal, auth.PermissionUsersWrite)
		}
	}
	if status != http.StatusOK && request.Header.Get("HX-Request") != "true" {
		writer.WriteHeader(status)
	}
	if request.Header.Get("HX-Request") == "true" {
		_ = pages.AdministrationContent(view).Render(request.Context(), writer)
		return
	}
	_ = pages.AdministrationPage(view).Render(request.Context(), writer)
}

func controlPageTab(request *http.Request, fallback string, allowed ...string) string {
	tab := request.URL.Query().Get("tab")
	if tab == "" {
		if current, err := url.Parse(request.Header.Get("HX-Current-URL")); err == nil {
			tab = current.Query().Get("tab")
		}
	}
	for _, candidate := range allowed {
		if tab == candidate {
			return tab
		}
	}
	return fallback
}

func formID(value string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("identifier is invalid")
	}
	return id, nil
}
