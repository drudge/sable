package web

import (
	"net/http"
	"strings"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/web/pages"
)

func (server *Server) profilePage(writer http.ResponseWriter, request *http.Request) {
	if !server.securityEnabled {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	view, err := server.profileView(request, "", "")
	if err != nil {
		server.logger.Error("load profile", "client", requestClientIP(request), "error", err)
		http.Error(writer, "Unable to load your profile.", http.StatusInternalServerError)
		return
	}
	if err := pages.ProfilePage(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render profile", "error", err)
	}
}

func (server *Server) updateOwnProfile(writer http.ResponseWriter, request *http.Request) {
	server.profileMutation(writer, request, func(principal auth.Principal) error {
		return server.auth.UpdateOwnProfile(
			request.Context(), principal, request.FormValue("display_name"), request.FormValue("email"),
			requestClientIP(request), request.UserAgent(),
		)
	})
}

func (server *Server) changeOwnPassword(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "Invalid password form.", http.StatusBadRequest)
		return
	}
	if request.FormValue("new_password") != request.FormValue("confirm_password") {
		server.renderProfileContent(writer, request, http.StatusUnprocessableEntity, "", "New passwords do not match")
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	if err := server.auth.ChangeOwnPassword(
		request.Context(), principal, request.FormValue("current_password"), request.FormValue("new_password"),
		requestClientIP(request), request.UserAgent(),
	); err != nil {
		server.logger.Warn("change own password", "user", principal.Username, "client", requestClientIP(request), "error", err)
		server.renderProfileContent(writer, request, http.StatusUnprocessableEntity, "", profileError(err))
		return
	}
	writer.Header().Set("HX-Redirect", "/login")
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) profileTokens(writer http.ResponseWriter, request *http.Request) {
	view, err := server.profileView(request, "", "")
	if err != nil {
		http.Error(writer, "Unable to load API tokens.", http.StatusInternalServerError)
		return
	}
	_ = pages.ProfileTokens(view).Render(request.Context(), writer)
}

func (server *Server) revokeOwnAPIToken(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "Invalid token form.", http.StatusBadRequest)
		return
	}
	tokenID, err := formID(request.FormValue("token_id"))
	if err != nil {
		http.Error(writer, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	if err := server.auth.RevokeOwnAPIToken(request.Context(), principal, tokenID, requestClientIP(request), request.UserAgent()); err != nil {
		server.logger.Warn("revoke own API token", "user", principal.Username, "client", requestClientIP(request), "error", err)
		http.Error(writer, profileError(err), http.StatusUnprocessableEntity)
		return
	}
	server.profileTokens(writer, request)
}

func (server *Server) profileMutation(writer http.ResponseWriter, request *http.Request, mutate func(auth.Principal) error) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "Invalid profile form.", http.StatusBadRequest)
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	if err := mutate(principal); err != nil {
		server.logger.Warn("update own profile", "user", principal.Username, "client", requestClientIP(request), "error", err)
		server.renderProfileContent(writer, request, http.StatusUnprocessableEntity, "", profileError(err))
		return
	}
	writer.Header().Set("HX-Redirect", "/profile")
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) renderProfileContent(writer http.ResponseWriter, request *http.Request, status int, message, errorMessage string) {
	view, err := server.profileView(request, message, errorMessage)
	if err != nil {
		http.Error(writer, "Unable to refresh your profile.", http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(status)
	_ = pages.ProfileContent(view).Render(request.Context(), writer)
}

func (server *Server) profileView(request *http.Request, message, errorMessage string) (pages.ProfilePageView, error) {
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	snapshot, err := server.auth.Profile(request.Context(), principal)
	if err != nil {
		return pages.ProfilePageView{}, err
	}
	tab := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("tab")))
	if tab != "tokens" {
		tab = "profile"
	}
	return pages.ProfilePageView{
		Console: server.consoleView(request), User: snapshot.User, Roles: snapshot.Roles, Tokens: snapshot.Tokens, ActiveTab: tab,
		DefaultTokenTTL: server.config.Current().Config.Security.APITokenTTL.Duration,
		Message:         message, Error: errorMessage,
	}, nil
}

func profileError(err error) string {
	if err == auth.ErrInvalidCredential {
		return "Current password is incorrect"
	}
	return err.Error()
}
