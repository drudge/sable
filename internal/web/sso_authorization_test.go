package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
)

type ssoPermissionAuthenticator struct {
	testAuthenticator
	principal auth.Principal
}

func (authentication ssoPermissionAuthenticator) AuthenticateSession(context.Context, string) (auth.Principal, error) {
	return authentication.principal, nil
}

func TestSSOAdministrationRequiresUserManagement(t *testing.T) {
	for _, permissions := range [][]string{
		{auth.PermissionSettingsWrite},
		{auth.PermissionSettingsRead, auth.PermissionSettingsWrite, auth.PermissionClusterWrite},
		{auth.PermissionUsersRead},
		{auth.PermissionUsersWrite},
		{auth.PermissionAll},
	} {
		principal := auth.Principal{Permissions: permissions, CSRFToken: "csrf-token"}
		for _, action := range []string{"wizard", "enabled", "remove", "check"} {
			t.Run(strings.Join(permissions, ",")+"/"+action, func(t *testing.T) {
				server := newWizardServer(t, &fakeSSOAdmin{})
				server.auth = ssoPermissionAuthenticator{principal: principal}
				request := httptest.NewRequest(http.MethodPost, "/ui/integrations/sso/"+action, nil)
				request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: "session-token"})
				request.Header.Set("X-CSRF-Token", principal.CSRFToken)
				response := httptest.NewRecorder()
				reached := false
				server.accessControl(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					reached = true
					writer.WriteHeader(http.StatusNoContent)
				})).ServeHTTP(response, request)
				allowed := auth.HasPermission(principal, auth.PermissionUsersWrite)
				if reached != allowed || !allowed && response.Code != http.StatusForbidden {
					t.Fatalf("SSO action reached=%v status=%d, allowed=%v", reached, response.Code, allowed)
				}
			})
		}
	}
}

func TestSettingsWriterCannotSubmitAdministratorSSOPolicy(t *testing.T) {
	admin := &fakeSSOAdmin{}
	server := newWizardServer(t, admin)
	server.auth = ssoPermissionAuthenticator{principal: auth.Principal{
		Grants:  []auth.Grant{{Permission: auth.PermissionSettingsWrite, Surface: auth.SurfaceWeb}},
		Surface: auth.SurfaceWeb, CSRFToken: "csrf-token",
	}}
	form := providerAnswers()
	form.Set("wizard_step", pages.SSOStepReview)
	form.Set("roles_present", "true")
	form.Set("provision", "true")
	form.Set("default_roles", "Administrator")
	request := httptest.NewRequest(http.MethodPost, "/ui/integrations/sso/wizard", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-CSRF-Token", "csrf-token")
	request.AddCookie(&http.Cookie{Name: server.sessionCookieName(), Value: "session-token"})
	response := httptest.NewRecorder()
	server.accessControl(http.HandlerFunc(server.runSSOWizard)).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || admin.saveCalls != 0 {
		t.Fatalf("settings writer saved SSO policy: status=%d saves=%d", response.Code, admin.saveCalls)
	}
}

func TestSettingsWriterSeesSSOStatusWithoutSetup(t *testing.T) {
	server := newWizardServer(t, &fakeSSOAdmin{status: SSOStatusView{Configured: true}})
	request := httptest.NewRequest(http.MethodGet, "/integrations?setup=sso", nil)
	request = request.WithContext(context.WithValue(request.Context(), principalContextKey{}, auth.Principal{
		Permissions: []string{auth.PermissionSettingsRead, auth.PermissionSettingsWrite},
	}))
	if server.ssoView(request, nil).CanManage {
		t.Fatal("settings writer can manage the SSO card")
	}
	response := httptest.NewRecorder()
	server.integrationsPage(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("direct setup link status=%d", response.Code)
	}
	entities := server.commandPaletteEntities(request, config.Snapshot{Config: config.Defaults()}, pages.DashboardView{
		CanSettings: true, CanWriteSettings: true,
	})
	for _, entity := range entities {
		if entity.ID == "command-entity-integration-sso" && (entity.Href != "" || entity.Route != "/integrations" || entity.Focus != "#sso-card") {
			t.Fatalf("settings writer sees SSO setup command: %+v", entity)
		}
	}
}
