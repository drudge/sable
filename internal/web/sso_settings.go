package web

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
)

// ssoAdministration is the half of the single sign-on service the integrations
// page drives. It is separate from ssoController because a deployment can have
// a provider that signs people in without the console being able to edit it,
// which is what happens on a cluster replica.
type ssoAdministration interface {
	Status(context.Context) SSOStatusView
	Check(context.Context) SSOStatusView
	Save(context.Context, config.OIDC, string) error
	Remove(context.Context) error
	// Probe contacts a provider that is not saved yet, so the wizard can
	// refuse a bad issuer before the operator fills in the rest.
	Probe(context.Context, config.OIDC, string) (SSOProbeResult, error)
	// PutSecret stores the client secret on its own. The wizard writes it as
	// soon as the provider answers, the same way the UniFi wizard stores
	// controller credentials once the controller responds.
	PutSecret(context.Context, string) error
}

// SSOProbeResult is what a provider advertises about itself.
type SSOProbeResult struct {
	Issuer       string
	Scopes       []string
	Claims       []string
	SupportsPKCE bool
	EndSession   bool
}

// SSOStatusView mirrors the application's status type. The web package
// declares its own so it does not depend on the application package.
type SSOStatusView struct {
	Configured    bool
	Enabled       bool
	Label         string
	Issuer        string
	ClientID      string
	RedirectURL   string
	Scopes        []string
	UsernameClaim string
	GroupsClaim   string
	Provision     bool
	LinkByEmail   bool
	SyncRoles     bool
	DefaultRoles  []string
	Mappings      []config.OIDCRoleMapping
	SecretStored  bool

	Checked      bool
	Reachable    bool
	Error        string
	SupportsPKCE bool
	EndSession   bool
}

// SetSSOAdministration installs the console's editor for the provider.
func (server *Server) SetSSOAdministration(controller ssoAdministration) {
	server.ssoAdmin = controller
}

// ssoView builds the card. It never contacts the provider: the page has to
// render even when the identity provider is down, which is exactly when an
// operator most wants to look at it.
func (server *Server) ssoView(request *http.Request, check *SSOStatusView) pages.SSOAppView {
	if server.ssoAdmin == nil {
		return pages.SSOAppView{}
	}
	status := server.ssoAdmin.Status(request.Context())
	if check != nil {
		status = *check
	}
	view := pages.SSOAppView{
		Available:    true,
		Configured:   status.Configured,
		Enabled:      status.Enabled,
		Label:        status.Label,
		Issuer:       status.Issuer,
		ClientID:     status.ClientID,
		RedirectURL:  status.RedirectURL,
		Scopes:       strings.Join(status.Scopes, " "),
		GroupsClaim:  status.GroupsClaim,
		Provision:    status.Provision,
		LinkByEmail:  status.LinkByEmail,
		SyncRoles:    status.SyncRoles,
		DefaultRoles: strings.Join(status.DefaultRoles, ", "),
		SecretStored: status.SecretStored,
		Mappings:     ssoMappingViews(status.Mappings),
	}
	if status.Checked {
		view.Check = pages.SSOCheckView{
			Ran: true, Reachable: status.Reachable, Error: status.Error,
			SupportsPKCE: status.SupportsPKCE, EndSession: status.EndSession,
		}
	}
	server.fillSSOAccountCounts(request, &view)
	return view
}

// fillSSOAccountCounts adds the linked-account totals the card shows. A
// failure here leaves the counters at zero rather than failing the page.
func (server *Server) fillSSOAccountCounts(request *http.Request, view *pages.SSOAppView) {
	if server.administrator == nil {
		return
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	snapshot, err := server.administrator.Administration(request.Context(), principal)
	if err != nil {
		return
	}
	var latest time.Time
	for _, user := range snapshot.Users {
		for _, identity := range user.Identities {
			view.Users++
			if identity.LastLoginAt.After(latest) {
				latest = identity.LastLoginAt
			}
		}
	}
	if !latest.IsZero() {
		view.LastSignIn = pages.FormatDateTime(latest, requestTimeDisplay(request))
	}
}

func ssoMappingViews(mappings []config.OIDCRoleMapping) []pages.SSOMappingView {
	views := make([]pages.SSOMappingView, 0, len(mappings))
	for _, mapping := range mappings {
		views = append(views, pages.SSOMappingView{Group: mapping.Group, Role: mapping.Role})
	}
	return views
}

// newSSOWizard starts the setup dialog, prefilled from whatever is already
// configured so a returning operator edits rather than retypes.
func (server *Server) newSSOWizard(request *http.Request) pages.SSOWizardView {
	status := server.ssoAdmin.Status(request.Context())
	defaults := config.DefaultOIDC()
	wizard := pages.SSOWizardView{
		Open: true, Step: pages.SSOStepProvider,
		Label:         firstNonEmpty(status.Label, defaults.Label()),
		Issuer:        status.Issuer,
		ClientID:      status.ClientID,
		RedirectURL:   firstNonEmpty(status.RedirectURL, absoluteURL(request, ssoCallbackPath)),
		Scopes:        strings.Join(firstNonEmptyList(status.Scopes, defaults.Scopes), " "),
		UsernameClaim: firstNonEmpty(status.UsernameClaim, defaults.UsernameClaim),
		GroupsClaim:   firstNonEmpty(status.GroupsClaim, defaults.GroupsClaim),
		SecretStored:  status.SecretStored,
		Roles:         server.assignableRoles(request),
		Mappings:      ssoMappingViews(status.Mappings),
		DefaultRoles:  strings.Join(status.DefaultRoles, ", "),
	}
	if status.Configured {
		wizard.Provision, wizard.LinkByEmail, wizard.SyncRoles = status.Provision, status.LinkByEmail, status.SyncRoles
	} else {
		wizard.Provision, wizard.LinkByEmail, wizard.SyncRoles = defaults.Provision, defaults.LinkByVerifiedEmail, defaults.SyncRoles
	}
	return wizard
}

func firstNonEmptyList(values ...[]string) []string {
	for _, value := range values {
		if len(value) > 0 {
			return value
		}
	}
	return nil
}

// assignableRoles lists the roles a mapping may point at. Only roles that
// grant console access are offered, because a mapping to an API-only role
// would produce an account that signs in and then sees nothing.
func (server *Server) assignableRoles(request *http.Request) []string {
	if server.administrator == nil {
		return nil
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	snapshot, err := server.administrator.Administration(request.Context(), principal)
	if err != nil {
		return nil
	}
	roles := make([]string, 0, len(snapshot.Roles))
	for _, role := range snapshot.Roles {
		roles = append(roles, role.Name)
	}
	return roles
}

// checkSSO contacts the provider and re-renders the card with the result.
func (server *Server) checkSSO(writer http.ResponseWriter, request *http.Request) {
	if server.ssoAdmin == nil {
		http.NotFound(writer, request)
		return
	}
	status := server.ssoAdmin.Check(request.Context())
	view := server.integrationsView(request, "", "")
	view.SSO = server.ssoView(request, &status)
	writer.WriteHeader(http.StatusOK)
	if err := pages.IntegrationsContent(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render integrations content", "error", err)
	}
}

// setSSOEnabled switches the provider on or off without touching anything else.
func (server *Server) setSSOEnabled(writer http.ResponseWriter, request *http.Request) {
	if server.ssoAdmin == nil {
		http.NotFound(writer, request)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, authFormLimit)
	if err := request.ParseForm(); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusBadRequest, "", "Invalid form.")
		return
	}
	enabled := request.FormValue("enabled") == "true"
	status := server.ssoAdmin.Status(request.Context())
	settings := ssoSettingsFromStatus(status)
	settings.Enabled = enabled
	if err := server.ssoAdmin.Save(request.Context(), settings, ""); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	message := "Single sign-on is disabled."
	if enabled {
		message = "Single sign-on is enabled."
	}
	server.renderIntegrationsMutation(writer, request, http.StatusOK, message, "")
}

// runSSOWizard advances the setup wizard. Each step is a server round trip
// because the first one has to contact the provider before the rest is worth
// filling in, and the review step has to show what will actually be saved.
func (server *Server) runSSOWizard(writer http.ResponseWriter, request *http.Request) {
	if server.ssoAdmin == nil {
		http.NotFound(writer, request)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusBadRequest, "", "Invalid setup form.")
		return
	}
	wizard := server.ssoWizardFromRequest(request)
	// Back wins over the step being submitted, so an operator can retreat
	// without the current step's validation stopping them.
	if target := strings.TrimSpace(request.FormValue("wizard_target")); target != "" {
		wizard.Step = target
		server.renderSSOWizard(writer, request, http.StatusOK, wizard)
		return
	}
	switch request.FormValue("wizard_step") {
	case pages.SSOStepProvider:
		server.ssoWizardProvider(writer, request, wizard)
	case pages.SSOStepClaims:
		wizard.Step = pages.SSOStepRoles
		server.renderSSOWizard(writer, request, http.StatusOK, wizard)
	case pages.SSOStepRoles:
		wizard.Step = pages.SSOStepReview
		server.renderSSOWizard(writer, request, http.StatusOK, wizard)
	case pages.SSOStepReview:
		server.ssoWizardFinish(writer, request, wizard)
	default:
		server.renderSSOWizard(writer, request, http.StatusBadRequest, wizard)
	}
}

// ssoWizardProvider validates the first step by contacting the issuer. A
// provider that cannot be reached, or that answers for somebody else, is
// caught here rather than at the first attempted sign-in.
func (server *Server) ssoWizardProvider(writer http.ResponseWriter, request *http.Request, wizard pages.SSOWizardView) {
	settings := ssoSettingsFromWizard(wizard)
	if err := settings.Validate(); err != nil {
		wizard.Error = err.Error()
		server.renderSSOWizard(writer, request, http.StatusUnprocessableEntity, wizard)
		return
	}
	secret := request.FormValue("client_secret")
	if strings.TrimSpace(secret) == "" && !wizard.SecretStored {
		wizard.Error = "A client secret is required. Copy it from the application at your provider."
		server.renderSSOWizard(writer, request, http.StatusUnprocessableEntity, wizard)
		return
	}
	probe, err := server.ssoAdmin.Probe(request.Context(), settings, secret)
	if err != nil {
		wizard.Error = err.Error()
		server.renderSSOWizard(writer, request, http.StatusBadGateway, wizard)
		return
	}
	// The provider answered, so the secret is worth keeping. Storing it now
	// means the later steps do not have to carry it through the browser.
	if strings.TrimSpace(secret) != "" {
		if err := server.ssoAdmin.PutSecret(request.Context(), secret); err != nil {
			wizard.Error = err.Error()
			server.renderSSOWizard(writer, request, http.StatusUnprocessableEntity, wizard)
			return
		}
		wizard.SecretStored = true
		server.recordControlPlaneAudit(request, "integrations.sso.secret", "stored OIDC client secret")
	}
	wizard.Probe = pages.SSOProbeView{
		Ran: true, Issuer: probe.Issuer, Scopes: probe.Scopes, Claims: probe.Claims,
		SupportsPKCE: probe.SupportsPKCE, EndSession: probe.EndSession,
	}
	wizard.Step = pages.SSOStepClaims
	server.renderSSOWizard(writer, request, http.StatusOK, wizard)
}

// ssoWizardFinish saves the provider and switches it on.
func (server *Server) ssoWizardFinish(writer http.ResponseWriter, request *http.Request, wizard pages.SSOWizardView) {
	settings := ssoSettingsFromWizard(wizard)
	settings.Enabled = true
	if err := server.ssoAdmin.Save(request.Context(), settings, ""); err != nil {
		wizard.Error = err.Error()
		server.renderSSOWizard(writer, request, http.StatusUnprocessableEntity, wizard)
		return
	}
	server.recordControlPlaneAudit(request, "integrations.sso.save", "configured single sign-on for "+settings.Issuer)
	server.renderIntegrationsMutation(writer, request, http.StatusOK, "Single sign-on is set up.", "")
}

// renderSSOWizard re-renders the page with the wizard open on its current step.
func (server *Server) renderSSOWizard(writer http.ResponseWriter, request *http.Request, status int, wizard pages.SSOWizardView) {
	wizard.Open = true
	if len(wizard.Roles) == 0 {
		wizard.Roles = server.assignableRoles(request)
	}
	view := server.integrationsView(request, "", "")
	view.SSO.Wizard = wizard
	writeFragmentStatus(writer, status)
	if err := pages.IntegrationsContent(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render integrations content", "error", err)
	}
}

// ssoWizardFromRequest rebuilds the operator's answers from the posted form,
// seeding anything the current step has not collected yet from the defaults.
func (server *Server) ssoWizardFromRequest(request *http.Request) pages.SSOWizardView {
	defaults := config.DefaultOIDC()
	// A step only posts the answers it collects, so anything it does not ask
	// about has to be seeded from what is already saved rather than from the
	// defaults. Seeding from the defaults would drop an existing operator's
	// group mappings the moment they walked past the provider step, and would
	// quietly switch settings like provisioning back on.
	saved := server.ssoAdmin.Status(request.Context())
	wizard := pages.SSOWizardView{
		Open:         true,
		Step:         firstNonEmpty(request.FormValue("wizard_step"), pages.SSOStepProvider),
		Label:        strings.TrimSpace(request.FormValue("display_name")),
		Issuer:       strings.TrimSpace(request.FormValue("issuer")),
		ClientID:     strings.TrimSpace(request.FormValue("client_id")),
		RedirectURL:  strings.TrimSpace(request.FormValue("redirect_url")),
		SecretStored: saved.SecretStored,
	}

	// The provider step does not ask about claims, so unchecked boxes there
	// must not be read as deliberate answers.
	if ssoWizardCollected(request, "claims_present", pages.SSOStepClaims) {
		wizard.Scopes = strings.TrimSpace(request.FormValue("scopes"))
		wizard.UsernameClaim = strings.TrimSpace(request.FormValue("username_claim"))
		wizard.GroupsClaim = strings.TrimSpace(request.FormValue("groups_claim"))
		wizard.FetchUserInfo = request.FormValue("fetch_userinfo") == "true"
	} else {
		wizard.Scopes = strings.Join(saved.Scopes, " ")
		wizard.UsernameClaim = saved.UsernameClaim
		wizard.GroupsClaim = saved.GroupsClaim
	}
	wizard.Scopes = firstNonEmpty(wizard.Scopes, strings.TrimSpace(request.FormValue("scopes")), strings.Join(defaults.Scopes, " "))
	wizard.UsernameClaim = firstNonEmpty(wizard.UsernameClaim, defaults.UsernameClaim)
	wizard.GroupsClaim = firstNonEmpty(wizard.GroupsClaim, defaults.GroupsClaim)

	if ssoWizardCollected(request, "roles_present", pages.SSOStepRoles) {
		wizard.Provision = request.FormValue("provision") == "true"
		wizard.LinkByEmail = request.FormValue("link_by_email") == "true"
		wizard.SyncRoles = request.FormValue("sync_roles") == "true"
		wizard.DefaultRoles = strings.TrimSpace(request.FormValue("default_roles"))
		wizard.Mappings = ssoMappingViewsFromForm(request)
	} else if saved.Configured {
		wizard.Provision, wizard.LinkByEmail = saved.Provision, saved.LinkByEmail
		wizard.SyncRoles = saved.SyncRoles
		wizard.DefaultRoles = strings.Join(saved.DefaultRoles, ", ")
		wizard.Mappings = ssoMappingViews(saved.Mappings)
	} else {
		wizard.Provision, wizard.LinkByEmail = defaults.Provision, defaults.LinkByVerifiedEmail
		wizard.SyncRoles = defaults.SyncRoles
	}
	return wizard
}

// ssoWizardCollected reports whether the posted form carries a section's
// answers: either the step that collects them is the one being submitted, or a
// later step re-posted them through its hidden fields.
func ssoWizardCollected(request *http.Request, marker, step string) bool {
	return request.Form.Has(marker) || request.FormValue("wizard_step") == step
}

// ssoSettingsFromWizard turns the wizard's answers into the configuration the
// provider is built from.
func ssoSettingsFromWizard(wizard pages.SSOWizardView) config.OIDC {
	settings := config.DefaultOIDC()
	settings.DisplayName = wizard.Label
	settings.Issuer = wizard.Issuer
	settings.ClientID = wizard.ClientID
	settings.RedirectURL = wizard.RedirectURL
	if scopes := strings.Fields(wizard.Scopes); len(scopes) > 0 {
		settings.Scopes = scopes
	}
	if wizard.UsernameClaim != "" {
		settings.UsernameClaim = wizard.UsernameClaim
	}
	if wizard.GroupsClaim != "" {
		settings.GroupsClaim = wizard.GroupsClaim
	}
	settings.FetchUserInfo = wizard.FetchUserInfo
	settings.Provision = wizard.Provision
	settings.LinkByVerifiedEmail = wizard.LinkByEmail
	settings.SyncRoles = wizard.SyncRoles
	settings.DefaultRoles = splitRoleList(wizard.DefaultRoles)
	for _, mapping := range wizard.Mappings {
		settings.RoleMappings = append(settings.RoleMappings, config.OIDCRoleMapping{Group: mapping.Group, Role: mapping.Role})
	}
	return settings
}

// ssoMappingViewsFromForm pairs the group and role inputs by position. A row
// with either half blank is dropped, which is how a mapping is deleted.
func ssoMappingViewsFromForm(request *http.Request) []pages.SSOMappingView {
	groups := request.Form["mapping_group"]
	roles := request.Form["mapping_role"]
	mappings := make([]pages.SSOMappingView, 0, len(groups))
	for index, group := range groups {
		group = strings.TrimSpace(group)
		role := ""
		if index < len(roles) {
			role = strings.TrimSpace(roles[index])
		}
		if group == "" || role == "" {
			continue
		}
		mappings = append(mappings, pages.SSOMappingView{Group: group, Role: role})
	}
	return mappings
}

// removeSSO forgets the provider and its secret.
func (server *Server) removeSSO(writer http.ResponseWriter, request *http.Request) {
	if server.ssoAdmin == nil {
		http.NotFound(writer, request)
		return
	}
	if err := server.ssoAdmin.Remove(request.Context()); err != nil {
		server.renderIntegrationsMutation(writer, request, http.StatusUnprocessableEntity, "", err.Error())
		return
	}
	server.renderIntegrationsMutation(writer, request, http.StatusOK, "Single sign-on removed.", "")
}

// ssoSettingsFromStatus rebuilds the configuration behind the current status,
// so a toggle can be applied without the operator re-entering everything.
func ssoSettingsFromStatus(status SSOStatusView) config.OIDC {
	settings := config.DefaultOIDC()
	settings.Enabled = status.Enabled
	settings.DisplayName = status.Label
	settings.Issuer = status.Issuer
	settings.ClientID = status.ClientID
	settings.RedirectURL = status.RedirectURL
	if len(status.Scopes) > 0 {
		settings.Scopes = status.Scopes
	}
	if status.UsernameClaim != "" {
		settings.UsernameClaim = status.UsernameClaim
	}
	if status.GroupsClaim != "" {
		settings.GroupsClaim = status.GroupsClaim
	}
	settings.Provision = status.Provision
	settings.LinkByVerifiedEmail = status.LinkByEmail
	settings.SyncRoles = status.SyncRoles
	settings.DefaultRoles = status.DefaultRoles
	settings.RoleMappings = status.Mappings
	return settings
}

// ssoSettingsFromForm reads the editor dialog. Enabling happens here because
// an operator who fills the form in has said what they want it to do.
func ssoSettingsFromForm(request *http.Request) config.OIDC {
	settings := config.DefaultOIDC()
	settings.Enabled = true
	settings.DisplayName = strings.TrimSpace(request.FormValue("display_name"))
	settings.Issuer = strings.TrimSpace(request.FormValue("issuer"))
	settings.ClientID = strings.TrimSpace(request.FormValue("client_id"))
	settings.RedirectURL = strings.TrimSpace(request.FormValue("redirect_url"))
	if scopes := strings.Fields(request.FormValue("scopes")); len(scopes) > 0 {
		settings.Scopes = scopes
	}
	if claim := strings.TrimSpace(request.FormValue("username_claim")); claim != "" {
		settings.UsernameClaim = claim
	}
	if claim := strings.TrimSpace(request.FormValue("groups_claim")); claim != "" {
		settings.GroupsClaim = claim
	}
	settings.Provision = request.FormValue("provision") == "true"
	settings.LinkByVerifiedEmail = request.FormValue("link_by_email") == "true"
	settings.SyncRoles = request.FormValue("sync_roles") == "true"
	settings.DefaultRoles = splitRoleList(request.FormValue("default_roles"))
	settings.RoleMappings = ssoMappingsFromForm(request)
	return settings
}

// ssoMappingsFromForm pairs the group and role inputs by position. A row with
// either half blank is dropped, which is how a mapping is deleted.
func ssoMappingsFromForm(request *http.Request) []config.OIDCRoleMapping {
	groups := request.Form["mapping_group"]
	roles := request.Form["mapping_role"]
	mappings := make([]config.OIDCRoleMapping, 0, len(groups))
	for index, group := range groups {
		group = strings.TrimSpace(group)
		role := ""
		if index < len(roles) {
			role = strings.TrimSpace(roles[index])
		}
		if group == "" || role == "" {
			continue
		}
		mappings = append(mappings, config.OIDCRoleMapping{Group: group, Role: role})
	}
	return mappings
}

func splitRoleList(value string) []string {
	roles := make([]string, 0)
	for _, entry := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			roles = append(roles, trimmed)
		}
	}
	return roles
}

// ssoFormEcho turns rejected settings back into a view so the dialog reopens
// with what the operator typed rather than with what is saved.
func ssoFormEcho(settings config.OIDC) pages.SSOAppView {
	return pages.SSOAppView{
		Available:    true,
		Configured:   true,
		Enabled:      settings.Enabled,
		Label:        settings.Label(),
		Issuer:       settings.Issuer,
		ClientID:     settings.ClientID,
		RedirectURL:  settings.RedirectURL,
		Scopes:       strings.Join(settings.Scopes, " "),
		GroupsClaim:  settings.GroupsClaim,
		Provision:    settings.Provision,
		LinkByEmail:  settings.LinkByVerifiedEmail,
		SyncRoles:    settings.SyncRoles,
		DefaultRoles: strings.Join(settings.DefaultRoles, ", "),
		Mappings:     ssoMappingViews(settings.RoleMappings),
	}
}
