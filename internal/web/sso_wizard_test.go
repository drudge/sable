package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/web/pages"
)

// fakeSSOAdmin records what the wizard asked it to do. The wizard's job is to
// collect answers across four round trips and hand over one configuration, so
// what it finally saves is what these tests assert on.
type fakeSSOAdmin struct {
	status    SSOStatusView
	probe     SSOProbeResult
	probeErr  error
	saveErr   error
	saved     config.OIDC
	saveCalls int
	secrets   []string
}

func (fake *fakeSSOAdmin) Status(context.Context) SSOStatusView { return fake.status }
func (fake *fakeSSOAdmin) Check(context.Context) SSOStatusView  { return fake.status }

func (fake *fakeSSOAdmin) Save(_ context.Context, settings config.OIDC, _ string) error {
	fake.saveCalls++
	if fake.saveErr != nil {
		return fake.saveErr
	}
	fake.saved = settings
	return nil
}

func (fake *fakeSSOAdmin) Remove(context.Context) error { return nil }

func (fake *fakeSSOAdmin) Probe(_ context.Context, _ config.OIDC, _ string) (SSOProbeResult, error) {
	if fake.probeErr != nil {
		return SSOProbeResult{}, fake.probeErr
	}
	return fake.probe, nil
}

func (fake *fakeSSOAdmin) PutSecret(_ context.Context, secret string) error {
	fake.secrets = append(fake.secrets, secret)
	return nil
}

// staticConfig and staticStats are the smallest sources the integrations page
// will render against.
type staticConfig struct{ snapshot config.Snapshot }

func (source staticConfig) Current() config.Snapshot { return source.snapshot }

type staticQueryLog struct{}

func (staticQueryLog) Stats() querylog.Stats { return querylog.Stats{} }

type staticStats struct{}

func (staticStats) Stats() dnsserver.Stats                      { return dnsserver.Stats{} }
func (staticStats) PurgeCache() int                             { return 0 }
func (staticStats) CachedResponses() []dnsserver.CachedResponse { return nil }

func newWizardServer(t *testing.T, admin *fakeSSOAdmin) *Server {
	t.Helper()
	return &Server{
		logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		securityEnabled: true,
		ssoAdmin:        admin,
		crossOrigin:     &http.CrossOriginProtection{},
		config:          staticConfig{snapshot: config.Snapshot{Config: config.Defaults(), Revision: 1}},
		stats:           staticStats{},
		queryLog:        staticQueryLog{},
		history:         newStatsHistory(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
}

func postWizard(t *testing.T, server *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://dns.example.test/ui/integrations/sso/wizard",
		strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.runSSOWizard(response, request)
	return response
}

// providerAnswers is the first step filled in, which every later step re-posts.
func providerAnswers() url.Values {
	return url.Values{
		"display_name": {"Pocket ID"},
		"issuer":       {"https://id.example.com"},
		"client_id":    {"sable"},
		"redirect_url": {"https://dns.example.test/auth/oidc/callback"},
	}
}

func TestWizardAdvancesOneStepAtATime(t *testing.T) {
	admin := &fakeSSOAdmin{probe: SSOProbeResult{Issuer: "https://id.example.com", SupportsPKCE: true}}
	server := newWizardServer(t, admin)

	form := providerAnswers()
	form.Set("wizard_step", pages.SSOStepProvider)
	form.Set("client_secret", "secret-1")
	response := postWizard(t, server, form)
	if !strings.Contains(response.Body.String(), `name="wizard_step" value="`+pages.SSOStepClaims+`"`) {
		t.Fatal("the provider step did not advance to the claims step")
	}

	form = providerAnswers()
	form.Set("wizard_step", pages.SSOStepClaims)
	form.Set("claims_present", "true")
	form.Set("scopes", "openid profile email groups")
	form.Set("groups_claim", "groups")
	response = postWizard(t, server, form)
	if !strings.Contains(response.Body.String(), `name="wizard_step" value="`+pages.SSOStepRoles+`"`) {
		t.Fatal("the claims step did not advance to the roles step")
	}

	form.Set("wizard_step", pages.SSOStepRoles)
	form.Set("roles_present", "true")
	form.Set("provision", "true")
	response = postWizard(t, server, form)
	if !strings.Contains(response.Body.String(), `name="wizard_step" value="`+pages.SSOStepReview+`"`) {
		t.Fatal("the roles step did not advance to the review step")
	}
	if admin.saveCalls != 0 {
		t.Fatal("the wizard saved before reaching the review step")
	}
}

// A provider Sable cannot reach is caught on the first step, so an operator is
// not asked to fill in claims and roles for something that will never work.
func TestWizardStopsOnAProviderItCannotReach(t *testing.T) {
	admin := &fakeSSOAdmin{probeErr: errors.New("read provider metadata: connection refused")}
	server := newWizardServer(t, admin)

	form := providerAnswers()
	form.Set("wizard_step", pages.SSOStepProvider)
	form.Set("client_secret", "secret-1")
	response := postWizard(t, server, form)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
	body := response.Body.String()
	if !strings.Contains(body, `name="wizard_step" value="`+pages.SSOStepProvider+`"`) {
		t.Fatal("the wizard advanced past a provider it could not reach")
	}
	if !strings.Contains(body, "connection refused") {
		t.Fatal("the wizard did not report why the provider could not be reached")
	}
}

// The secret is stored as soon as the provider answers, so the later steps do
// not have to carry it back and forth through the browser.
func TestWizardStoresTheSecretOnceTheProviderAnswers(t *testing.T) {
	admin := &fakeSSOAdmin{probe: SSOProbeResult{Issuer: "https://id.example.com"}}
	server := newWizardServer(t, admin)

	form := providerAnswers()
	form.Set("wizard_step", pages.SSOStepProvider)
	form.Set("client_secret", "secret-1")
	body := postWizard(t, server, form).Body.String()

	if len(admin.secrets) != 1 || admin.secrets[0] != "secret-1" {
		t.Fatalf("stored secrets = %v, want the one the operator typed", admin.secrets)
	}
	if strings.Contains(body, "secret-1") {
		t.Fatal("the client secret was written back into the page")
	}
}

func TestWizardRequiresASecretWhenNoneIsStored(t *testing.T) {
	admin := &fakeSSOAdmin{probe: SSOProbeResult{Issuer: "https://id.example.com"}}
	server := newWizardServer(t, admin)

	form := providerAnswers()
	form.Set("wizard_step", pages.SSOStepProvider)
	response := postWizard(t, server, form)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
	if !strings.Contains(response.Body.String(), "client secret is required") {
		t.Fatal("the wizard did not ask for the missing client secret")
	}
}

// A returning operator leaves the secret blank to keep the stored one.
func TestWizardKeepsAStoredSecret(t *testing.T) {
	admin := &fakeSSOAdmin{
		status: SSOStatusView{SecretStored: true},
		probe:  SSOProbeResult{Issuer: "https://id.example.com"},
	}
	server := newWizardServer(t, admin)

	form := providerAnswers()
	form.Set("wizard_step", pages.SSOStepProvider)
	response := postWizard(t, server, form)

	if !strings.Contains(response.Body.String(), `name="wizard_step" value="`+pages.SSOStepClaims+`"`) {
		t.Fatal("a blank secret was refused even though one is stored")
	}
	if len(admin.secrets) != 0 {
		t.Fatal("a blank secret overwrote the stored one")
	}
}

func TestWizardSavesEverythingItCollected(t *testing.T) {
	admin := &fakeSSOAdmin{probe: SSOProbeResult{Issuer: "https://id.example.com"}}
	server := newWizardServer(t, admin)

	form := providerAnswers()
	form.Set("wizard_step", pages.SSOStepReview)
	form.Set("claims_present", "true")
	form.Set("roles_present", "true")
	form.Set("scopes", "openid profile email groups")
	form.Set("username_claim", "preferred_username")
	form.Set("groups_claim", "groups")
	form.Set("provision", "true")
	form.Set("link_by_email", "true")
	form.Set("sync_roles", "true")
	form.Set("default_roles", "Auditor")
	form["mapping_group"] = []string{"dns-admins", "noc"}
	form["mapping_role"] = []string{"Administrator", "Operator"}

	if response := postWizard(t, server, form); response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	saved := admin.saved
	if !saved.Enabled {
		t.Error("the wizard saved a provider that is switched off")
	}
	if saved.Issuer != "https://id.example.com" || saved.ClientID != "sable" {
		t.Errorf("saved issuer/client = %q/%q", saved.Issuer, saved.ClientID)
	}
	if strings.Join(saved.Scopes, " ") != "openid profile email groups" {
		t.Errorf("saved scopes = %v", saved.Scopes)
	}
	if len(saved.RoleMappings) != 2 ||
		saved.RoleMappings[0] != (config.OIDCRoleMapping{Group: "dns-admins", Role: "Administrator"}) ||
		saved.RoleMappings[1] != (config.OIDCRoleMapping{Group: "noc", Role: "Operator"}) {
		t.Errorf("saved mappings = %v", saved.RoleMappings)
	}
	if strings.Join(saved.DefaultRoles, ",") != "Auditor" {
		t.Errorf("saved default roles = %v", saved.DefaultRoles)
	}
}

// A row with either half blank is how a mapping is deleted, so it must not
// reach the configuration as a half-formed rule.
func TestWizardDropsIncompleteMappings(t *testing.T) {
	admin := &fakeSSOAdmin{probe: SSOProbeResult{Issuer: "https://id.example.com"}}
	server := newWizardServer(t, admin)

	form := providerAnswers()
	form.Set("wizard_step", pages.SSOStepReview)
	form.Set("claims_present", "true")
	form.Set("roles_present", "true")
	form.Set("provision", "true")
	form["mapping_group"] = []string{"dns-admins", "", "orphan"}
	form["mapping_role"] = []string{"Administrator", "Operator", ""}

	postWizard(t, server, form)

	if len(admin.saved.RoleMappings) != 1 || admin.saved.RoleMappings[0].Group != "dns-admins" {
		t.Fatalf("saved mappings = %v, want only the complete row", admin.saved.RoleMappings)
	}
}

// Back has to work from a half-filled step, or an operator who mistyped the
// issuer cannot get back to fix it.
func TestWizardBackReturnsToAnEarlierStep(t *testing.T) {
	admin := &fakeSSOAdmin{probe: SSOProbeResult{Issuer: "https://id.example.com"}}
	server := newWizardServer(t, admin)

	form := providerAnswers()
	form.Set("wizard_step", pages.SSOStepRoles)
	form.Set("wizard_target", pages.SSOStepProvider)
	response := postWizard(t, server, form)

	body := response.Body.String()
	if !strings.Contains(body, `name="wizard_step" value="`+pages.SSOStepProvider+`"`) {
		t.Fatal("Back did not return to the provider step")
	}
	if !strings.Contains(body, "https://id.example.com") {
		t.Fatal("Back lost the answers the operator had already given")
	}
	if admin.saveCalls != 0 {
		t.Fatal("Back saved the provider")
	}
}

// A node with no override has to show the callback it will actually use, so the
// operator can register it without first inventing a value to make it appear.
func TestWizardShowsTheDerivedCallbackWithoutAnOverride(t *testing.T) {
	status := configuredProvider()
	status.RedirectOverride = ""
	status.RedirectURL = "https://ns2.example.test/auth/oidc/callback"
	server := newWizardServer(t, &fakeSSOAdmin{status: status})

	wizard := server.newSSOWizard(httptest.NewRequest(http.MethodGet, "https://ns2.example.test/integrations", nil))
	if wizard.RedirectURL != "" {
		t.Fatalf("the override field was prefilled with %q", wizard.RedirectURL)
	}
	if wizard.DerivedRedirectURL != status.RedirectURL {
		t.Fatalf("derived callback = %q, want %q", wizard.DerivedRedirectURL, status.RedirectURL)
	}
}

// An operator who set an override has to see it in the field, not as a hint
// they could scroll past and overwrite with the derived value.
func TestWizardShowsAnOverrideInTheField(t *testing.T) {
	status := configuredProvider()
	status.RedirectOverride = "https://dns.example.test/auth/oidc/callback"
	status.RedirectURL = status.RedirectOverride
	server := newWizardServer(t, &fakeSSOAdmin{status: status})

	wizard := server.newSSOWizard(httptest.NewRequest(http.MethodGet, "https://ns2.example.test/integrations", nil))
	if wizard.RedirectURL != status.RedirectOverride {
		t.Fatalf("override field = %q, want %q", wizard.RedirectURL, status.RedirectOverride)
	}
}

// configuredProvider is a provider that is already set up, which is what an
// operator sees when they choose Edit Setup rather than starting fresh.
func configuredProvider() SSOStatusView {
	return SSOStatusView{
		Configured:    true,
		Enabled:       true,
		Label:         "Pocket ID",
		Issuer:        "https://id.example.com",
		ClientID:      "sable",
		RedirectURL:   "https://dns.example.test/auth/oidc/callback",
		Scopes:        []string{"openid", "profile", "email", "groups"},
		UsernameClaim: "preferred_username",
		GroupsClaim:   "groups",
		Provision:     false,
		LinkByEmail:   false,
		SyncRoles:     true,
		DefaultRoles:  []string{"Auditor"},
		Mappings:      []config.OIDCRoleMapping{{Group: "dns-admins", Role: "Administrator"}},
		SecretStored:  true,
	}
}

// Editing an existing provider walks the same steps as first-time setup, and
// the early steps do not collect roles. Those answers have to be seeded from
// what is saved, or an operator who clicks through loses every mapping they
// had.
func TestWizardKeepsSavedMappingsWhileEditing(t *testing.T) {
	admin := &fakeSSOAdmin{status: configuredProvider(), probe: SSOProbeResult{Issuer: "https://id.example.com"}}
	server := newWizardServer(t, admin)

	// Advance to the roles step, which is where the mappings are edited. The
	// assertions target the wizard's own inputs rather than any text on the
	// page, because the card behind the dialog also lists the saved mappings
	// and would mask the bug.
	form := providerAnswers()
	form.Set("wizard_step", pages.SSOStepClaims)
	form.Set("claims_present", "true")
	form.Set("scopes", "openid profile email groups")
	form.Set("groups_claim", "groups")
	body := postWizard(t, server, form).Body.String()

	if !strings.Contains(body, `name="mapping_group" value="dns-admins"`) {
		t.Fatal("the roles step did not load the saved group mapping")
	}
	if !strings.Contains(body, `name="default_roles" value="Auditor"`) {
		t.Fatal("the roles step did not load the saved default roles")
	}
}

// The same gap would quietly re-enable settings the operator had turned off,
// because an unchecked box on a step that never asked is not an answer.
func TestWizardDoesNotResurrectSettingsTheOperatorTurnedOff(t *testing.T) {
	admin := &fakeSSOAdmin{status: configuredProvider(), probe: SSOProbeResult{Issuer: "https://id.example.com"}}
	server := newWizardServer(t, admin)

	form := providerAnswers()
	form.Set("wizard_step", pages.SSOStepReview)
	postWizard(t, server, form)

	if admin.saved.Provision {
		t.Error("provisioning was switched back on by a step that never asked about it")
	}
	if admin.saved.LinkByVerifiedEmail {
		t.Error("email linking was switched back on by a step that never asked about it")
	}
	if len(admin.saved.RoleMappings) != 1 || admin.saved.RoleMappings[0].Group != "dns-admins" {
		t.Errorf("saved mappings = %v, want the existing mapping to survive", admin.saved.RoleMappings)
	}
}

// Claims are carried by the provider step's hidden fields, but an operator
// arriving at a later step must not fall back to the defaults either.
func TestWizardKeepsSavedClaimsWhileEditing(t *testing.T) {
	status := configuredProvider()
	status.GroupsClaim = "roles"
	status.Scopes = []string{"openid", "profile", "email", "roles"}
	admin := &fakeSSOAdmin{status: status, probe: SSOProbeResult{Issuer: "https://id.example.com"}}
	server := newWizardServer(t, admin)

	form := providerAnswers()
	form.Set("wizard_step", pages.SSOStepReview)
	postWizard(t, server, form)

	if admin.saved.GroupsClaim != "roles" {
		t.Errorf("saved groups claim = %q, want the configured one", admin.saved.GroupsClaim)
	}
	if strings.Join(admin.saved.Scopes, " ") != "openid profile email roles" {
		t.Errorf("saved scopes = %v, want the configured ones", admin.saved.Scopes)
	}
}
