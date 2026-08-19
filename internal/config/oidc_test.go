package config

import (
	"strings"
	"testing"
	"time"
)

func TestOIDCValidateRejectsUnusableSettings(t *testing.T) {
	base := func() OIDC {
		settings := DefaultOIDC()
		settings.Enabled = true
		settings.Issuer = "https://id.example.com"
		settings.ClientID = "sable"
		settings.RedirectURL = "https://dns.example.com/auth/oidc/callback"
		return settings
	}
	tests := []struct {
		name    string
		adjust  func(*OIDC)
		wantErr string
	}{
		{"no issuer", func(settings *OIDC) { settings.Issuer = "" }, "oidc.issuer is required"},
		{"plaintext issuer", func(settings *OIDC) { settings.Issuer = "http://id.example.com" }, "oidc.issuer must use https"},
		{"no client id", func(settings *OIDC) { settings.ClientID = "" }, "oidc.client_id is required"},
		{"relative redirect", func(settings *OIDC) { settings.RedirectURL = "/auth/oidc/callback" }, "must be an absolute URL"},
		{"redirect with a query", func(settings *OIDC) { settings.RedirectURL = "https://dns.example.com/cb?next=/" }, "must not carry a query"},
		{"scopes without openid", func(settings *OIDC) { settings.Scopes = []string{"profile"} }, "must contain openid"},
		{"nobody can ever sign in", func(settings *OIDC) {
			settings.Provision = false
			settings.LinkByVerifiedEmail = false
		}, "no one can ever sign in"},
		{"skew wide enough to matter", func(settings *OIDC) {
			settings.ClockSkew = Duration{Duration: time.Hour}
		}, "oidc.clock_skew must be at most"},
		{"duplicate group mapping", func(settings *OIDC) {
			settings.RoleMappings = []OIDCRoleMapping{{Group: "noc", Role: "Operator"}, {Group: "noc", Role: "Viewer"}}
		}, "duplicate oidc role mapping"},
		{"mapping without a role", func(settings *OIDC) {
			settings.RoleMappings = []OIDCRoleMapping{{Group: "noc"}}
		}, "role is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := base()
			test.adjust(&settings)
			err := settings.Validate()
			if err == nil {
				t.Fatal("settings were accepted, want a rejection")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err, test.wantErr)
			}
		})
	}
}

// Settings that are switched off are not held to the rules a live provider
// must meet, so an operator can leave a half-filled section in place.
func TestOIDCValidateIgnoresAnUnconfiguredProvider(t *testing.T) {
	if err := DefaultOIDC().Validate(); err != nil {
		t.Fatalf("default settings were rejected: %v", err)
	}
}

// A loopback issuer is how a developer or a test harness runs a throwaway
// provider, and refusing it would make local work impossible.
func TestOIDCValidateAllowsALoopbackProvider(t *testing.T) {
	settings := DefaultOIDC()
	settings.Enabled = true
	settings.Issuer = "http://localhost:1411"
	settings.ClientID = "sable"
	settings.RedirectURL = "http://127.0.0.1:8080/auth/oidc/callback"
	if err := settings.Validate(); err != nil {
		t.Fatalf("loopback provider was rejected: %v", err)
	}
}

func TestOIDCMappedRolesResolvesGroupsAndDefaults(t *testing.T) {
	settings := DefaultOIDC()
	settings.DefaultRoles = []string{"Viewer"}
	settings.RoleMappings = []OIDCRoleMapping{
		{Group: "dns-admins", Role: "Administrator"},
		{Group: "noc", Role: "Operator"},
	}

	roles := settings.MappedRoles([]string{"noc", "unmapped-group", "dns-admins", "noc"})
	if strings.Join(roles, ",") != "Administrator,Operator,Viewer" {
		t.Fatalf("roles = %v, want Administrator, Operator, Viewer", roles)
	}
	// Someone with no mapped group still earns the default roles, and nothing
	// more.
	if roles := settings.MappedRoles(nil); strings.Join(roles, ",") != "Viewer" {
		t.Fatalf("roles for no groups = %v, want Viewer", roles)
	}
}

// The set of roles the provider may touch has to include the defaults, or a
// user removed from every mapped group would keep a default role forever.
func TestOIDCManagedRolesCoversMappingsAndDefaults(t *testing.T) {
	settings := DefaultOIDC()
	settings.DefaultRoles = []string{"Viewer"}
	settings.RoleMappings = []OIDCRoleMapping{{Group: "noc", Role: "Operator"}}
	if managed := settings.ManagedRoles(); strings.Join(managed, ",") != "Operator,Viewer" {
		t.Fatalf("managed = %v, want Operator, Viewer", managed)
	}
}

// Group names are opaque identifiers at the provider, so two that differ only
// in case are two different groups.
func TestOIDCRoleForIsCaseSensitive(t *testing.T) {
	settings := DefaultOIDC()
	settings.RoleMappings = []OIDCRoleMapping{{Group: "NOC", Role: "Operator"}}
	if _, mapped := settings.RoleFor("noc"); mapped {
		t.Fatal("a differently cased group name matched a mapping")
	}
}
