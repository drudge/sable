package pages

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestAuthPageGroupsAlternateSignInMethods(t *testing.T) {
	for _, test := range []struct {
		name, sso       string
		passkeys, setup bool
		dividers        int
	}{
		{"both", "Pocket ID", true, false, 1},
		{"oidc only", "Pocket ID", false, false, 1},
		{"passkey only", "", true, false, 1},
		{"password only", "", false, false, 0},
		{"setup", "Pocket ID", true, true, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var body bytes.Buffer
			if err := AuthPage(test.setup, "", "csrf", "/", test.sso, test.passkeys).Render(context.Background(), &body); err != nil {
				t.Fatal(err)
			}
			html := body.String()
			brand := strings.Index(html, `class="auth-brand"`)
			card := strings.Index(html, `class="auth-card"`)
			if brand < 0 || card < 0 || brand > card || !strings.Contains(html, `<strong>Sable</strong>`) {
				t.Fatal("brand should be rendered outside the authentication card")
			}
			if !strings.Contains(html, `data-dialog-open="mit-license-dialog"`) ||
				!strings.Contains(html, `id="mit-license-dialog"`) ||
				!strings.Contains(html, "Copyright (c) 2026 Nicholas Penree") ||
				!strings.Contains(html, `href="https://github.com/drudge/sable/blob/main/LICENSE"`) {
				t.Fatal("authentication page should provide an in-app MIT license dialog with a repository link")
			}
			// Third-party licenses load for a signed-in operator, from About.
			if strings.Contains(html, "third-party-licenses-dialog") {
				t.Error("authentication page offers third-party licenses it cannot load")
			}
			if got := strings.Count(html, `class="auth-divider"`); got != test.dividers {
				t.Fatalf("got %d dividers, want %d", got, test.dividers)
			}
			divider := strings.Index(html, `class="auth-divider"`)
			if test.dividers > 0 && divider > strings.Index(html, `name="username"`) {
				t.Fatal("divider should precede password form")
			}
			if test.passkeys && !test.setup && divider < strings.Index(html, `data-passkey-action="login"`) {
				t.Fatal("divider split alternate sign-in buttons")
			}
			if test.sso == "" && test.passkeys && !test.setup && !strings.Contains(html, `class="auth-divider" data-passkey-capability`) {
				t.Fatal("passkey-only divider must hide with unsupported passkeys")
			}
			if test.passkeys && !test.setup && !strings.Contains(html, `class="auth-error" role="status" data-passkey-status`) {
				t.Fatal("passkey status should use the authentication error treatment")
			}
			if test.passkeys && !test.setup && strings.Index(html, `data-passkey-status`) > strings.Index(html, `data-passkey-action="login"`) {
				t.Fatal("passkey status should appear above the passkey button")
			}
		})
	}
}
