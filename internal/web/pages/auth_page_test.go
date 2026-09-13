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
		})
	}
}
