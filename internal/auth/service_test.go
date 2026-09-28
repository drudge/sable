package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoginRecordsTheUsernameTriedButNeverThePassword(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name        string
		username    string
		password    string
		wantDetails string
		wantTried   string
	}{
		{
			name: "an account's wrong password", username: "casey", password: "not casey's password",
			wantDetails: "invalid credentials; username=casey", wantTried: "casey",
		},
		{
			name: "a username with no account, as typed", username: "  Root ", password: "toor toor toor",
			wantDetails: "invalid credentials; username=root", wantTried: "root",
		},
		{
			// Someone typing their password into the username field must not
			// leave it in the audit log, so a malformed username is not kept.
			name: "a password typed as the username", username: "Tr0ub4dor&3 horse", password: "Tr0ub4dor&3 horse",
			wantDetails: "invalid credentials; malformed username",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			store := newFakeStore()
			store.addUser("casey", "casey@example.com", "Operator")
			service := newFederatedService(t, store)

			_, err := service.Login(context.Background(), testCase.username, testCase.password, "192.0.2.7", "test-agent")
			if !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("Login() error = %v, want %v", err, ErrInvalidCredential)
			}
			if len(store.audit) != 1 {
				t.Fatalf("audit events = %+v, want one", store.audit)
			}
			event := store.audit[0]
			if event.Action != ActionLoginFailed || event.UserID != nil || event.ClientIP != "192.0.2.7" || event.Details != testCase.wantDetails {
				t.Fatalf("audit event = %+v, want %s from 192.0.2.7 with details %q", event, ActionLoginFailed, testCase.wantDetails)
			}
			for _, field := range []string{event.Action, event.ClientIP, event.UserAgent, event.Details} {
				if strings.Contains(field, testCase.password) {
					t.Fatalf("audit event %+v records the password", event)
				}
			}
			if got := AttemptedUsername(event.Details); got != testCase.wantTried {
				t.Fatalf("AttemptedUsername(%q) = %q, want %q", event.Details, got, testCase.wantTried)
			}
		})
	}
}

func TestLoginRecordsEachLockoutOnce(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	service, err := NewService(store, Options{LoginAttempts: 2, LoginWindow: 15 * time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	attempt := func() error {
		_, err := service.Login(context.Background(), "admin", "a wrong password", "198.51.100.4", "test-agent")
		return err
	}
	actions := func() []string {
		recorded := make([]string, 0, len(store.audit))
		for _, event := range store.audit {
			recorded = append(recorded, event.Action)
		}
		return recorded
	}

	for range 2 {
		if err := attempt(); !errors.Is(err, ErrInvalidCredential) {
			t.Fatalf("attempt within the limit error = %v", err)
		}
	}
	// Every request the lockout turns away is refused, but only the first is
	// recorded.
	for range 3 {
		if err := attempt(); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("attempt past the limit error = %v, want %v", err, ErrRateLimited)
		}
	}
	want := []string{ActionLoginFailed, ActionLoginFailed, ActionLoginLocked}
	if got := actions(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("audit actions = %v, want %v", got, want)
	}
	if locked := store.audit[2]; locked.Details != "too many failed sign-ins; username=admin" || locked.ClientIP != "198.51.100.4" {
		t.Fatalf("lockout event = %+v", locked)
	}

	// Once the window passes, a new run of failures can lock the account
	// again, and that lockout is recorded too.
	now = now.Add(15 * time.Minute)
	for range 3 {
		_ = attempt()
	}
	want = append(want, ActionLoginFailed, ActionLoginFailed, ActionLoginLocked)
	if got := actions(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("audit actions after the window = %v, want %v", got, want)
	}
}

func TestFederatedLoginRecordsEachLockoutOnce(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	service, err := NewService(store, Options{LoginAttempts: 1})
	if err != nil {
		t.Fatal(err)
	}
	policy := defaultPolicy()
	policy.Provision = false
	identity := FederatedIdentity{Subject: "stranger", Username: "stranger"}

	if _, err := service.FederatedLogin(context.Background(), identity, policy, "203.0.113.9", "test"); !errors.Is(err, ErrNoFederatedAccount) {
		t.Fatalf("first sign-in error = %v, want %v", err, ErrNoFederatedAccount)
	}
	for range 2 {
		if _, err := service.FederatedLogin(context.Background(), identity, policy, "203.0.113.9", "test"); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("sign-in past the limit error = %v, want %v", err, ErrRateLimited)
		}
	}
	if len(store.audit) != 2 || store.audit[0].Action != ActionFederatedDenied || store.audit[1].Action != ActionLoginLocked ||
		store.audit[1].ClientIP != "203.0.113.9" {
		t.Fatalf("audit events = %+v, want the denial and one lockout", store.audit)
	}
}

// Every passkey sign-in counts against the client's budget before the browser
// is asked for a passkey, so a client that keeps trying is turned away, and
// that lockout is recorded once like any other.
func TestPasskeyAttemptsRecordEachLockoutOnce(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	service, err := NewService(store, Options{LoginAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := service.AllowPasskeyAttempt(context.Background(), "203.0.113.7", "test"); err != nil {
			t.Fatalf("attempt within the limit error = %v", err)
		}
	}
	for range 3 {
		if err := service.AllowPasskeyAttempt(context.Background(), "203.0.113.7", "test"); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("attempt past the limit error = %v, want %v", err, ErrRateLimited)
		}
	}
	if len(store.audit) != 1 || store.audit[0].Action != ActionLoginLocked || store.audit[0].ClientIP != "203.0.113.7" ||
		store.audit[0].Details != "too many passkey sign-in attempts" {
		t.Fatalf("audit events = %+v, want one lockout", store.audit)
	}
}

func TestAttemptedUsernameReadsOnlyARecordedUsername(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		details string
		want    string
	}{
		{details: "invalid credentials; username=casey", want: "casey"},
		{details: "too many failed sign-ins; username=admin", want: "admin"},
		{details: "invalid credentials; malformed username"},
		// Records written before usernames were kept name none.
		{details: "invalid credentials"},
		{details: "passkey verification failed"},
		{details: "pocket-id subject username=x has no linked account"},
	} {
		if got := AttemptedUsername(testCase.details); got != testCase.want {
			t.Errorf("AttemptedUsername(%q) = %q, want %q", testCase.details, got, testCase.want)
		}
	}
}
