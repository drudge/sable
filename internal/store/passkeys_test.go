package store

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/go-webauthn/webauthn/webauthn"
)

func storedTestPasskey(userID int64, id string) auth.Passkey {
	return auth.Passkey{ID: base64.RawURLEncoding.EncodeToString([]byte(id)), UserID: userID, UserHandle: []byte("opaque-user-handle"), RPID: "sable.example", Name: id, CreatedAt: time.Now().UTC(), Credential: webauthn.Credential{ID: []byte(id), PublicKey: []byte("public-key")}}
}
func TestPasskeyStorageOwnershipAndLastSignInMethod(t *testing.T) {
	database := openIdentityStore(t)
	ctx := context.Background()
	admin := seedAdministrator(t, database)
	key := storedTestPasskey(admin.ID, "primary")
	if err := database.SavePasskey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := database.SavePasskey(ctx, key); err == nil {
		t.Fatal("duplicate credential accepted")
	}
	if err := database.SetPasswordLogin(ctx, admin.ID, false, time.Now()); err != nil {
		t.Fatalf("last administrator cannot use a passkey instead of password: %v", err)
	}
	if err := database.DeletePasskey(ctx, admin.ID+1, key.ID); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("foreign key removal: %v", err)
	}
	if err := database.DeletePasskey(ctx, admin.ID, key.ID); err == nil {
		t.Fatal("removed last passwordless key")
	}
	keys, err := database.PasskeysForUser(ctx, admin.ID)
	if err != nil || len(keys) != 1 {
		t.Fatalf("failed removal was not rolled back: %+v %v", keys, err)
	}
	second := storedTestPasskey(admin.ID, "backup")
	if err := database.SavePasskey(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := database.DeletePasskey(ctx, admin.ID, key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.UserForPasskey(ctx, key.ID); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("removed credential still resolves: %v", err)
	}
	if _, err := database.CreateUser(ctx, "backup-admin", "Backup", "", "hash", []string{"Administrator"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := database.SetUserDisabled(ctx, admin.ID, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.UserForPasskey(ctx, second.ID); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("disabled user resolves: %v", err)
	}
}
func TestPasskeyUpdatesRejectStaleOrDeletedCredentials(t *testing.T) {
	database := openIdentityStore(t)
	ctx := context.Background()
	admin := seedAdministrator(t, database)
	key := storedTestPasskey(admin.ID, "primary")
	if err := database.SavePasskey(ctx, key); err != nil {
		t.Fatal(err)
	}
	updated := key.Credential
	updated.Authenticator.SignCount = 1
	if err := database.UpdatePasskey(ctx, key, updated, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdatePasskey(ctx, key, updated, time.Now()); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("stale counter update accepted: %v", err)
	}
	keys, err := database.PasskeysForUser(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.DeletePasskey(ctx, admin.ID, key.ID); err != nil {
		t.Fatal(err)
	}
	if err := database.UpdatePasskey(ctx, keys[0], updated, time.Now()); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("deleted key update accepted: %v", err)
	}
}
func TestAuthorizationStateRoundTripsPasskeyOnlyAccount(t *testing.T) {
	database := openIdentityStore(t)
	ctx := context.Background()
	seedAdministrator(t, database)
	user, err := database.CreateFederatedUser(ctx, "casey", "Casey", "casey@example.com", []string{"Auditor"}, "oidc", "casey", "https://id.example", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key := storedTestPasskey(user.ID, "primary")
	if err := database.SavePasskey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := database.UnlinkIdentity(ctx, user.ID, "oidc"); err != nil {
		t.Fatalf("cannot switch from OIDC to passkey only: %v", err)
	}
	state, err := database.ExportAuthorizationState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	restored := openIdentityStore(t)
	if err := restored.ReplaceAuthorizationState(ctx, state); err != nil {
		t.Fatal(err)
	}
	keys, err := restored.PasskeysForUser(ctx, user.ID)
	if err != nil || !reflect.DeepEqual(keys, []auth.Passkey{key}) {
		t.Fatalf("round trip keys: %+v %v", keys, err)
	}
	found, err := restored.UserForPasskey(ctx, key.ID)
	if err != nil || found.PasswordLogin || found.PasswordHash != "" {
		t.Fatalf("restored passwordless account: %+v %v", found, err)
	}
	updated := key.Credential
	updated.Authenticator.SignCount = 10
	usedAt := time.Now().UTC()
	if err := restored.UpdatePasskey(ctx, key, updated, usedAt); err != nil {
		t.Fatal(err)
	}
	if err := restored.ReplaceAuthorizationState(ctx, state); err != nil {
		t.Fatal(err)
	}
	keys, err = restored.PasskeysForUser(ctx, user.ID)
	if err != nil || keys[0].Credential.Authenticator.SignCount != 10 || !keys[0].LastUsedAt.Equal(usedAt) {
		t.Fatalf("snapshot rolled back local passkey activity: %+v %v", keys, err)
	}
	// A missing field in a legacy snapshot removes passkeys instead of leaving
	// credentials attached to replaced accounts.
	for index := range state.Users {
		state.Users[index].Passkeys = nil
		if state.Users[index].ID == user.ID {
			state.Users[index].PasswordHash = "restored-password"
			state.Users[index].PasswordLogin = true
		}
	}
	if err := restored.ReplaceAuthorizationState(ctx, state); err != nil {
		t.Fatal(err)
	}
	keys, err = restored.PasskeysForUser(ctx, user.ID)
	if err != nil || len(keys) != 0 {
		t.Fatalf("old passkeys survived replacement: %+v %v", keys, err)
	}
}
