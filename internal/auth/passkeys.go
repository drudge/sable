package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

const MaximumPasskeys = 20

// Passkey holds the public credential and its account-bound user handle. Private
// keys stay on the authenticator; no biometric data is sent to Sable.
type Passkey struct {
	ID         string              `json:"id"`
	UserID     int64               `json:"user_id"`
	UserHandle []byte              `json:"user_handle"`
	RPID       string              `json:"rp_id"`
	Name       string              `json:"name"`
	Credential webauthn.Credential `json:"credential"`
	CreatedAt  time.Time           `json:"created_at"`
	LastUsedAt time.Time           `json:"last_used_at"`
}

type PasskeyStore interface {
	PasskeysForUser(context.Context, int64) ([]Passkey, error)
	UserForPasskey(context.Context, string) (User, error)
	SavePasskey(context.Context, Passkey) error
	UpdatePasskey(context.Context, Passkey, webauthn.Credential, time.Time) error
	DeletePasskey(context.Context, int64, string) error
}

type PasskeyUser struct {
	User
	Handle []byte
	Keys   []webauthn.Credential
}

func (user PasskeyUser) WebAuthnID() []byte   { return user.Handle }
func (user PasskeyUser) WebAuthnName() string { return user.Username }
func (user PasskeyUser) WebAuthnDisplayName() string {
	if user.DisplayName != "" {
		return user.DisplayName
	}
	return user.Username
}
func (user PasskeyUser) WebAuthnCredentials() []webauthn.Credential { return user.Keys }

func (service *Service) Passkeys(ctx context.Context, principal Principal) ([]Passkey, error) {
	store, ok := service.store.(PasskeyStore)
	if !ok {
		return nil, errors.New("passkey storage unavailable")
	}
	return store.PasskeysForUser(ctx, principal.UserID)
}

func (service *Service) PasskeyAccount(ctx context.Context, username, rpID string) (PasskeyUser, error) {
	user, err := service.store.UserByUsername(ctx, username)
	if err != nil || !user.LoginAllowed {
		return PasskeyUser{}, ErrUnauthorized
	}
	keys, err := service.Passkeys(ctx, Principal{UserID: user.ID})
	if err != nil {
		return PasskeyUser{}, err
	}
	result := PasskeyUser{User: user}
	for _, key := range keys {
		if key.RPID == rpID {
			result.Handle = key.UserHandle
			result.Keys = append(result.Keys, key.Credential)
		}
	}
	if result.Handle == nil {
		result.Handle = make([]byte, 32)
		if _, err := rand.Read(result.Handle); err != nil {
			return PasskeyUser{}, err
		}
	}
	return result, nil
}

func (service *Service) DiscoverPasskey(ctx context.Context, credentialID []byte, rpID string) (PasskeyUser, Passkey, error) {
	store, ok := service.store.(PasskeyStore)
	if !ok {
		return PasskeyUser{}, Passkey{}, ErrUnauthorized
	}
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	user, err := store.UserForPasskey(ctx, id)
	if err != nil {
		return PasskeyUser{}, Passkey{}, ErrUnauthorized
	}
	account, err := service.PasskeyAccount(ctx, user.Username, rpID)
	if err != nil {
		return PasskeyUser{}, Passkey{}, err
	}
	keys, err := store.PasskeysForUser(ctx, user.ID)
	if err != nil {
		return PasskeyUser{}, Passkey{}, err
	}
	for _, key := range keys {
		if key.ID == id && key.RPID == rpID {
			account.Handle = key.UserHandle
			return account, key, nil
		}
	}
	return PasskeyUser{}, Passkey{}, ErrUnauthorized
}

func (service *Service) AddPasskey(ctx context.Context, principal Principal, account PasskeyUser, rpID, name string, credential webauthn.Credential, clientIP, userAgent string) error {
	if principal.AuthenticatedByToken || principal.UserID != account.ID {
		return ErrForbidden
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return errors.New("passkey name must contain 1 to 100 characters")
	}
	store, ok := service.store.(PasskeyStore)
	if !ok {
		return errors.New("passkey storage unavailable")
	}
	key := Passkey{ID: base64.RawURLEncoding.EncodeToString(credential.ID), UserID: account.ID, UserHandle: account.Handle, RPID: rpID, Name: name, Credential: credential, CreatedAt: service.now()}
	if err := store.SavePasskey(ctx, key); err != nil {
		return err
	}
	service.audit(ctx, &principal.UserID, "passkey.create", clientIP, userAgent, "passkey_id="+key.ID)
	return nil
}

func (service *Service) CompletePasskeyLogin(ctx context.Context, key Passkey, credential webauthn.Credential, clientIP, userAgent string) (Credentials, error) {
	store, ok := service.store.(PasskeyStore)
	if !ok || credential.Authenticator.CloneWarning {
		return Credentials{}, ErrUnauthorized
	}
	user, err := store.UserForPasskey(ctx, key.ID)
	if err != nil || !user.LoginAllowed {
		return Credentials{}, ErrUnauthorized
	}
	if err := store.UpdatePasskey(ctx, key, credential, service.now()); err != nil {
		return Credentials{}, err
	}
	credentials, err := service.newSession(ctx, user.ID, service.now())
	if err == nil {
		service.limiter.success("passkey\x00" + clientIP)
		service.audit(ctx, &user.ID, "auth.login.passkey", clientIP, userAgent, "passkey_id="+key.ID)
	}
	return credentials, err
}

func (service *Service) RemovePasskey(ctx context.Context, principal Principal, id, clientIP, userAgent string) error {
	store, ok := service.store.(PasskeyStore)
	if !ok || principal.AuthenticatedByToken {
		return ErrForbidden
	}
	if err := store.DeletePasskey(ctx, principal.UserID, id); err != nil {
		return err
	}
	service.audit(ctx, &principal.UserID, "passkey.delete", clientIP, userAgent, "passkey_id="+id)
	return nil
}

func (service *Service) DisableOwnPassword(ctx context.Context, principal Principal, clientIP, userAgent string) error {
	keys, err := service.Passkeys(ctx, principal)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("add a passkey before disabling your password")
	}
	store, ok := service.store.(AdministrationStore)
	if !ok || principal.AuthenticatedByToken {
		return ErrForbidden
	}
	if err := store.SetPasswordLogin(ctx, principal.UserID, false, service.now()); err != nil {
		return err
	}
	service.audit(ctx, &principal.UserID, "user.password_login.update.self", clientIP, userAgent, "password_login=off")
	return nil
}

func (service *Service) EnableOwnPassword(ctx context.Context, principal Principal, clientIP, userAgent string) error {
	store, ok := service.store.(AdministrationStore)
	if !ok || principal.AuthenticatedByToken {
		return ErrForbidden
	}
	user, err := service.store.UserByUsername(ctx, principal.Username)
	if err != nil || user.ID != principal.UserID || !user.LoginAllowed {
		return ErrUnauthorized
	}
	if user.PasswordHash == "" {
		return errors.New("set a password before enabling password sign-in")
	}
	if err := store.SetPasswordLogin(ctx, principal.UserID, true, service.now()); err != nil {
		return err
	}
	service.audit(ctx, &principal.UserID, "user.password_login.update.self", clientIP, userAgent, "password_login=on")
	return nil
}

func (service *Service) AllowPasskeyAttempt(clientIP string) error {
	key := "passkey\x00" + clientIP
	now := service.now()
	if !service.limiter.allow(key, now) {
		return ErrRateLimited
	}
	service.limiter.failure(key, now)
	return nil
}

func (service *Service) RecordPasskeyFailure(ctx context.Context, clientIP, userAgent string) {
	service.audit(ctx, nil, "auth.login.passkey.failed", clientIP, userAgent, "passkey verification failed")
}

// ValidatePasskeyDisable checks the alternate sign-in methods before hiding passkeys.
func (service *Service) ValidatePasskeyDisable(ctx context.Context, oidcIssuer string) error {
	store, ok := service.store.(AdministrationStore)
	if !ok {
		return ErrForbidden
	}
	users, err := store.ListUsers(ctx)
	if err != nil {
		return err
	}
	for _, user := range users {
		if user.Disabled {
			continue
		}
		account, err := service.store.UserByUsername(ctx, user.Username)
		if err != nil {
			return err
		}
		if user.PasswordLogin && account.PasswordHash != "" {
			continue
		}
		linked := false
		for _, identity := range user.Identities {
			if oidcIssuer != "" && identity.Issuer == oidcIssuer {
				linked = true
				break
			}
		}
		if !linked {
			return fmt.Errorf("enable password sign-in or link the enabled identity provider for %s before disabling passkeys", user.Username)
		}
	}
	return nil
}
