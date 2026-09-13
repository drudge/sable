package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/store"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/webauthn"
)

// These public credentials populate the demo's real Profile view. Their
// private keys are discarded and the fixture password remains enabled; they
// demonstrate the controls without enrolling anything on the viewer's device.
func seedDemoPasskeys(ctx context.Context, dsn string) error {
	database, err := store.Open(ctx, "sqlite", dsn)
	if err != nil {
		return err
	}
	defer database.Close()
	user, err := database.UserByUsername(ctx, operatorUsername)
	if err != nil {
		return err
	}
	handle := make([]byte, 32)
	if _, err := rand.Read(handle); err != nil {
		return err
	}
	clientData, err := json.Marshal(map[string]string{"type": "webauthn.create", "origin": "https://ns1-queens." + clusterDomain, "challenge": "demo"})
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, fixture := range []struct {
		name          string
		age, lastUsed time.Duration
	}{
		{"MacBook Pro (demo)", 30 * 24 * time.Hour, 2 * time.Hour},
		{"iPhone (demo)", 7 * 24 * time.Hour, 24 * time.Hour},
	} {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		public, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: private.X.FillBytes(make([]byte, 32)), -3: private.Y.FillBytes(make([]byte, 32))})
		if err != nil {
			return err
		}
		id := make([]byte, 32)
		if _, err := rand.Read(id); err != nil {
			return err
		}
		key := auth.Passkey{ID: base64.RawURLEncoding.EncodeToString(id), UserID: user.ID, UserHandle: handle, RPID: clusterDomain, Name: fixture.name, CreatedAt: now.Add(-fixture.age), LastUsedAt: now.Add(-fixture.lastUsed), Credential: webauthn.Credential{ID: id, PublicKey: public, Attestation: webauthn.CredentialAttestation{ClientDataJSON: clientData}}}
		if err := database.SavePasskey(ctx, key); err != nil {
			return fmt.Errorf("seed %s: %w", fixture.name, err)
		}
	}
	return nil
}
