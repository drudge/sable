package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseJSONWebKeyRejectsUnusableKeys(t *testing.T) {
	// A modulus long enough to pass the size floor, so each case fails for the
	// one reason it is testing rather than for its length.
	longModulus := base64.RawURLEncoding.EncodeToString(new(big.Int).Lsh(big.NewInt(1), 2047).Bytes())
	exponent := base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes())

	tests := []struct {
		name string
		key  jsonWebKey
	}{
		{"unknown key type", jsonWebKey{KeyType: "OKP", Curve: "Ed25519"}},
		{"rsa modulus too short", jsonWebKey{KeyType: "RSA", Modulus: base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}), Exponent: exponent}},
		{"rsa modulus not base64url", jsonWebKey{KeyType: "RSA", Modulus: "not!base64", Exponent: exponent}},
		{"rsa exponent of one", jsonWebKey{KeyType: "RSA", Modulus: longModulus, Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes())}},
		{"unknown curve", jsonWebKey{KeyType: "EC", Curve: "P-192", X: "AA", Y: "AA"}},
		{"ec coordinate wrong width", jsonWebKey{KeyType: "EC", Curve: "P-256", X: "AAAA", Y: "AAAA"}},
		{"ec point off the curve", jsonWebKey{
			KeyType: "EC",
			Curve:   "P-256",
			X:       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			Y:       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseJSONWebKey(test.key); err == nil {
				t.Fatal("key was accepted, want a rejection")
			}
		})
	}
}

// A provider that rotates its signing key publishes a new identifier. The
// cache has to notice and refetch, or every sign-in fails until Sable restarts.
func TestKeyCacheRefetchesAfterAKeyRotation(t *testing.T) {
	var fetches atomic.Int64
	currentKeyID := "key-1"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		writeJSON(writer, map[string]any{"keys": []any{map[string]any{
			"kty": "RSA",
			"use": "sig",
			"kid": currentKeyID,
			"n":   base64.RawURLEncoding.EncodeToString(new(big.Int).Lsh(big.NewInt(1), 2047).Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes()),
		}}})
	}))
	defer server.Close()

	clock := time.Now()
	cache := newKeyCache(newFetcher(server.Client(), "sable"), func() time.Time { return clock })

	if _, err := cache.keyFor(context.Background(), server.URL, "key-1"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if fetches.Load() != 1 {
		t.Fatalf("fetches = %d, want 1", fetches.Load())
	}

	currentKeyID = "key-2"
	// Inside the refetch floor the miss is believed, so no request goes out.
	if _, err := cache.keyFor(context.Background(), server.URL, "key-2"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("error = %v, want %v", err, ErrKeyNotFound)
	}
	if fetches.Load() != 1 {
		t.Fatalf("fetches = %d, want the refetch floor to hold at 1", fetches.Load())
	}

	clock = clock.Add(refetchInterval + time.Second)
	if _, err := cache.keyFor(context.Background(), server.URL, "key-2"); err != nil {
		t.Fatalf("lookup after rotation: %v", err)
	}
	if fetches.Load() != 2 {
		t.Fatalf("fetches = %d, want 2 after the floor expired", fetches.Load())
	}
}

func TestRequireSecureURLKeepsProviderTrafficOnTLS(t *testing.T) {
	tests := []struct {
		endpoint string
		wantOK   bool
	}{
		{"https://id.example.com/token", true},
		{"http://id.example.com/token", false},
		{"http://localhost:9000/token", true},
		{"http://127.0.0.1:9000/token", true},
		{"http://[::1]:9000/token", true},
		{"ftp://id.example.com/token", false},
		{"://nonsense", false},
	}
	for _, test := range tests {
		t.Run(test.endpoint, func(t *testing.T) {
			err := requireSecureURL(test.endpoint)
			if test.wantOK && err != nil {
				t.Fatalf("endpoint was rejected: %v", err)
			}
			if !test.wantOK && err == nil {
				t.Fatal("endpoint was accepted, want a rejection")
			}
		})
	}
}
