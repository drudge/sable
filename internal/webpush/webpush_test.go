package webpush

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := decode(strings.ReplaceAll(value, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// TestEncryptMatchesTheRFC8291Example encrypts the example message in RFC
// 8291 section 5 with the appendix's keys and salt, and gets its result.
func TestEncryptMatchesTheRFC8291Example(t *testing.T) {
	t.Parallel()
	ephemeral, err := ecdh.P256().NewPrivateKey(mustDecode(t, "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
	if err != nil {
		t.Fatal(err)
	}
	subscription := Subscription{
		Endpoint: "https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV",
		P256DH:   "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
		Auth:     "BTBZMqHH6r4Tts7J_aSIgg",
	}
	subscription.P256DH = strings.ReplaceAll(subscription.P256DH, " ", "")
	got, err := encrypt(subscription, []byte("When I grow up, I want to be a watermelon"), mustDecode(t, "DGv6ra1nlYgDCS1FRnbzlw"), ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	want := append(
		mustDecode(t, "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z 9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml mlMoZIIgDll6e3vCYLocInmYWAmS6Tlz AC8wEqKK6PBru3jl7A8"),
		mustDecode(t, "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrd irN6GcG7sFz1y1sqLgVi1VhjVkHsUoEs bI_0LpXMuGvnzQ")...)
	if !bytes.Equal(got, want) {
		t.Fatalf("encrypted =\n%x\nwant\n%x", got, want)
	}
}

func TestVAPIDSignsATokenForTheEndpointOrigin(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_790_000_000, 0)
	header, err := VAPID(key, "https://fcm.googleapis.com/fcm/send/abc", "mailto:ops@example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	token, public, found := strings.Cut(strings.TrimPrefix(header, "vapid t="), ", k=")
	if !found {
		t.Fatalf("header = %q", header)
	}
	if want, _ := PublicKey(key); public != want {
		t.Fatalf("k = %q, want %q", public, want)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token = %q", token)
	}
	var claims struct {
		Audience string `json:"aud"`
		Expires  int64  `json:"exp"`
		Subject  string `json:"sub"`
	}
	if err := json.Unmarshal(mustDecode(t, parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Audience != "https://fcm.googleapis.com" || claims.Subject != "mailto:ops@example.com" || claims.Expires != now.Add(12*time.Hour).Unix() {
		t.Fatalf("claims = %+v", claims)
	}
	signature := mustDecode(t, parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(signature) != 64 || !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("the token's ES256 signature does not verify")
	}
}

func TestSendPostsAnEncryptedSignedPushAndSaysWhenItIsGone(t *testing.T) {
	t.Parallel()
	browser, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gone := false
	var seen *http.Request
	var body []byte
	service := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen, body = request, mustRead(request.Body)
		if gone {
			writer.WriteHeader(http.StatusGone)
			return
		}
		writer.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(service.Close)
	key, _ := GenerateKey()
	sender := Sender{Key: key, Subject: "https://sable.example", Client: service.Client()}
	subscription := Subscription{
		Endpoint: service.URL + "/push/abc",
		P256DH:   base64.RawURLEncoding.EncodeToString(browser.PublicKey().Bytes()),
		Auth:     base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")),
	}
	// Random ciphertext can contain a short word by chance, but never this.
	const marker = "plaintext-marker-that-must-never-reach-the-wire"
	if err := sender.Send(context.Background(), subscription, []byte(`{"title":"`+marker+`"}`), time.Hour); err != nil {
		t.Fatal(err)
	}
	if seen.Header.Get("Content-Encoding") != "aes128gcm" || seen.Header.Get("TTL") != "3600" || !strings.HasPrefix(seen.Header.Get("Authorization"), "vapid t=") {
		t.Fatalf("headers = %v", seen.Header)
	}
	if bytes.Contains(body, []byte(marker)) || len(body) < 86 {
		t.Fatalf("body is not an encrypted record: %q", body)
	}
	gone = true
	if err := sender.Send(context.Background(), subscription, []byte("again"), time.Hour); !errors.Is(err, ErrGone) {
		t.Fatalf("sending to a gone subscription = %v", err)
	}
}

func TestSubscriptionsAreCheckedBeforeUse(t *testing.T) {
	t.Parallel()
	for _, subscription := range []Subscription{
		{Endpoint: "http://push.example.net/x", P256DH: strings.Repeat("A", 87), Auth: strings.Repeat("A", 22)},
		{Endpoint: "https://push.example.net/x", P256DH: "short", Auth: strings.Repeat("A", 22)},
		{Endpoint: "https://push.example.net/x", P256DH: strings.Repeat("A", 87), Auth: "short"},
	} {
		if subscription.Valid() == nil {
			t.Errorf("%+v is valid", subscription)
		}
	}
	if (Subscription{Endpoint: "https://a"}).ID() == (Subscription{Endpoint: "https://b"}).ID() {
		t.Error("two endpoints share an ID")
	}
}

func mustRead(reader io.Reader) []byte {
	body, _ := io.ReadAll(reader)
	return body
}
