// Package webpush sends Web Push messages, the notifications a browser shows
// even when no page of the site is open. It encrypts each message for the
// browser that subscribed (RFC 8291) and signs the request with the server's
// key (VAPID, RFC 8292), so no push provider account is needed: the browser's
// own push service delivers it.
package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// recordSize is the one record every message fits in. Push services accept
// payloads up to 4096 bytes, so one record is always enough.
const recordSize = 4096

// ErrGone reports a subscription the push service no longer knows, because
// the browser unsubscribed or the site's permission was revoked. It will
// never work again and should be forgotten.
var ErrGone = errors.New("push subscription is gone")

// Subscription is what a browser hands over when it agrees to receive pushes:
// where to send them and the keys to encrypt them for it.
type Subscription struct {
	Endpoint string
	// P256DH is the browser's public key and Auth its shared secret, both
	// base64url as the browser gives them.
	P256DH string
	Auth   string
	// Label says which browser it is, for people choosing which to remove.
	Label     string
	CreatedBy string
	CreatedAt time.Time
}

// ID names a subscription without showing its endpoint, which is itself
// enough to send to it.
func (subscription Subscription) ID() string {
	sum := sha256.Sum256([]byte(subscription.Endpoint))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

// Valid reports whether a subscription could be sent to.
func (subscription Subscription) Valid() error {
	endpoint, err := url.Parse(subscription.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return errors.New("push endpoint must be an https URL")
	}
	if key, err := decode(subscription.P256DH); err != nil || len(key) != 65 {
		return errors.New("push key must be a P-256 public key")
	}
	if secret, err := decode(subscription.Auth); err != nil || len(secret) != 16 {
		return errors.New("push secret must be 16 bytes")
	}
	return nil
}

// GenerateKey makes a new VAPID key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PublicKey is the VAPID public key as browsers take it when subscribing.
func PublicKey(key *ecdsa.PrivateKey) (string, error) {
	public, err := key.PublicKey.ECDH()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(public.Bytes()), nil
}

// Sender sends pushes signed with one VAPID key.
type Sender struct {
	Key *ecdsa.PrivateKey
	// Subject is how a push service can reach whoever runs the server: a
	// mailto: or https: URL.
	Subject string
	Client  *http.Client
	Now     func() time.Time
}

// Send delivers one payload to one subscription. TTL is how long the push
// service may hold it for a browser that is offline.
func (sender Sender) Send(ctx context.Context, subscription Subscription, payload []byte, ttl time.Duration) error {
	body, err := Encrypt(subscription, payload)
	if err != nil {
		return err
	}
	now := time.Now
	if sender.Now != nil {
		now = sender.Now
	}
	authorization, err := VAPID(sender.Key, subscription.Endpoint, sender.Subject, now())
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, subscription.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Content-Encoding", "aes128gcm")
	request.Header.Set("TTL", strconv.Itoa(int(ttl.Seconds())))
	request.Header.Set("Urgency", "normal")
	request.Header.Set("Authorization", authorization)
	client := sender.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("send push: %w", err)
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
	switch {
	case response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone:
		return ErrGone
	case response.StatusCode < 200 || response.StatusCode > 299:
		said := strings.TrimSpace(string(answer))
		if len(said) > 200 {
			said = said[:200]
		}
		return fmt.Errorf("push service answered %s: %s", response.Status, said)
	}
	return nil
}

// Encrypt seals a payload for one browser the way RFC 8291 describes, as a
// single aes128gcm record.
func Encrypt(subscription Subscription, payload []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return encrypt(subscription, payload, salt, ephemeral)
}

func encrypt(subscription Subscription, payload, salt []byte, ephemeral *ecdh.PrivateKey) ([]byte, error) {
	if err := subscription.Valid(); err != nil {
		return nil, err
	}
	// One record holds the payload, its delimiter, and the 16-byte tag.
	if len(payload) > recordSize-17 {
		return nil, fmt.Errorf("push payload is %d bytes, more than one record holds", len(payload))
	}
	browserKey, _ := decode(subscription.P256DH)
	authSecret, _ := decode(subscription.Auth)
	browserPublic, err := ecdh.P256().NewPublicKey(browserKey)
	if err != nil {
		return nil, fmt.Errorf("read push key: %w", err)
	}
	shared, err := ephemeral.ECDH(browserPublic)
	if err != nil {
		return nil, err
	}
	serverPublic := ephemeral.PublicKey().Bytes()
	keyInfo := "WebPush: info\x00" + string(browserKey) + string(serverPublic)
	inputKey, err := hkdf.Key(sha256.New, shared, authSecret, keyInfo, 32)
	if err != nil {
		return nil, err
	}
	contentKey, err := hkdf.Key(sha256.New, inputKey, salt, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Key(sha256.New, inputKey, salt, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	sealer, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// 0x02 marks the last, and only, record.
	sealed := sealer.Seal(nil, nonce, append(append([]byte{}, payload...), 0x02), nil)
	header := make([]byte, 0, 16+4+1+len(serverPublic))
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint32(header, recordSize)
	header = append(header, byte(len(serverPublic)))
	header = append(header, serverPublic...)
	return append(header, sealed...), nil
}

// VAPID is the Authorization header that tells a push service which server
// sent a push: a short-lived token for the endpoint's origin, signed with the
// server's key, and that key's public half.
func VAPID(key *ecdsa.PrivateKey, endpoint, subject string, now time.Time) (string, error) {
	target, err := url.Parse(endpoint)
	if err != nil || target.Host == "" {
		return "", errors.New("push endpoint must be a URL")
	}
	claims, err := json.Marshal(map[string]any{
		"aud": target.Scheme + "://" + target.Host,
		"exp": now.Add(12 * time.Hour).Unix(),
		"sub": subject,
	})
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	// ES256 is the two halves side by side, not the ASN.1 form Go signs in.
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	public, err := PublicKey(key)
	if err != nil {
		return "", err
	}
	return "vapid t=" + unsigned + "." + base64.RawURLEncoding.EncodeToString(signature) + ", k=" + public, nil
}

// decode reads base64url with or without padding, as browsers vary.
func decode(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
}
