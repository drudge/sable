package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// publicKey is one usable signing key from a provider's JWKS. keyType is kept
// alongside the parsed material so the algorithm check in verifySignature can
// compare families without a type switch.
type publicKey struct {
	id       string
	keyType  string
	material any
}

// jsonWebKey is the wire shape of a single JWKS entry. Only signing keys of
// the two families Sable verifies are read; a provider that also publishes
// encryption keys or an unfamiliar key type has those entries skipped rather
// than having the whole set rejected.
type jsonWebKey struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

// refetchInterval bounds how often an unknown key identifier may send Sable
// back to the provider. A rotation should be picked up within seconds, but
// without a floor a stream of tokens naming random identifiers would turn this
// server into a traffic source aimed at the identity provider.
const refetchInterval = 30 * time.Second

// keyCache holds the provider's current signing keys and refetches them when a
// token names an identifier it has not seen.
type keyCache struct {
	fetcher *fetcher

	mutex     sync.Mutex
	keys      map[string]publicKey
	lastFetch time.Time
	now       func() time.Time
}

func newKeyCache(fetcher *fetcher, now func() time.Time) *keyCache {
	if now == nil {
		now = time.Now
	}
	return &keyCache{fetcher: fetcher, keys: map[string]publicKey{}, now: now}
}

// keyFor resolves the key a token's header names. A token without a key
// identifier is matched against every cached key, which is what providers that
// publish a single key expect. A miss triggers at most one refetch per
// refetchInterval before the lookup gives up.
func (cache *keyCache) keyFor(ctx context.Context, uri, keyID string) ([]publicKey, error) {
	matches, fresh := cache.lookup(keyID)
	if len(matches) > 0 {
		return matches, nil
	}
	if fresh {
		return nil, fmt.Errorf("%w: key %q", ErrKeyNotFound, keyID)
	}
	if err := cache.refresh(ctx, uri); err != nil {
		return nil, err
	}
	matches, _ = cache.lookup(keyID)
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: key %q", ErrKeyNotFound, keyID)
	}
	return matches, nil
}

// lookup reports the matching keys and whether the cache was refreshed
// recently enough that a miss should be believed rather than retried.
func (cache *keyCache) lookup(keyID string) ([]publicKey, bool) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if keyID == "" {
		matches := make([]publicKey, 0, len(cache.keys))
		for _, key := range cache.keys {
			matches = append(matches, key)
		}
		return matches, cache.now().Sub(cache.lastFetch) < refetchInterval
	}
	if key, found := cache.keys[keyID]; found {
		return []publicKey{key}, true
	}
	return nil, cache.now().Sub(cache.lastFetch) < refetchInterval
}

func (cache *keyCache) refresh(ctx context.Context, uri string) error {
	var set jsonWebKeySet
	if err := cache.fetcher.getJSON(ctx, uri, &set); err != nil {
		return fmt.Errorf("read signing keys: %w", err)
	}
	parsed := make(map[string]publicKey, len(set.Keys))
	for _, entry := range set.Keys {
		// "enc" keys are for encryption, never for verifying a signature.
		if entry.Use != "" && entry.Use != "sig" {
			continue
		}
		key, err := parseJSONWebKey(entry)
		if err != nil {
			continue
		}
		parsed[key.id] = key
	}
	if len(parsed) == 0 {
		return fmt.Errorf("%w: provider published no usable signing keys", ErrKeyNotFound)
	}
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.keys = parsed
	cache.lastFetch = cache.now()
	return nil
}

func parseJSONWebKey(entry jsonWebKey) (publicKey, error) {
	switch entry.KeyType {
	case "RSA":
		modulus, err := decodeBigInt(entry.Modulus)
		if err != nil {
			return publicKey{}, err
		}
		exponent, err := decodeBigInt(entry.Exponent)
		if err != nil {
			return publicKey{}, err
		}
		if !exponent.IsInt64() || exponent.Int64() < 3 {
			return publicKey{}, fmt.Errorf("%w: RSA exponent is out of range", ErrInvalidToken)
		}
		// A short modulus is not a usable signing key. 2048 bits is the floor
		// every mainstream provider meets and below it the signature is not
		// worth checking.
		if modulus.BitLen() < 2048 {
			return publicKey{}, fmt.Errorf("%w: RSA modulus is %d bits", ErrInvalidToken, modulus.BitLen())
		}
		return publicKey{
			id:      entry.KeyID,
			keyType: "RSA",
			material: &rsa.PublicKey{
				N: modulus,
				E: int(exponent.Int64()),
			},
		}, nil
	case "EC":
		curve, size, err := curveFor(entry.Curve)
		if err != nil {
			return publicKey{}, err
		}
		x, err := decodeCoordinate(entry.X, size)
		if err != nil {
			return publicKey{}, err
		}
		y, err := decodeCoordinate(entry.Y, size)
		if err != nil {
			return publicKey{}, err
		}
		key := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		// ECDH rejects a point that is not on the curve or is the identity.
		// Verifying against an off-curve point is undefined, so the key is
		// refused here rather than reaching crypto/ecdsa.
		if _, err := key.ECDH(); err != nil {
			return publicKey{}, fmt.Errorf("%w: EC point is not on %s", ErrInvalidToken, entry.Curve)
		}
		return publicKey{id: entry.KeyID, keyType: "EC", material: key}, nil
	default:
		return publicKey{}, fmt.Errorf("%w: key type %q", ErrUnsupported, entry.KeyType)
	}
}

func curveFor(name string) (elliptic.Curve, int, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), 32, nil
	case "P-384":
		return elliptic.P384(), 48, nil
	case "P-521":
		return elliptic.P521(), 66, nil
	default:
		return nil, 0, fmt.Errorf("%w: curve %q", ErrUnsupported, name)
	}
}

func decodeBigInt(value string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("%w: key parameter is not base64url", ErrInvalidToken)
	}
	return new(big.Int).SetBytes(raw), nil
}

// decodeCoordinate insists on the exact width the curve defines. A short or
// long coordinate means the key was not encoded the way the JWK spec requires,
// and silently left-padding it would accept a malformed key.
func decodeCoordinate(value string, size int) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: EC coordinate is not base64url", ErrInvalidToken)
	}
	if len(raw) != size {
		return nil, fmt.Errorf("%w: EC coordinate is %d bytes, expected %d", ErrInvalidToken, len(raw), size)
	}
	return new(big.Int).SetBytes(raw), nil
}
