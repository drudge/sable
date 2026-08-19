package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

// jwsHeader is the protected header of a compact JWS. Only the fields that
// change a verification decision are read; anything else a provider adds is
// ignored rather than rejected, because unknown header fields are ordinary.
type jwsHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

// signatureAlgorithm describes one accepted way to sign an ID token: which
// hash to run and which kind of public key is allowed to verify it.
type signatureAlgorithm struct {
	hash    crypto.Hash
	keyType string
	pss     bool
	// coordinate is the byte width of each half of a raw ECDSA signature,
	// which is fixed by the curve rather than by the encoded integers.
	coordinate int
}

// acceptedAlgorithms is an allowlist, not a denylist. Two families are absent
// on purpose. "none" is unsigned and would let anyone mint an administrator.
// HMAC ("HS256" and friends) is symmetric, and a verifier that accepts it can
// be handed a token signed with the provider's own public key, which is
// published; that is the classic algorithm-confusion attack. Neither can be
// reached here because a token naming them never finds an entry.
var acceptedAlgorithms = map[string]signatureAlgorithm{
	"RS256": {hash: crypto.SHA256, keyType: "RSA"},
	"RS384": {hash: crypto.SHA384, keyType: "RSA"},
	"RS512": {hash: crypto.SHA512, keyType: "RSA"},
	"PS256": {hash: crypto.SHA256, keyType: "RSA", pss: true},
	"PS384": {hash: crypto.SHA384, keyType: "RSA", pss: true},
	"PS512": {hash: crypto.SHA512, keyType: "RSA", pss: true},
	"ES256": {hash: crypto.SHA256, keyType: "EC", coordinate: 32},
	"ES384": {hash: crypto.SHA384, keyType: "EC", coordinate: 48},
	"ES512": {hash: crypto.SHA512, keyType: "EC", coordinate: 66},
}

// parseJWS splits a compact serialization into its header, its raw payload,
// its signature, and the exact bytes that were signed. Decoding is strict, so
// a segment whose unused trailing bits are not zero is refused rather than
// silently decoding to the same bytes as a different spelling of itself.
// The signing input has
// to be taken from the original string rather than re-encoded from the decoded
// parts, because base64 has more than one spelling for the same bytes and a
// re-encoded input would verify a token whose real bytes differ.
func parseJWS(token string) (jwsHeader, []byte, []byte, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwsHeader{}, nil, nil, nil, fmt.Errorf("%w: expected three segments, found %d", ErrInvalidToken, len(parts))
	}
	rawHeader, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return jwsHeader{}, nil, nil, nil, fmt.Errorf("%w: header is not base64url", ErrInvalidToken)
	}
	var header jwsHeader
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return jwsHeader{}, nil, nil, nil, fmt.Errorf("%w: header is not JSON", ErrInvalidToken)
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return jwsHeader{}, nil, nil, nil, fmt.Errorf("%w: payload is not base64url", ErrInvalidToken)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return jwsHeader{}, nil, nil, nil, fmt.Errorf("%w: signature is not base64url", ErrInvalidToken)
	}
	return header, payload, signature, []byte(parts[0] + "." + parts[1]), nil
}

// verifySignature checks the signature against one public key. The algorithm
// comes from the header, but the header cannot widen what is acceptable: the
// name has to appear in the allowlist and the key handed in has to be of the
// kind that algorithm names. A token asking for RS256 against an EC key is
// refused rather than coerced.
func verifySignature(header jwsHeader, key publicKey, signed, signature []byte) error {
	algorithm, accepted := acceptedAlgorithms[header.Algorithm]
	if !accepted {
		return fmt.Errorf("%w: %q", ErrUnsupported, header.Algorithm)
	}
	if key.keyType != algorithm.keyType {
		return fmt.Errorf("%w: %s token cannot be verified by a %s key", ErrInvalidToken, header.Algorithm, key.keyType)
	}
	digest := digestOf(algorithm.hash, signed)
	switch material := key.material.(type) {
	case *rsa.PublicKey:
		if algorithm.pss {
			return wrapVerify(rsa.VerifyPSS(material, algorithm.hash, digest, signature, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       algorithm.hash,
			}))
		}
		return wrapVerify(rsa.VerifyPKCS1v15(material, algorithm.hash, digest, signature))
	case *ecdsa.PublicKey:
		// JWS carries an ECDSA signature as the fixed-width concatenation of r
		// and s, not as the ASN.1 sequence crypto/ecdsa marshals by default.
		if len(signature) != algorithm.coordinate*2 {
			return fmt.Errorf("%w: %s signature is %d bytes, expected %d", ErrInvalidToken, header.Algorithm, len(signature), algorithm.coordinate*2)
		}
		r := new(big.Int).SetBytes(signature[:algorithm.coordinate])
		s := new(big.Int).SetBytes(signature[algorithm.coordinate:])
		if !ecdsa.Verify(material, digest, r, s) {
			return fmt.Errorf("%w: signature does not match", ErrInvalidToken)
		}
		return nil
	default:
		return fmt.Errorf("%w: %T", ErrUnsupported, key.material)
	}
}

func wrapVerify(err error) error {
	if err != nil {
		return fmt.Errorf("%w: signature does not match", ErrInvalidToken)
	}
	return nil
}

func digestOf(algorithm crypto.Hash, signed []byte) []byte {
	var digest hash.Hash
	switch algorithm {
	case crypto.SHA384:
		digest = sha512.New384()
	case crypto.SHA512:
		digest = sha512.New()
	default:
		digest = sha256.New()
	}
	digest.Write(signed)
	return digest.Sum(nil)
}
