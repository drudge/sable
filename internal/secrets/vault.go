package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	keyLength     = 32
	cipherVersion = "v1:"
)

type Store interface {
	PutEncryptedSecret(context.Context, string, string, time.Time) error
	EncryptedSecret(context.Context, string) (string, error)
}

type Vault struct {
	store Store
	aead  cipher.AEAD
	now   func() time.Time
}

func Open(path string, store Store) (*Vault, error) {
	if store == nil {
		return nil, errors.New("secret store is required")
	}
	key, err := loadOrCreateKey(path)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize secret encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize secret authentication: %w", err)
	}
	return &Vault{store: store, aead: aead, now: time.Now}, nil
}

func (vault *Vault) Put(ctx context.Context, name string, plaintext []byte) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("secret name is required")
	}
	nonce := make([]byte, vault.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate secret nonce: %w", err)
	}
	sealed := vault.aead.Seal(nonce, nonce, plaintext, []byte(name))
	encoded := cipherVersion + base64.RawStdEncoding.EncodeToString(sealed)
	return vault.store.PutEncryptedSecret(ctx, name, encoded, vault.now())
}

func (vault *Vault) Get(ctx context.Context, name string) ([]byte, error) {
	encoded, err := vault.store.EncryptedSecret(ctx, name)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(encoded, cipherVersion) {
		return nil, errors.New("unsupported encrypted secret version")
	}
	sealed, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(encoded, cipherVersion))
	if err != nil || len(sealed) < vault.aead.NonceSize()+vault.aead.Overhead() {
		return nil, errors.New("invalid encrypted secret")
	}
	nonce := sealed[:vault.aead.NonceSize()]
	plaintext, err := vault.aead.Open(nil, nonce, sealed[vault.aead.NonceSize():], []byte(name))
	if err != nil {
		return nil, errors.New("decrypt secret: authentication failed")
	}
	return plaintext, nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("secret key file is required")
	}
	contents, err := os.ReadFile(path)
	if err == nil {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil, fmt.Errorf("inspect secret key file: %w", statErr)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("secret key file %s must not be accessible by group or other users", path)
		}
		key, decodeErr := base64.RawStdEncoding.Strict().DecodeString(strings.TrimSpace(string(contents)))
		if decodeErr != nil || len(key) != keyLength {
			return nil, fmt.Errorf("secret key file %s is invalid", path)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read secret key file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create secret key directory: %w", err)
	}
	key := make([]byte, keyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate secret key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create secret key file: %w", err)
	}
	encoded := base64.RawStdEncoding.EncodeToString(key) + "\n"
	if _, err := file.WriteString(encoded); err != nil {
		file.Close()
		return nil, fmt.Errorf("write secret key file: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close secret key file: %w", err)
	}
	return key, nil
}
