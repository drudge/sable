package store

import (
	"context"
	"fmt"
	"time"
)

// EncryptedSecret is one row of the encrypted secret store. The ciphertext is
// only meaningful alongside the vault key that sealed it, so a backup has to
// carry both or neither.
type EncryptedSecret struct {
	Name       string    `json:"name"`
	Ciphertext string    `json:"ciphertext"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ExportSecrets returns every stored secret in a stable order.
func (store *Store) ExportSecrets(ctx context.Context) ([]EncryptedSecret, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT name, ciphertext, updated_at FROM sable_secrets ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("export secrets: %w", err)
	}
	defer rows.Close()
	secrets := []EncryptedSecret{}
	for rows.Next() {
		var secret EncryptedSecret
		if err := rows.Scan(&secret.Name, &secret.Ciphertext, &secret.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		secret.UpdatedAt = secret.UpdatedAt.UTC()
		secrets = append(secrets, secret)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secrets: %w", err)
	}
	return secrets, nil
}

// ReplaceSecrets swaps the whole secret store for the supplied set. Restoring a
// deployment has to remove secrets the backup does not know about, otherwise a
// stale DNSSEC key left behind on the target node outlives the restore.
func (store *Store) ReplaceSecrets(ctx context.Context, secrets []EncryptedSecret) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin secret replacement: %w", err)
	}
	defer transaction.Rollback()

	if _, err := transaction.ExecContext(ctx, "DELETE FROM sable_secrets"); err != nil {
		return fmt.Errorf("clear secrets: %w", err)
	}
	for _, secret := range secrets {
		if secret.Name == "" {
			return fmt.Errorf("secret name is required")
		}
		updatedAt := secret.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = time.Now()
		}
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_secrets (name, ciphertext, updated_at)
VALUES (`+store.placeholders(3)+`)`, secret.Name, secret.Ciphertext, updatedAt.UTC()); err != nil {
			return fmt.Errorf("restore secret %q: %w", secret.Name, err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit secret replacement: %w", err)
	}
	return nil
}

// TrustAnchorOwners lists the trust points that have persisted state, so a
// backup can capture every managed anchor rather than only the root.
func (store *Store) TrustAnchorOwners(ctx context.Context) ([]string, error) {
	rows, err := store.database.QueryContext(ctx, `
SELECT owner FROM sable_dnssec_trust_points ORDER BY owner`)
	if err != nil {
		return nil, fmt.Errorf("list trust anchor owners: %w", err)
	}
	defer rows.Close()
	owners := []string{}
	for rows.Next() {
		var owner string
		if err := rows.Scan(&owner); err != nil {
			return nil, fmt.Errorf("scan trust anchor owner: %w", err)
		}
		owners = append(owners, owner)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate trust anchor owners: %w", err)
	}
	return owners, nil
}
