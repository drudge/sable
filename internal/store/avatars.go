package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/drudge/sable/internal/auth"
)

// SaveAvatar stores the profile picture an identity provider serves for an
// account, replacing whatever was there.
//
// The image and the tag are written together in one transaction. They are kept
// in two tables because the tag is read on every authenticated request while
// the bytes are read only when a browser asks for the image, and a row holding
// both would drag a quarter megabyte through every session lookup.
func (store *Store) SaveAvatar(ctx context.Context, userID int64, avatar auth.Avatar, now time.Time) error {
	if len(avatar.Data) == 0 || avatar.ContentType == "" || avatar.ETag == "" {
		return errors.New("an avatar needs bytes, a content type, and a tag")
	}
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin avatar save: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx,
		"DELETE FROM sable_user_avatars WHERE user_id = "+store.placeholder(1), userID); err != nil {
		return fmt.Errorf("replace avatar: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
INSERT INTO sable_user_avatars (user_id, content_type, image, source_url, etag, updated_at)
VALUES (`+store.placeholders(6)+`)`,
		userID, avatar.ContentType, avatar.Data, avatar.SourceURL, avatar.ETag, now.UTC()); err != nil {
		return fmt.Errorf("store avatar: %w", err)
	}
	result, err := transaction.ExecContext(ctx,
		"UPDATE sable_user_profiles SET avatar_etag = "+store.placeholder(1)+", updated_at = "+store.placeholder(2)+
			" WHERE user_id = "+store.placeholder(3), avatar.ETag, now.UTC(), userID)
	if err != nil {
		return fmt.Errorf("record avatar tag: %w", err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return auth.ErrNotFound
	}
	return transaction.Commit()
}

// DeleteAvatar forgets the stored picture for an account. It is not an error
// when there was none, because the caller reaches here whenever a provider
// stops advertising a picture rather than only when one was stored.
func (store *Store) DeleteAvatar(ctx context.Context, userID int64, now time.Time) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin avatar removal: %w", err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx,
		"DELETE FROM sable_user_avatars WHERE user_id = "+store.placeholder(1), userID); err != nil {
		return fmt.Errorf("remove avatar: %w", err)
	}
	if _, err := transaction.ExecContext(ctx,
		"UPDATE sable_user_profiles SET avatar_etag = "+store.placeholder(1)+", updated_at = "+store.placeholder(2)+
			" WHERE user_id = "+store.placeholder(3), "", now.UTC(), userID); err != nil {
		return fmt.Errorf("clear avatar tag: %w", err)
	}
	return transaction.Commit()
}

// Avatar reads the stored picture for an account. A missing one is reported as
// auth.ErrNotFound so the console can answer with a 404 rather than an empty
// image the browser would render as broken.
func (store *Store) Avatar(ctx context.Context, userID int64) (auth.Avatar, error) {
	var avatar auth.Avatar
	err := store.database.QueryRowContext(ctx, `
SELECT content_type, image, source_url, etag FROM sable_user_avatars WHERE user_id = `+store.placeholder(1),
		userID,
	).Scan(&avatar.ContentType, &avatar.Data, &avatar.SourceURL, &avatar.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Avatar{}, auth.ErrNotFound
	}
	if err != nil {
		return auth.Avatar{}, fmt.Errorf("read avatar: %w", err)
	}
	return avatar, nil
}
