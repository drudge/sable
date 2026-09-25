package store

import (
	"context"
	"fmt"

	"github.com/drudge/sable/internal/webpush"
)

func pushSubscriptionTable() string {
	return `
CREATE TABLE IF NOT EXISTS sable_push_subscriptions (
    endpoint TEXT PRIMARY KEY,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
)`
}

// SavePushSubscription remembers a browser that asked for Insights alerts. A
// browser that subscribes again replaces what was known about it.
func (store *Store) SavePushSubscription(ctx context.Context, subscription webpush.Subscription) error {
	_, err := store.database.ExecContext(ctx, `
INSERT INTO sable_push_subscriptions (endpoint, p256dh, auth, label, created_by, created_at)
VALUES (`+store.placeholders(6)+`)
ON CONFLICT (endpoint) DO UPDATE SET p256dh = excluded.p256dh, auth = excluded.auth,
    label = excluded.label, created_by = excluded.created_by, created_at = excluded.created_at`,
		subscription.Endpoint, subscription.P256DH, subscription.Auth, subscription.Label, subscription.CreatedBy, subscription.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("save push subscription: %w", err)
	}
	return nil
}

// PushSubscriptions lists the browsers that get Insights alerts, newest first.
func (store *Store) PushSubscriptions(ctx context.Context) ([]webpush.Subscription, error) {
	rows, err := store.database.QueryContext(ctx,
		"SELECT endpoint, p256dh, auth, label, created_by, created_at FROM sable_push_subscriptions ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("read push subscriptions: %w", err)
	}
	defer rows.Close()
	subscriptions := make([]webpush.Subscription, 0)
	for rows.Next() {
		var subscription webpush.Subscription
		var created any
		if err := rows.Scan(&subscription.Endpoint, &subscription.P256DH, &subscription.Auth, &subscription.Label, &subscription.CreatedBy, &created); err != nil {
			return nil, fmt.Errorf("scan push subscription: %w", err)
		}
		if subscription.CreatedAt, err = databaseTime(created); err != nil {
			return nil, fmt.Errorf("read push subscription time: %w", err)
		}
		subscriptions = append(subscriptions, subscription)
	}
	return subscriptions, rows.Err()
}

// DeletePushSubscription forgets a browser, because someone removed it or its
// push service said it is gone.
func (store *Store) DeletePushSubscription(ctx context.Context, endpoint string) error {
	if _, err := store.database.ExecContext(ctx, "DELETE FROM sable_push_subscriptions WHERE endpoint = "+store.placeholder(1), endpoint); err != nil {
		return fmt.Errorf("delete push subscription: %w", err)
	}
	return nil
}
