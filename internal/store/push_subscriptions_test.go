package store

import (
	"context"
	"testing"
	"time"

	"github.com/drudge/sable/internal/webpush"
)

func TestPushSubscriptionsAreSavedReplacedAndForgotten(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	opened := openQueryLogStore(t, nil)
	now := time.Now().UTC().Truncate(time.Second)
	first := webpush.Subscription{Endpoint: "https://push.example/a", P256DH: "key-a", Auth: "auth-a", Label: "Chrome on macOS", CreatedBy: "nick", CreatedAt: now}
	second := webpush.Subscription{Endpoint: "https://push.example/b", P256DH: "key-b", Auth: "auth-b", Label: "Safari on iOS", CreatedAt: now.Add(time.Minute)}
	for _, subscription := range []webpush.Subscription{first, second} {
		if err := opened.SavePushSubscription(ctx, subscription); err != nil {
			t.Fatal(err)
		}
	}
	// Subscribing again replaces the keys.
	first.P256DH = "key-a2"
	if err := opened.SavePushSubscription(ctx, first); err != nil {
		t.Fatal(err)
	}
	subscriptions, err := opened.PushSubscriptions(ctx)
	if err != nil || len(subscriptions) != 2 || subscriptions[0].Endpoint != second.Endpoint || subscriptions[1].P256DH != "key-a2" ||
		subscriptions[1].Label != "Chrome on macOS" || !subscriptions[1].CreatedAt.Equal(now) {
		t.Fatalf("subscriptions = %+v, %v", subscriptions, err)
	}
	if err := opened.DeletePushSubscription(ctx, first.Endpoint); err != nil {
		t.Fatal(err)
	}
	if subscriptions, _ := opened.PushSubscriptions(ctx); len(subscriptions) != 1 || subscriptions[0].Endpoint != second.Endpoint {
		t.Fatalf("after delete = %+v", subscriptions)
	}
}
