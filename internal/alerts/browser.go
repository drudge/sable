package alerts

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/drudge/sable/internal/webpush"
)

// pushTTL is how long a browser's push service holds an alert for a browser
// that is offline. An alert older than a day is no longer news.
const pushTTL = 24 * time.Hour

// ErrNoBrowsers is why a browser alert went nowhere.
var ErrNoBrowsers = errors.New("no browser has turned alerts on yet; use Turn On in This Browser first")

// ErrBrowsersUnavailable is why a server cannot push to browsers at all.
var ErrBrowsersUnavailable = errors.New("browser alerts are not available on this server")

// PushKeys hands out the key browser pushes are signed with.
type PushKeys interface {
	PushKey(context.Context) (*ecdsa.PrivateKey, error)
}

// Subscriptions keeps the browsers that turned alerts on.
type Subscriptions interface {
	PushSubscriptions(context.Context) ([]webpush.Subscription, error)
	DeletePushSubscription(context.Context, string) error
}

// Browsers pushes alerts to the browsers that turned them on.
type Browsers struct {
	Keys   PushKeys
	Store  Subscriptions
	Client *http.Client
	Logger *slog.Logger
}

// Available reports whether this server can push to browsers.
func (browsers *Browsers) Available() bool {
	return browsers != nil && browsers.Keys != nil && browsers.Store != nil
}

// Subscriptions lists the browsers that turned alerts on, or none when this
// server cannot push to browsers.
func (browsers *Browsers) Subscriptions(ctx context.Context) ([]webpush.Subscription, error) {
	if !browsers.Available() {
		return nil, nil
	}
	return browsers.Store.PushSubscriptions(ctx)
}

// Push sends one payload to every browser that turned alerts on, and forgets
// any whose push service says it is gone. It counts the browsers reached; one
// that fails does not keep the rest from hearing. base is the console's
// address: push services want a way to reach whoever runs the server, so a
// console served over HTTPS names itself and any other names Sable's project
// page.
func (browsers *Browsers) Push(ctx context.Context, base string, payload []byte, urgent bool) (int, error) {
	if !browsers.Available() {
		return 0, ErrBrowsersUnavailable
	}
	subscriptions, err := browsers.Store.PushSubscriptions(ctx)
	if err != nil {
		return 0, err
	}
	if len(subscriptions) == 0 {
		return 0, ErrNoBrowsers
	}
	key, err := browsers.Keys.PushKey(ctx)
	if err != nil {
		return 0, err
	}
	subject := strings.TrimRight(base, "/")
	if !strings.HasPrefix(subject, "https://") {
		subject = "https://github.com/drudge/sable"
	}
	sender := webpush.Sender{Key: key, Subject: subject, Client: browsers.Client}
	if urgent {
		sender.Urgency = "high"
	}
	logger := browsers.Logger
	if logger == nil {
		logger = slog.Default()
	}
	sent := 0
	var failure error
	for _, subscription := range subscriptions {
		sendContext, cancel := context.WithTimeout(ctx, sendTimeout)
		err := sender.Send(sendContext, subscription, payload, pushTTL)
		cancel()
		switch {
		case err == nil:
			sent++
		case errors.Is(err, webpush.ErrGone):
			if err := browsers.Store.DeletePushSubscription(ctx, subscription.Endpoint); err != nil {
				logger.Warn("forget gone push subscription", "error", err)
			}
		default:
			logger.Warn("push alert", "browser", subscription.Label, "error", err)
			failure = err
		}
	}
	if sent == 0 && failure != nil {
		return 0, failure
	}
	if sent == 0 {
		return 0, ErrNoBrowsers
	}
	return sent, nil
}
