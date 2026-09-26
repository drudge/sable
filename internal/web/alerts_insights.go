package web

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/drudge/sable/internal/alerts"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/web/pages"
	"github.com/drudge/sable/internal/webpush"
)

// insightAlertCache is how long Insights keeps its answer as an alert source.
// Device findings compare whole days, so minutes are plenty, and the analysis
// is too costly to run every time the dispatcher asks.
const insightAlertCache = 5 * time.Minute

// pushSubscriptionStore is the optional store capability behind browser
// alerts.
type pushSubscriptionStore interface {
	SavePushSubscription(context.Context, webpush.Subscription) error
	PushSubscriptions(context.Context) ([]webpush.Subscription, error)
	DeletePushSubscription(context.Context, string) error
}

// pushKeySource hands out the key browser pushes are signed with.
type pushKeySource interface {
	PushKey(context.Context) (*ecdsa.PrivateKey, error)
}

// SetPushKeys lets browsers subscribe to alerts.
func (server *Server) SetPushKeys(keys pushKeySource) { server.pushKeys = keys }

// SetAlerts gives the console the dispatcher that sends alerts and the store
// their destinations' secrets live in, for the alert settings.
func (server *Server) SetAlerts(dispatcher *alerts.Dispatcher, secrets *alerts.SecretStore) {
	server.alerts, server.alertSecrets = dispatcher, secrets
}

// InsightAlerts is Insights as an alert source: every finding from the last
// day that is news, minus what an operator hid.
func (server *Server) InsightAlerts() alerts.Source {
	return &insightAlertSource{server: server}
}

type insightAlertSource struct {
	server *Server
	mu     sync.Mutex
	at     time.Time
	alerts []alerts.Alert
}

func (source *insightAlertSource) Alerts(ctx context.Context, now time.Time) ([]alerts.Alert, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.at.IsZero() || now.Before(source.at) || now.Sub(source.at) >= insightAlertCache {
		news := source.server.insightNews(ctx, now)
		source.alerts = make([]alerts.Alert, 0, len(news))
		for _, finding := range news {
			source.alerts = append(source.alerts, insightAlert(finding))
		}
		source.at = now
	}
	return slices.Clone(source.alerts), nil
}

// insightAlert words a finding as an alert. It keeps the finding's ID, which
// is how older releases recorded what each destination was sent.
func insightAlert(finding insights.Finding) alerts.Alert {
	reasons := make([]string, 0, len(finding.Reasons))
	for _, reason := range finding.Reasons {
		if text := strings.TrimSpace(reason.Text + " " + reason.Code); text != "" {
			reasons = append(reasons, text)
		}
	}
	tone := alerts.ToneNotice
	switch finding.Tone {
	case insights.ToneAttention:
		tone = alerts.ToneAttention
	case insights.TonePositive:
		tone = alerts.TonePositive
	}
	return alerts.Alert{
		ID: finding.ID, Group: config.AlertGroupInsights, Kind: finding.Kind, Tone: tone,
		Title: finding.Title, Subject: finding.Subject.Label, Headline: finding.Headline, Summary: finding.Summary,
		Reasons: reasons, Path: "/insights", PathLabel: "Open Insights", ObservedAt: finding.ObservedAt,
	}
}

// insightNews is every finding from the last day that is news, minus what an
// operator hid.
func (server *Server) insightNews(ctx context.Context, now time.Time) []insights.Finding {
	window := insightsWindow("day", now)
	console := pages.DashboardView{CanLogs: true, CanBlocking: true}
	analyzers, _, _ := server.insightAnalyzers(console, window)
	findings := insights.Collect(ctx, insights.Window{Start: window.Start, End: window.End}, analyzers,
		func(analyzer insights.Analyzer, err error) {
			server.logger.Warn("analyze insights for alerts", "analyzer", fmt.Sprintf("%T", analyzer), "error", err)
		})
	if store, ok := server.queries.(insightFeedbackStore); ok {
		if feedback, err := store.InsightFeedback(ctx, now); err == nil {
			findings, _ = insights.Hide(findings, feedback, now)
		}
	}
	news := make([]insights.Finding, 0, len(findings))
	for _, finding := range findings {
		if finding.Headline != "" {
			news = append(news, finding)
		}
	}
	return news
}

// browserLabel names a browser the way people know it, from its user agent.
func browserLabel(userAgent string) string {
	browser := "A browser"
	for _, known := range []struct{ token, name string }{
		{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Firefox/", "Firefox"}, {"FxiOS/", "Firefox"},
		{"CriOS/", "Chrome"}, {"Chrome/", "Chrome"}, {"Safari/", "Safari"},
	} {
		if strings.Contains(userAgent, known.token) {
			browser = known.name
			break
		}
	}
	for _, known := range []struct{ token, name string }{
		{"iPhone", "iPhone"}, {"iPad", "iPad"}, {"Android", "Android"}, {"Mac OS X", "macOS"},
		{"Windows", "Windows"}, {"CrOS", "ChromeOS"}, {"Linux", "Linux"},
	} {
		if strings.Contains(userAgent, known.token) {
			return browser + " on " + known.name
		}
	}
	return browser
}
