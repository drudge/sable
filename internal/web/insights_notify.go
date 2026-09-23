package web

import (
	"bytes"
	"context"
	"errors"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/version"
	"github.com/drudge/sable/internal/web/pages"
)

const (
	// insightAlertInterval is how often Insights looks for something new to
	// send. Device findings compare whole days, so minutes are plenty.
	insightAlertInterval = 5 * time.Minute
	// insightAlertDelay lets startup settle before the first look.
	insightAlertDelay = time.Minute
	// insightAlertForget is how long a finding must be gone before it can
	// alert again, so one that flickers does not alert every few minutes.
	insightAlertForget  = 6 * time.Hour
	insightAlertTimeout = 10 * time.Second
)

// insightNotificationStore is the optional store capability behind alerts.
type insightNotificationStore interface {
	InsightsNotified(context.Context, string) (map[string]time.Time, bool, error)
	MarkInsightsNotified(context.Context, string, []string, time.Time) error
	ForgetInsightsNotified(context.Context, string, []string) error
}

// insightAlert is what a webhook receives for one finding. Text and Content
// repeat the finding as one message, which Slack and Discord show on their
// own.
type insightAlert struct {
	Source     string    `json:"source"`
	Event      string    `json:"event"`
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Tone       string    `json:"tone"`
	Title      string    `json:"title"`
	Subject    string    `json:"subject"`
	Headline   string    `json:"headline"`
	Summary    string    `json:"summary"`
	Reasons    []string  `json:"reasons"`
	ObservedAt time.Time `json:"observed_at"`
	URL        string    `json:"url"`
	Text       string    `json:"text"`
	Content    string    `json:"content"`
}

// RunInsightAlerts sends each new finding worth a look to the configured
// webhook until ctx ends. Only the node leading says what is news, so a
// cluster alerts once.
func (server *Server) RunInsightAlerts(ctx context.Context, leading func() bool) {
	timer := time.NewTimer(insightAlertDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if leading == nil || leading() {
			if err := server.sendInsightAlerts(ctx, time.Now()); err != nil && ctx.Err() == nil {
				server.logger.Warn("send insight alerts", "error", err)
			}
		}
		timer.Reset(insightAlertInterval)
	}
}

// sendInsightAlerts compares what Insights finds now with what the webhook was
// already told. A webhook it has never told anything first takes stock
// quietly, so turning alerts on never floods it with old news.
func (server *Server) sendInsightAlerts(ctx context.Context, now time.Time) error {
	snapshot := server.config.Current().Config
	webhook := snapshot.Insights.Webhook
	notifications, ok := server.queries.(insightNotificationStore)
	if webhook.URL == "" || !ok {
		return nil
	}
	target := insightAlertTarget(webhook.URL)
	notified, known, err := notifications.InsightsNotified(ctx, target)
	if err != nil {
		return err
	}
	news := server.insightNews(ctx, now)
	if !known {
		ids := make([]string, 0, len(news))
		for _, finding := range news {
			ids = append(ids, finding.ID)
		}
		return notifications.MarkInsightsNotified(ctx, target, ids, now)
	}
	current := make(map[string]bool, len(news))
	for _, finding := range news {
		current[finding.ID] = true
		if _, sent := notified[finding.ID]; sent {
			continue
		}
		if err := server.postInsightAlert(ctx, webhook, snapshot, finding); err != nil {
			return err
		}
		if err := notifications.MarkInsightsNotified(ctx, target, []string{finding.ID}, now); err != nil {
			return err
		}
	}
	gone := make([]string, 0)
	for id, at := range notified {
		if !current[id] && now.Sub(at) >= insightAlertForget {
			gone = append(gone, id)
		}
	}
	return notifications.ForgetInsightsNotified(ctx, target, gone)
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

func (server *Server) postInsightAlert(ctx context.Context, webhook config.InsightsWebhook, snapshot config.Config, finding insights.Finding) error {
	link := strings.TrimRight(snapshot.AdvertisedBaseURL(), "/") + "/insights"
	message := finding.Title + ": " + finding.Subject.Label + "\n" + finding.Summary
	alert := insightAlert{
		Source: "sable", Event: "insight", ID: finding.ID, Kind: finding.Kind, Tone: string(finding.Tone),
		Title: finding.Title, Subject: finding.Subject.Label, Headline: finding.Headline, Summary: finding.Summary,
		ObservedAt: finding.ObservedAt.UTC(), URL: link, Text: message, Content: message,
	}
	for _, reason := range finding.Reasons {
		alert.Reasons = append(alert.Reasons, strings.TrimSpace(reason.Text+" "+reason.Code))
	}
	var body []byte
	contentType := "application/json"
	if webhook.Format == config.InsightsWebhookText {
		body, contentType = []byte(finding.Summary+"\n"+link), "text/plain; charset=utf-8"
	} else {
		encoded, err := json.Marshal(alert)
		if err != nil {
			return err
		}
		body = encoded
	}
	requestContext, cancel := context.WithTimeout(ctx, insightAlertTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, webhook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("User-Agent", "Sable/"+version.Current().Release)
	if webhook.Format == config.InsightsWebhookText {
		// ntfy shows this as the notification's title.
		request.Header.Set("Title", finding.Title+": "+finding.Subject.Label)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("post insight alert: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("post insight alert: webhook answered %s", response.Status)
	}
	return nil
}

// insightAlertTarget names a webhook without keeping its URL, which often
// carries a secret token, in the database.
func insightAlertTarget(url string) string {
	sum := sha256.Sum256([]byte(url))
	return hex.EncodeToString(sum[:16])
}

// insightAlertsView is the alert setup as the Overview shows it, for
// operators who can change it.
func (server *Server) insightAlertsView(console pages.DashboardView) *pages.InsightAlertsView {
	if !console.CanWriteSettings {
		return nil
	}
	if _, ok := server.queries.(insightNotificationStore); !ok {
		return nil
	}
	webhook := server.config.Current().Config.Insights.Webhook
	return &pages.InsightAlertsView{URL: webhook.URL, Format: webhook.Format}
}

// saveInsightAlerts changes where new findings are sent.
func (server *Server) saveInsightAlerts(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil {
		writeFragmentStatus(writer, http.StatusBadRequest)
		return
	}
	webhook := config.InsightsWebhook{URL: strings.TrimSpace(request.FormValue("url")), Format: request.FormValue("format")}
	view := pages.InsightAlertsView{URL: webhook.URL, Format: webhook.Format}
	editor, ok := server.config.(settingsEditor)
	err := webhook.Validate()
	if err == nil && !ok {
		err = errors.New("configuration cannot be edited on this server")
	}
	if err == nil {
		err = editor.Update(request.Context(), func(configuration *config.Config) error {
			configuration.Insights.Webhook = webhook
			return nil
		})
	}
	if err != nil {
		writeFragmentStatus(writer, http.StatusUnprocessableEntity)
		view.Error = err.Error()
	} else {
		view.Message = "Alerts turned off."
		if webhook.URL != "" {
			view.Message = "Saved. New findings will be sent to this webhook."
		}
		server.recordControlPlaneAudit(request, "insights.alerts", ifThenString(webhook.URL != "", "set the Insights alert webhook", "turned Insights alerts off"))
	}
	server.renderInsightAlerts(writer, request, view)
}

// testInsightAlerts sends a sample alert to the saved webhook.
func (server *Server) testInsightAlerts(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	snapshot := server.config.Current().Config
	webhook := snapshot.Insights.Webhook
	view := pages.InsightAlertsView{URL: webhook.URL, Format: webhook.Format}
	if webhook.URL == "" {
		view.Error = "Save a webhook URL first."
		server.renderInsightAlerts(writer, request, view)
		return
	}
	sample := insights.Finding{
		ID: "sable.test", Kind: "sable.test", Tone: insights.ToneNotice, Title: "Test alert",
		Subject: insights.Subject{Label: "Sable"}, Headline: "Sable can reach this webhook",
		Summary: "This is a test from Sable Insights. New findings worth a look will arrive like this.",
		ObservedAt: time.Now(),
	}
	if err := server.postInsightAlert(request.Context(), webhook, snapshot, sample); err != nil {
		view.Error = err.Error()
	} else {
		view.Message = "Test sent."
	}
	server.renderInsightAlerts(writer, request, view)
}

func (server *Server) renderInsightAlerts(writer http.ResponseWriter, request *http.Request, view pages.InsightAlertsView) {
	if err := pages.InsightAlerts(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render insight alerts", "error", err)
	}
}
