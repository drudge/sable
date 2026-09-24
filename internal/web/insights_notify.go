package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
// quietly, so turning alerts on never floods it with old news. A paused
// webhook keeps taking stock, so resuming never sends what happened meanwhile.
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
		if !webhook.Paused {
			if _, err := server.postInsightAlert(ctx, webhook, snapshot, finding); err != nil {
				return err
			}
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

// ntfyReceipt is the part of ntfy's answer that shows it published a message.
type ntfyReceipt struct {
	ID    string `json:"id"`
	Event string `json:"event"`
}

// pushoverAnswer is what Pushover's message API says about a send.
type pushoverAnswer struct {
	Status  int      `json:"status"`
	Request string   `json:"request"`
	Errors  []string `json:"errors"`
}

// insightToneColors are the colors the console gives each tone, for the
// bar Slack draws beside a card and the edge of a Discord embed.
var insightToneColors = map[insights.Tone]int{
	insights.ToneAttention: 0xd97706,
	insights.ToneNotice:    0x2563eb,
	insights.TonePositive:  0x16a34a,
}

// slackMessage is a Slack incoming-webhook message. Text is what
// notifications show; the attachment carries the card and its colored bar.
type slackMessage struct {
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color  string       `json:"color"`
	Blocks []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type     string         `json:"type"`
	Text     *slackText     `json:"text,omitempty"`
	Elements []slackElement `json:"elements,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// slackElement is a context block's text or an actions block's button.
type slackElement struct {
	Type string `json:"type"`
	Text any    `json:"text,omitempty"`
	URL  string `json:"url,omitempty"`
}

// discordMessage is a Discord webhook message with one embed. It mentions no
// one, whatever a device happens to be called.
type discordMessage struct {
	Username        string          `json:"username"`
	Embeds          []discordEmbed  `json:"embeds"`
	AllowedMentions discordMentions `json:"allowed_mentions"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	URL         string         `json:"url"`
	Color       int            `json:"color"`
	Timestamp   string         `json:"timestamp"`
	Fields      []discordField `json:"fields,omitempty"`
	Footer      discordFooter  `json:"footer"`
}

type discordField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type discordFooter struct {
	Text string `json:"text"`
}

type discordMentions struct {
	Parse []string `json:"parse"`
}

// slackEscape keeps Slack from reading a device name as a link or mention.
var slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// truncateAlertText keeps text within a service's limit for a field.
func truncateAlertText(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit-1]) + "…"
}

// insightReasonTexts lists a finding's reasons as people read them.
func insightReasonTexts(finding insights.Finding) []string {
	texts := make([]string, 0, len(finding.Reasons))
	for _, reason := range finding.Reasons {
		if text := strings.TrimSpace(reason.Text + " " + reason.Code); text != "" {
			texts = append(texts, text)
		}
	}
	return texts
}

// insightAlertHeader is one header an alert request carries.
type insightAlertHeader struct{ Name, Value string }

// insightAlertRequest is everything an alert sends, so the console can
// preview a request before it is sent.
type insightAlertRequest struct {
	ContentType string
	Headers     []insightAlertHeader
	Body        []byte
}

// buildInsightAlert lays out one finding in the webhook's format.
func buildInsightAlert(webhook config.InsightsWebhook, snapshot config.Config, finding insights.Finding) (insightAlertRequest, error) {
	link := strings.TrimRight(snapshot.AdvertisedBaseURL(), "/") + "/insights"
	title := finding.Title + ": " + finding.Subject.Label
	message := title + "\n" + finding.Summary
	var built insightAlertRequest
	switch webhook.Format {
	case config.InsightsWebhookText:
		built.ContentType, built.Body = "text/plain; charset=utf-8", []byte(finding.Summary+"\n"+link)
		// ntfy shows this as the notification's title.
		built.Headers = append(built.Headers, insightAlertHeader{"Title", title})
	case config.InsightsWebhookSlack:
		blocks := []slackBlock{
			{Type: "header", Text: &slackText{"plain_text", truncateAlertText(title, 150)}},
			{Type: "section", Text: &slackText{"mrkdwn", truncateAlertText(slackEscape.Replace(finding.Summary), 3000)}},
		}
		if reasons := insightReasonTexts(finding); len(reasons) > 0 {
			blocks = append(blocks, slackBlock{Type: "context", Elements: []slackElement{
				{Type: "mrkdwn", Text: truncateAlertText(slackEscape.Replace(strings.Join(reasons, " · ")), 2000)},
			}})
		}
		blocks = append(blocks, slackBlock{Type: "actions", Elements: []slackElement{
			{Type: "button", Text: slackText{"plain_text", "Open Insights"}, URL: link},
		}})
		encoded, err := json.Marshal(slackMessage{
			Text:        slackEscape.Replace(title + ": " + finding.Summary),
			Attachments: []slackAttachment{{Color: fmt.Sprintf("#%06x", insightToneColors[finding.Tone]), Blocks: blocks}},
		})
		if err != nil {
			return built, err
		}
		built.ContentType, built.Body = "application/json", encoded
	case config.InsightsWebhookDiscord:
		embed := discordEmbed{
			Title: truncateAlertText(title, 256), Description: truncateAlertText(finding.Summary, 4096), URL: link,
			Color: insightToneColors[finding.Tone], Timestamp: finding.ObservedAt.UTC().Format(time.RFC3339),
			Footer: discordFooter{Text: "Sable Insights"},
		}
		if reasons := insightReasonTexts(finding); len(reasons) > 0 {
			embed.Fields = []discordField{{Name: "Why", Value: truncateAlertText("• "+strings.Join(reasons, "\n• "), 1024)}}
		}
		encoded, err := json.Marshal(discordMessage{Username: "Sable", Embeds: []discordEmbed{embed}, AllowedMentions: discordMentions{Parse: []string{}}})
		if err != nil {
			return built, err
		}
		built.ContentType, built.Body = "application/json", encoded
	case config.InsightsWebhookPushover:
		form := url.Values{
			"token": {webhook.PushoverToken}, "user": {webhook.PushoverUser},
			"title": {title}, "message": {finding.Summary}, "url": {link}, "url_title": {"Open Insights"},
		}
		built.ContentType, built.Body = "application/x-www-form-urlencoded", []byte(form.Encode())
	default:
		alert := insightAlert{
			Source: "sable", Event: "insight", ID: finding.ID, Kind: finding.Kind, Tone: string(finding.Tone),
			Title: finding.Title, Subject: finding.Subject.Label, Headline: finding.Headline, Summary: finding.Summary,
			ObservedAt: finding.ObservedAt.UTC(), URL: link, Text: message, Content: message,
		}
		for _, reason := range finding.Reasons {
			alert.Reasons = append(alert.Reasons, strings.TrimSpace(reason.Text+" "+reason.Code))
		}
		encoded, err := json.Marshal(alert)
		if err != nil {
			return built, err
		}
		built.ContentType, built.Body = "application/json", encoded
	}
	for _, header := range webhook.Headers {
		built.Headers = append(built.Headers, insightAlertHeader{header.Name, header.Value})
	}
	return built, nil
}

// postInsightAlert sends one finding. When the answer carries a receipt,
// from ntfy or Pushover, it returns the ID it gave the message.
func (server *Server) postInsightAlert(ctx context.Context, webhook config.InsightsWebhook, snapshot config.Config, finding insights.Finding) (string, error) {
	built, err := buildInsightAlert(webhook, snapshot, finding)
	if err != nil {
		return "", err
	}
	requestContext, cancel := context.WithTimeout(ctx, insightAlertTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, webhook.URL, bytes.NewReader(built.Body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", built.ContentType)
	request.Header.Set("User-Agent", "Sable/"+version.Current().Release)
	for _, header := range built.Headers {
		request.Header.Set(header.Name, header.Value)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("post insight alert: %w", err)
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	switch webhook.Format {
	case config.InsightsWebhookSlack:
		// Slack answers "ok", or says what was wrong in plain words.
		said := strings.TrimSpace(string(answer))
		if response.StatusCode >= 400 && said != "" && !strings.HasPrefix(said, "<") {
			return "", fmt.Errorf("Slack did not post it: %s", truncateAlertText(said, 200))
		}
		if response.StatusCode < 200 || response.StatusCode > 299 || said != "ok" {
			return "", fmt.Errorf("the webhook answered %s, but not like Slack; check the URL", response.Status)
		}
		return "", nil
	case config.InsightsWebhookDiscord:
		// Discord answers 204 with nothing, or the message it posted when
		// asked to wait, and explains a refusal in JSON.
		var discord struct {
			ID      string `json:"id"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(answer, &discord)
		switch {
		case response.StatusCode >= 400 && discord.Message != "":
			return "", fmt.Errorf("Discord did not post it: %s", discord.Message)
		case response.StatusCode == http.StatusNoContent || (response.StatusCode >= 200 && response.StatusCode <= 299 && discord.ID != ""):
			return "", nil
		default:
			return "", fmt.Errorf("the webhook answered %s, but not like Discord; check the URL", response.Status)
		}
	case config.InsightsWebhookPushover:
		// Pushover always answers with a status, and says what was wrong.
		var pushover pushoverAnswer
		if json.Unmarshal(answer, &pushover) != nil {
			return "", fmt.Errorf("the webhook answered %s, but not like Pushover; check the URL", response.Status)
		}
		if pushover.Status != 1 {
			return "", fmt.Errorf("Pushover did not send it: %s", strings.Join(pushover.Errors, "; "))
		}
		return pushover.Request, nil
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", fmt.Errorf("post insight alert: webhook answered %s", response.Status)
	}
	if !webhook.NtfyReceipt {
		return "", nil
	}
	// Any server can answer 200, including a parked domain behind a typo, so
	// only ntfy's own receipt proves the message was published.
	var receipt ntfyReceipt
	if json.Unmarshal(answer, &receipt) != nil || receipt.ID == "" || receipt.Event != "message" {
		return "", errors.New("the webhook answered, but not with an ntfy receipt; check the URL")
	}
	return receipt.ID, nil
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
	view := newInsightAlertsView(server.config.Current().Config.Insights.Webhook)
	return &view
}

func newInsightAlertsView(webhook config.InsightsWebhook) pages.InsightAlertsView {
	view := pages.InsightAlertsView{
		URL: webhook.URL, Format: webhook.Format, Paused: webhook.Paused, NtfyReceipt: webhook.NtfyReceipt,
		PushoverToken: webhook.PushoverToken, PushoverUser: webhook.PushoverUser,
	}
	for _, header := range webhook.Headers {
		view.Headers = append(view.Headers, pages.InsightAlertHeader{Name: header.Name, Value: header.Value})
	}
	return view
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
	webhook := insightWebhookFromForm(request, server.config.Current().Config.Insights.Webhook)
	view := newInsightAlertsView(webhook)
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
		switch {
		case webhook.URL == "":
			view.Message = "Alerts turned off."
		case webhook.Paused:
			view.Message = "Saved. Alerts are paused."
		default:
			view.Message = "Saved. New findings will be sent to this webhook."
		}
		server.recordControlPlaneAudit(request, "insights.alerts", ifThenString(webhook.URL != "", "set the Insights alert webhook", "turned Insights alerts off"))
		// The bell beside the range control shows the old state until the page
		// reloads itself.
		writer.Header().Set("HX-Trigger", "insightsChanged")
	}
	server.renderInsightAlerts(writer, request, view)
}

// insightWebhookFromForm reads the alert setup as the dialog posts it. Saving
// changes where alerts go, not whether they are paused, so that comes from
// the current setup.
func insightWebhookFromForm(request *http.Request, current config.InsightsWebhook) config.InsightsWebhook {
	webhook := config.InsightsWebhook{
		URL: request.FormValue("url"), Format: request.FormValue("format"), Paused: current.Paused,
		NtfyReceipt:   request.FormValue("ntfy_receipt") == "true",
		PushoverToken: request.FormValue("pushover_token"), PushoverUser: request.FormValue("pushover_user"),
	}
	// The dialog asks Pushover for no URL; its own API is the one to use.
	if webhook.Format == config.InsightsWebhookPushover {
		webhook.URL = ""
	}
	names, values := request.Form["header_name"], request.Form["header_value"]
	for index, name := range names {
		header := config.InsightsWebhookHeader{Name: name}
		if index < len(values) {
			header.Value = values[index]
		}
		webhook.Headers = append(webhook.Headers, header)
	}
	webhook.Normalize()
	return webhook
}

// previewInsightAlerts shows what a sample alert would send in the format
// the dialog has picked, saved or not, with secrets cut short.
func (server *Server) previewInsightAlerts(writer http.ResponseWriter, request *http.Request) {
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
	snapshot := server.config.Current().Config
	webhook := insightWebhookFromForm(request, snapshot.Insights.Webhook)
	built, err := buildInsightAlert(webhook, snapshot, sampleInsightFinding(time.Now()))
	preview := pages.InsightAlertPreview{Method: "POST", URL: maskInsightWebhookURL(webhook), ContentType: built.ContentType}
	if err != nil {
		preview.Error = err.Error()
	}
	for _, header := range built.Headers {
		value := header.Value
		if strings.EqualFold(header.Name, "Authorization") {
			value = maskInsightSecret(value)
		}
		preview.Headers = append(preview.Headers, pages.InsightAlertHeader{Name: header.Name, Value: value})
	}
	preview.Body = previewInsightAlertBody(built)
	if err := pages.InsightAlertPreviewPanel(preview).Render(request.Context(), writer); err != nil {
		server.logger.Error("render insight alert preview", "error", err)
	}
}

// previewInsightAlertBody lays a body out to be read: JSON indented, and a
// form one field per line.
func previewInsightAlertBody(built insightAlertRequest) string {
	switch built.ContentType {
	case "application/json":
		var indented bytes.Buffer
		if json.Indent(&indented, built.Body, "", "  ") == nil {
			return indented.String()
		}
	case "application/x-www-form-urlencoded":
		form, err := url.ParseQuery(string(built.Body))
		if err != nil {
			break
		}
		lines := make([]string, 0, len(form))
		for _, name := range []string{"token", "user", "title", "message", "url", "url_title"} {
			value := form.Get(name)
			if name == "token" || name == "user" {
				value = maskInsightSecret(value)
			}
			lines = append(lines, name+"="+value)
		}
		return strings.Join(lines, "\n")
	}
	return string(built.Body)
}

// maskInsightWebhookURL cuts short the token that ends a Slack or Discord
// webhook URL, which is all it takes to post to the channel.
func maskInsightWebhookURL(webhook config.InsightsWebhook) string {
	if webhook.Format != config.InsightsWebhookSlack && webhook.Format != config.InsightsWebhookDiscord {
		return webhook.URL
	}
	address, _, _ := strings.Cut(webhook.URL, "?")
	address = strings.TrimRight(address, "/")
	cut := strings.LastIndex(address, "/")
	if cut < 0 || strings.HasSuffix(address[:cut], "/") {
		return webhook.URL
	}
	return address[:cut+1] + maskInsightSecret(address[cut+1:])
}

// maskInsightSecret keeps only enough of a secret to tell which one it is.
func maskInsightSecret(secret string) string {
	if len(secret) <= 4 {
		return strings.Repeat("•", len(secret))
	}
	return "••••" + secret[len(secret)-4:]
}

// sampleInsightFinding stands in for a real finding in tests and previews.
func sampleInsightFinding(now time.Time) insights.Finding {
	return insights.Finding{
		ID: "sable.test", Kind: "sable.test", Tone: insights.ToneNotice, Title: "Test alert",
		Subject: insights.Subject{Label: "Sable"}, Headline: "Sable can reach this webhook",
		Summary:    "This is a test from Sable Insights. New findings worth a look will arrive like this.",
		Reasons:    insights.Reasons("Sent from the Alerts setup to show how findings arrive."),
		ObservedAt: now,
	}
}

// setInsightAlertsEnabled pauses or resumes alerts without forgetting the
// webhook.
func (server *Server) setInsightAlertsEnabled(writer http.ResponseWriter, request *http.Request) {
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
	paused := request.FormValue("enabled") != "true"
	webhook := server.config.Current().Config.Insights.Webhook
	view := newInsightAlertsView(webhook)
	if webhook.URL == "" {
		view.Error = "Save a webhook URL first."
		server.renderInsightAlerts(writer, request, view)
		return
	}
	editor, ok := server.config.(settingsEditor)
	err := errors.New("configuration cannot be edited on this server")
	if ok {
		err = editor.Update(request.Context(), func(configuration *config.Config) error {
			configuration.Insights.Webhook.Paused = paused
			return nil
		})
	}
	if err != nil {
		writeFragmentStatus(writer, http.StatusUnprocessableEntity)
		view.Error = err.Error()
	} else {
		view.Paused = paused
		view.Message = ifThenString(paused, "Alerts paused.", "Alerts resumed. Only findings from now on will be sent.")
		server.recordControlPlaneAudit(request, "insights.alerts", ifThenString(paused, "paused Insights alerts", "resumed Insights alerts"))
		writer.Header().Set("HX-Trigger", "insightsChanged")
	}
	server.renderInsightAlerts(writer, request, view)
}

// testInsightAlerts sends a sample alert to the saved webhook, even while
// alerts are paused.
func (server *Server) testInsightAlerts(writer http.ResponseWriter, request *http.Request) {
	console := server.consoleView(request)
	if !console.CanWriteSettings {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return
	}
	snapshot := server.config.Current().Config
	webhook := snapshot.Insights.Webhook
	view := newInsightAlertsView(webhook)
	if webhook.URL == "" {
		view.Error = "Save a webhook URL first."
		server.renderInsightAlerts(writer, request, view)
		return
	}
	if receipt, err := server.postInsightAlert(request.Context(), webhook, snapshot, sampleInsightFinding(time.Now())); err != nil {
		view.Error = err.Error()
	} else if webhook.Format == config.InsightsWebhookSlack || webhook.Format == config.InsightsWebhookDiscord {
		view.Message = "Test sent. " + ifThenString(webhook.Format == config.InsightsWebhookSlack, "Slack", "Discord") + " posted it."
	} else if receipt != "" && webhook.Format == config.InsightsWebhookPushover {
		view.Message = "Test sent. Pushover accepted it as request " + receipt + "."
	} else if receipt != "" {
		view.Message = "Test sent. ntfy published it as message " + receipt + "."
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
