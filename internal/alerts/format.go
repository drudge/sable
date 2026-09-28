package alerts

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
)

// Links are how an alert points back at the console.
type Links struct {
	// Base is the console's advertised address, such as https://sable.example.
	Base string
	// Icon is the image browsers show beside a pushed alert.
	Icon string
}

// Header is one header an alert request carries.
type Header struct{ Name, Value string }

// Request is everything an alert sends, so the console can preview one before
// it goes out.
type Request struct {
	ContentType string
	Headers     []Header
	Body        []byte
}

// webhookAlert is what a plain webhook receives for one alert. Text and
// Content repeat the alert as one message, which Slack and Discord show on
// their own.
type webhookAlert struct {
	Source     string    `json:"source"`
	Event      string    `json:"event"`
	ID         string    `json:"id"`
	Group      string    `json:"group"`
	Kind       string    `json:"kind"`
	Tone       string    `json:"tone"`
	Priority   string    `json:"priority"`
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

// browserPush is what a browser's service worker gets for an alert.
type browserPush struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	URL   string `json:"url"`
	Tag   string `json:"tag"`
	Icon  string `json:"icon"`
}

// toneColors are the colors the console gives each tone, for the bar Slack
// draws beside a card and the edge of a Discord embed.
var toneColors = map[Tone]int{
	ToneAttention: 0xd97706,
	ToneNotice:    0x2563eb,
	TonePositive:  0x16a34a,
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

// truncate keeps text within a service's limit for a field.
func truncate(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit-1]) + "…"
}

// NotificationTitle is the title a notification shows: what kind of news, and
// what it is about.
func (alert Alert) NotificationTitle() string {
	if alert.Subject == "" {
		return alert.Title
	}
	return alert.Title + ": " + alert.Subject
}

// Link is where the alert's button leads in the console.
func (alert Alert) Link(links Links) string {
	path := alert.Path
	if path == "" {
		path = "/"
	}
	return strings.TrimRight(links.Base, "/") + path
}

// event names the alert for a plain webhook. Insights alerts keep the name
// older releases sent, so webhooks that filter on it keep working.
func (alert Alert) event() string {
	if alert.Group == config.AlertGroupInsights || alert.Group == "" {
		return "insight"
	}
	return alert.Group
}

// footer names what sent a Discord embed.
func (alert Alert) footer() string {
	if alert.Group == config.AlertGroupInsights || alert.Group == "" {
		return "Sable Insights"
	}
	return "Sable"
}

// Build lays out one alert in a destination's format.
func Build(destination config.AlertDestination, alert Alert, links Links) (Request, error) {
	link := alert.Link(links)
	title := alert.NotificationTitle()
	message := title + "\n" + alert.Summary
	var built Request
	switch destination.Format {
	case config.AlertFormatText:
		built.ContentType, built.Body = "text/plain; charset=utf-8", []byte(alert.Summary+"\n"+link)
		// ntfy shows this as the notification's title, and rings louder for a
		// high priority.
		built.Headers = append(built.Headers, Header{"Title", title})
		if alert.Problem {
			built.Headers = append(built.Headers, Header{"Priority", "high"})
		}
	case config.AlertFormatSlack:
		blocks := []slackBlock{
			{Type: "header", Text: &slackText{"plain_text", truncate(title, 150)}},
			{Type: "section", Text: &slackText{"mrkdwn", truncate(slackEscape.Replace(alert.Summary), 3000)}},
		}
		if len(alert.Reasons) > 0 {
			blocks = append(blocks, slackBlock{Type: "context", Elements: []slackElement{
				{Type: "mrkdwn", Text: truncate(slackEscape.Replace(strings.Join(alert.Reasons, " · ")), 2000)},
			}})
		}
		blocks = append(blocks, slackBlock{Type: "actions", Elements: []slackElement{
			{Type: "button", Text: slackText{"plain_text", pathLabel(alert)}, URL: link},
		}})
		encoded, err := json.Marshal(slackMessage{
			Text:        slackEscape.Replace(title + ": " + alert.Summary),
			Attachments: []slackAttachment{{Color: fmt.Sprintf("#%06x", toneColors[alert.Tone]), Blocks: blocks}},
		})
		if err != nil {
			return built, err
		}
		built.ContentType, built.Body = "application/json", encoded
	case config.AlertFormatDiscord:
		embed := discordEmbed{
			Title: truncate(title, 256), Description: truncate(alert.Summary, 4096), URL: link,
			Color: toneColors[alert.Tone], Timestamp: alert.ObservedAt.UTC().Format(time.RFC3339),
			Footer: discordFooter{Text: alert.footer()},
		}
		if len(alert.Reasons) > 0 {
			embed.Fields = []discordField{{Name: "Why", Value: truncate("• "+strings.Join(alert.Reasons, "\n• "), 1024)}}
		}
		encoded, err := json.Marshal(discordMessage{Username: "Sable", Embeds: []discordEmbed{embed}, AllowedMentions: discordMentions{Parse: []string{}}})
		if err != nil {
			return built, err
		}
		built.ContentType, built.Body = "application/json", encoded
	case config.AlertFormatBrowser:
		// Each browser gets this encrypted for it alone; the service worker
		// shows it as a notification.
		path := alert.Path
		if path == "" {
			path = "/"
		}
		encoded, err := json.Marshal(browserPush{
			Title: truncate(title, 120), Body: truncate(alert.Summary, 400), URL: path, Tag: alert.ID, Icon: links.Icon,
		})
		if err != nil {
			return built, err
		}
		built.ContentType, built.Body = "application/json", encoded
	case config.AlertFormatPushover:
		form := url.Values{
			"token": {destination.PushoverToken}, "user": {destination.PushoverUser},
			"title": {title}, "message": {alert.Summary}, "url": {link}, "url_title": {pathLabel(alert)},
		}
		if alert.Problem {
			form.Set("priority", "1")
		}
		built.ContentType, built.Body = "application/x-www-form-urlencoded", []byte(form.Encode())
	default:
		payload := webhookAlert{
			Source: "sable", Event: alert.event(), ID: alert.ID, Group: alert.Group, Kind: alert.Kind, Tone: string(alert.Tone),
			Priority: priority(alert), Title: alert.Title, Subject: alert.Subject, Headline: alert.Headline, Summary: alert.Summary,
			Reasons: alert.Reasons, ObservedAt: alert.ObservedAt.UTC(), URL: link, Text: message, Content: message,
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return built, err
		}
		built.ContentType, built.Body = "application/json", encoded
	}
	for _, header := range destination.Headers {
		built.Headers = append(built.Headers, Header{header.Name, header.Value})
	}
	return built, nil
}

func priority(alert Alert) string {
	if alert.Problem {
		return "high"
	}
	return "normal"
}

func pathLabel(alert Alert) string {
	if alert.PathLabel != "" {
		return alert.PathLabel
	}
	return "Open Sable"
}
