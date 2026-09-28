package alerts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/drudge/sable/internal/config"
)

func answering(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(server.Close)
	return server
}

func post(t *testing.T, destination config.AlertDestination, alert Alert) (string, error) {
	t.Helper()
	built, err := Build(destination, alert, Links{Base: "https://sable.example"})
	if err != nil {
		t.Fatal(err)
	}
	return Post(context.Background(), nil, destination, built)
}

func TestNtfyReceiptsProveTheMessageWasPublished(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var authorization string
	ntfy := answering(t, func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		authorization = request.Header.Get("Authorization")
		mu.Unlock()
		_, _ = io.WriteString(writer, `{"id":"kqsbW5IVYYUc","time":1790289679,"event":"message","topic":"sable","message":"hi"}`)
	})
	// A parked domain answers anything with a page.
	parked := answering(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "<html>This domain is for sale</html>")
	})
	destination := config.AlertDestination{Format: config.AlertFormatText, URL: ntfy.URL, NtfyReceipt: true,
		Headers: []config.AlertHeader{{Name: "Authorization", Value: "Bearer tk_secret"}}}
	if receipt, err := post(t, destination, Sample(testNow)); err != nil || receipt != "kqsbW5IVYYUc" {
		t.Fatalf("posting to ntfy = %q, %v", receipt, err)
	}
	mu.Lock()
	if authorization != "Bearer tk_secret" {
		t.Fatalf("Authorization sent = %q", authorization)
	}
	mu.Unlock()
	destination.URL = parked.URL
	if _, err := post(t, destination, Sample(testNow)); err == nil || !strings.Contains(err.Error(), "not with an ntfy receipt") {
		t.Fatalf("posting to a parked domain = %v", err)
	}
	// Without the check, any 200 counts.
	destination.NtfyReceipt = false
	if _, err := post(t, destination, Sample(testNow)); err != nil {
		t.Fatalf("posting without the check = %v", err)
	}
}

func TestPushoverSaysWhatItRejected(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var form url.Values
	pushover := answering(t, func(writer http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		mu.Lock()
		form = request.PostForm
		mu.Unlock()
		if request.PostForm.Get("token") != "app-token" {
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(writer, `{"token":"invalid","errors":["application token is invalid"],"status":0,"request":"r-bad"}`)
			return
		}
		_, _ = io.WriteString(writer, `{"status":1,"request":"r-good"}`)
	})
	destination := config.AlertDestination{Format: config.AlertFormatPushover, URL: pushover.URL, PushoverToken: "app-token", PushoverUser: "user-key"}
	if receipt, err := post(t, destination, Sample(testNow)); err != nil || receipt != "r-good" {
		t.Fatalf("posting to Pushover = %q, %v", receipt, err)
	}
	mu.Lock()
	if form.Get("user") != "user-key" || form.Get("title") != "Test alert: Sable" || form.Get("url") != "https://sable.example/settings?tab=alerts" ||
		form.Get("url_title") != "Open Alerts" || form.Has("priority") {
		t.Fatalf("Pushover got %v", form)
	}
	mu.Unlock()
	destination.PushoverToken = "wrong"
	if _, err := post(t, destination, Sample(testNow)); err == nil || !strings.Contains(err.Error(), "application token is invalid") {
		t.Fatalf("posting a wrong token = %v", err)
	}
	// A destination with no URL posts to Pushover's own API.
	if built, err := Build(config.AlertDestination{Format: config.AlertFormatPushover}, Sample(testNow), Links{}); err != nil || built.ContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("built = %+v, %v", built, err)
	}
}

func TestSlackAndDiscordGetRichMessagesAndSayWhatWentWrong(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	bodies := map[string][]byte{}
	slack := answering(t, func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mu.Lock()
		bodies["slack"] = body
		mu.Unlock()
		if strings.HasSuffix(request.URL.Path, "/bad") {
			writer.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(writer, "invalid_token")
			return
		}
		_, _ = io.WriteString(writer, "ok")
	})
	discord := answering(t, func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mu.Lock()
		bodies["discord"] = body
		mu.Unlock()
		if strings.HasSuffix(request.URL.Path, "/bad") {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(writer, `{"message": "Invalid Webhook Token", "code": 50027}`)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	parked := answering(t, func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "<html>This domain is for sale</html>")
	})
	alert := finding("quiet")
	alert.Reasons = []string{"No queries in the last 24 hours"}
	send := func(format, address string) error {
		t.Helper()
		_, err := post(t, config.AlertDestination{Format: format, URL: address}, alert)
		return err
	}
	if err := send(config.AlertFormatSlack, slack.URL+"/services/good"); err != nil {
		t.Fatalf("posting to Slack = %v", err)
	}
	var message slackMessage
	mu.Lock()
	if err := json.Unmarshal(bodies["slack"], &message); err != nil {
		t.Fatal(err)
	}
	mu.Unlock()
	blocks := message.Attachments[0].Blocks
	if message.Text == "" || message.Attachments[0].Color != "#d97706" || blocks[0].Type != "header" || blocks[0].Text.Text != "Went quiet: Printer" ||
		blocks[2].Type != "context" || blocks[3].Type != "actions" || blocks[3].Elements[0].URL != "https://sable.example/insights" {
		t.Fatalf("Slack message = %s", bodies["slack"])
	}
	if err := send(config.AlertFormatSlack, slack.URL+"/services/bad"); err == nil || !strings.Contains(err.Error(), "Slack did not post it: invalid_token") {
		t.Fatalf("posting a bad Slack token = %v", err)
	}
	if err := send(config.AlertFormatSlack, parked.URL); err == nil || !strings.Contains(err.Error(), "not like Slack") {
		t.Fatalf("posting Slack to a parked domain = %v", err)
	}
	if err := send(config.AlertFormatDiscord, discord.URL+"/api/webhooks/good"); err != nil {
		t.Fatalf("posting to Discord = %v", err)
	}
	var posted map[string]any
	mu.Lock()
	if err := json.Unmarshal(bodies["discord"], &posted); err != nil {
		t.Fatal(err)
	}
	mu.Unlock()
	embed := posted["embeds"].([]any)[0].(map[string]any)
	mentions := posted["allowed_mentions"].(map[string]any)["parse"].([]any)
	if embed["title"] != "Went quiet: Printer" || embed["color"] != float64(0xd97706) || embed["url"] != "https://sable.example/insights" ||
		embed["fields"].([]any)[0].(map[string]any)["name"] != "Why" || embed["footer"].(map[string]any)["text"] != "Sable Insights" || len(mentions) != 0 {
		t.Fatalf("Discord message = %s", bodies["discord"])
	}
	if err := send(config.AlertFormatDiscord, discord.URL+"/api/webhooks/bad"); err == nil || !strings.Contains(err.Error(), "Discord did not post it: Invalid Webhook Token") {
		t.Fatalf("posting a bad Discord token = %v", err)
	}
	if err := send(config.AlertFormatDiscord, parked.URL); err == nil || !strings.Contains(err.Error(), "not like Discord") {
		t.Fatalf("posting Discord to a parked domain = %v", err)
	}
}

func TestSlackDoesNotReadDeviceNamesAsMarkup(t *testing.T) {
	t.Parallel()
	alert := Sample(testNow)
	alert.Summary = "<!channel> & <https://evil.example|click>"
	built, err := Build(config.AlertDestination{Format: config.AlertFormatSlack}, alert, Links{})
	if err != nil {
		t.Fatal(err)
	}
	var message slackMessage
	if err := json.Unmarshal(built.Body, &message); err != nil {
		t.Fatal(err)
	}
	if section := message.Attachments[0].Blocks[1].Text.Text; section != "&lt;!channel&gt; &amp; &lt;https://evil.example|click&gt;" {
		t.Fatalf("Slack section = %q", section)
	}
}

func TestPreviewsCutSecretsShort(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		destination config.AlertDestination
		want        string
	}{
		{config.AlertDestination{Format: config.AlertFormatDiscord, URL: "https://discord.com/api/webhooks/123/secret-token"}, "https://discord.com/api/webhooks/123/••••oken"},
		{config.AlertDestination{Format: config.AlertFormatSlack, URL: "https://hooks.slack.com/services/T0/B0/secret-token"}, "https://hooks.slack.com/services/T0/B0/••••oken"},
		{config.AlertDestination{Format: config.AlertFormatText, URL: "https://ntfy.sh/sable-alerts?auth=abc"}, "https://ntfy.sh/••••erts"},
		{config.AlertDestination{URL: "https://hooks.example.com"}, "https://hooks.example.com"},
		{config.AlertDestination{}, ""},
	} {
		if got := MaskURL(test.destination); got != test.want {
			t.Errorf("MaskURL(%q) = %q, want %q", test.destination.URL, got, test.want)
		}
	}
	built, err := Build(config.AlertDestination{Format: config.AlertFormatPushover, PushoverToken: "azGDORePK8gMaC0QOYAM", PushoverUser: "uQiRzpo4DXghDmr9QzzfQu27"},
		problem("down", config.AlertGroupCluster), Links{Base: "https://sable.example"})
	if err != nil {
		t.Fatal(err)
	}
	preview := PreviewBody(built)
	for _, want := range []string{"token=••••OYAM", "user=••••Qu27", "title=Backup failed: ns1", "url_title=Open Sable", "priority=1"} {
		if !strings.Contains(preview, want) {
			t.Errorf("the Pushover preview lacks %q:\n%s", want, preview)
		}
	}
	json, err := Build(config.AlertDestination{Headers: []config.AlertHeader{{Name: "Authorization", Value: "Bearer secret-token"}}}, Sample(testNow), Links{})
	if err != nil {
		t.Fatal(err)
	}
	if headers := PreviewHeaders(json); len(headers) != 1 || headers[0].Value != "••••oken" {
		t.Fatalf("preview headers = %+v", headers)
	}
	if body := PreviewBody(json); !strings.Contains(body, "\n  \"source\": \"sable\"") {
		t.Fatalf("the JSON preview is not indented:\n%s", body)
	}
}
