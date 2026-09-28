package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/version"
)

// sendTimeout bounds one request to a destination, so one that hangs cannot
// hold up the rest.
const sendTimeout = 10 * time.Second

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

// Post sends one request to a destination that takes HTTP, which is every
// format but browsers. When the answer carries a receipt, from ntfy or
// Pushover, it returns the ID the service gave the message.
func Post(ctx context.Context, client *http.Client, destination config.AlertDestination, built Request) (string, error) {
	if client == nil {
		client = http.DefaultClient
	}
	address := destination.URL
	if address == "" && destination.Format == config.AlertFormatPushover {
		address = config.PushoverMessagesURL
	}
	requestContext, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, address, bytes.NewReader(built.Body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", built.ContentType)
	request.Header.Set("User-Agent", "Sable/"+version.Current().Release)
	for _, header := range built.Headers {
		request.Header.Set(header.Name, header.Value)
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("post alert: %w", err)
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	switch destination.Format {
	case config.AlertFormatSlack:
		// Slack answers "ok", or says what was wrong in plain words.
		said := strings.TrimSpace(string(answer))
		if response.StatusCode >= 400 && said != "" && !strings.HasPrefix(said, "<") {
			return "", fmt.Errorf("Slack did not post it: %s", truncate(said, 200))
		}
		if response.StatusCode < 200 || response.StatusCode > 299 || said != "ok" {
			return "", fmt.Errorf("the webhook answered %s, but not like Slack; check the URL", response.Status)
		}
		return "", nil
	case config.AlertFormatDiscord:
		// Discord answers 204 with nothing, or the message it posted when asked
		// to wait, and explains a refusal in JSON.
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
	case config.AlertFormatPushover:
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
		return "", fmt.Errorf("post alert: webhook answered %s", response.Status)
	}
	if !destination.NtfyReceipt {
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
