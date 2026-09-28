package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/serverlog"
)

const (
	mcpDefaultLogLimit  = 50
	mcpMaximumLogLimit  = 200
	mcpDefaultLogWindow = time.Hour
)

var mcpServerLogTool = mcpTool{
	Name:  "search_server_logs",
	Title: "Search Sable's runtime log",
	Description: "Search Sable's own runtime log, the Logs page's Runtime tab, newest first. Use it to find out " +
		"why something failed, for example the error behind a SERVFAIL. level is the least severe level to " +
		"include, so warn also returns errors. Anything that looks like a credential is blanked.",
	InputSchema: mcpObjectSchema(map[string]any{
		"level": map[string]any{
			"type": "string", "enum": []string{"debug", "info", "warn", "error"},
			"description": "Least severe level to include. Defaults to warn.",
		},
		"search": mcpString("Optional text to find in the message or its details, ignoring case."),
		"since":  mcpString("Start of the window: a duration back from now, such as 30m or 6h, or an RFC 3339 time. Defaults to 1h."),
		"until":  mcpString("Optional end of the window as an RFC 3339 time. Defaults to now."),
		"limit":  mcpInteger("Most entries to return, up to 200. Defaults to 50.", 1),
	}, nil),
	Annotations: mcpToolAnnotations{Title: "Search Sable's runtime log", ReadOnlyHint: true, IdempotentHint: true},
	call:        (*Server).mcpSearchServerLogs,
	// Log lines name devices and what they looked up, so like the query log
	// this is off until an operator adds it.
	section: "lookups",
	grant:   "logs.read",
}

type mcpLogEntry struct {
	At         time.Time         `json:"at"`
	Level      string            `json:"level"`
	Message    string            `json:"message"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

func (server *Server) mcpSearchServerLogs(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Level  string `json:"level"`
		Search string `json:"search"`
		Since  string `json:"since"`
		Until  string `json:"until"`
		Limit  int    `json:"limit"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	if !server.mcpHasPermission(request, auth.PermissionLogsRead) {
		return nil, errors.New("this token needs logs.read to search the runtime log")
	}
	level := strings.ToLower(strings.TrimSpace(input.Level))
	if level == "" {
		level = "warn"
	}
	if _, known := serverlog.LevelOf(level); !known {
		return nil, fmt.Errorf("level must be debug, info, warn, or error, not %q", input.Level)
	}
	now := time.Now()
	since, err := mcpLogSince(input.Since, now)
	if err != nil {
		return nil, err
	}
	until := now
	if value := strings.TrimSpace(input.Until); value != "" {
		if until, err = time.Parse(time.RFC3339, value); err != nil {
			return nil, fmt.Errorf("until must be an RFC 3339 time, such as 2026-09-27T21:00:00Z: %w", err)
		}
	}
	if !since.Before(until) {
		return nil, errors.New("since must be before until")
	}
	limit := input.Limit
	if limit <= 0 {
		limit = mcpDefaultLogLimit
	}
	limit = min(limit, mcpMaximumLogLimit)
	search := strings.TrimSpace(input.Search)

	result := map[string]any{"node": server.mcpNodeName(), "since": since.UTC(), "until": until.UTC()}
	var entries []serverlog.Entry
	if pager, persisted := server.runtimeLogHistory(); persisted {
		page, err := pager.ServerLogEntries(request.Context(), serverlog.Query{
			Page: 1, PageSize: limit, Search: search, Level: level, AtLeast: true, Since: since, Until: until,
		})
		if err != nil {
			server.logger.Error("read server log history", "error", err, "via", "mcp")
			return nil, errors.New("the runtime log history is unavailable right now")
		}
		result["source"], result["total"], entries = "persisted", page.TotalEntries, page.Entries
	} else {
		if server.runtimeLogs == nil {
			return nil, errors.New("runtime log capture is unavailable on this server")
		}
		// The buffer is small, so reading all of it to count the matches is cheap.
		matching := server.runtimeLogs.Entries(serverlog.Filter{Search: search, Level: level, AtLeast: true, Since: since, Until: until})
		result["source"], result["total"], entries = "live", len(matching), matching[:min(limit, len(matching))]
		result["note"] = "Runtime log history is off, so only recent entries since Sable started are searched. " +
			"Turn on Persist Server Logs in Sable under Settings, Logging, to keep more."
	}
	redact := server.mcpLogRedactor(request.Context())
	views := make([]mcpLogEntry, 0, len(entries))
	for _, entry := range entries {
		view := mcpLogEntry{At: entry.OccurredAt.UTC(), Level: mcpLevelName(entry), Message: redact(entry.Message)}
		if len(entry.Attributes) > 0 {
			view.Attributes = make(map[string]string, len(entry.Attributes))
			for key, value := range entry.Attributes {
				if providerFieldIsSecret(key) {
					value = "[redacted]"
				}
				view.Attributes[key] = redact(value)
			}
		}
		views = append(views, view)
	}
	result["entries"] = views
	return result, nil
}

// mcpLogSince reads the start of the window: a duration back from now or an
// RFC 3339 time.
func mcpLogSince(value string, now time.Time) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return now.Add(-mcpDefaultLogWindow), nil
	}
	if duration, err := time.ParseDuration(value); err == nil {
		if duration <= 0 {
			return time.Time{}, errors.New("since must be a positive duration, such as 1h")
		}
		return now.Add(-duration), nil
	}
	since, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("since must be a duration such as 30m or 6h, or an RFC 3339 time, not %q", value)
	}
	return since, nil
}

func mcpLevelName(entry serverlog.Entry) string {
	for _, name := range []string{"ERROR", "WARN", "INFO"} {
		if level, _ := serverlog.LevelOf(name); entry.Level >= level {
			return name
		}
	}
	return "DEBUG"
}

var urlUserinfoPattern = regexp.MustCompile(`(://)[^/\s@:]+:[^/\s@]+@`)

// mcpLogRedactor blanks what could be a credential in a log line before it
// leaves for the assistant's AI provider. Log lines are written for the
// operator, and a provider error or a failed request can carry a secret, so
// the line is checked three ways: fields that are named like a credential,
// passwords in URLs, and every credential Sable holds for Dynamic DNS,
// certificates, UniFi, and alert destinations, wherever it appears.
func (server *Server) mcpLogRedactor(ctx context.Context) func(string) string {
	secrets := server.mcpKnownSecrets(ctx)
	return func(text string) string {
		text = urlUserinfoPattern.ReplaceAllString(text, "${1}[redacted]@")
		return redactKnownSecrets(redactProviderSecrets(text), secrets...)
	}
}

func (server *Server) mcpKnownSecrets(ctx context.Context) []string {
	configuration := server.config.Current().Config
	var secrets []string
	if server.dynamicDNS != nil {
		providers := configuration.DynamicDNS.ProviderNames()
		if provider := configuration.EncryptedDNS.ACME.DNSProvider; provider != "" {
			providers = append(providers, provider)
		}
		for _, provider := range providers {
			if credentials, found := server.dynamicDNS.StoredCredentials(ctx, provider); found {
				secrets = append(secrets, dynamicDNSSecretValues(credentials)...)
			}
		}
	}
	if server.unifi != nil {
		if credentials, found := server.unifi.StoredCredentials(ctx); found {
			secrets = append(secrets, credentials.APIKey, credentials.Password)
		}
	}
	if server.alerts != nil {
		for _, destination := range server.alerts.Destinations(ctx) {
			secrets = append(secrets, destination.URL, destination.PushoverToken, destination.PushoverUser)
			// The last part of a webhook's path is its token, which a log line
			// may hold on its own or in an escaped URL.
			// Short parts, such as a path that ends in webhook, are words a log
			// line uses for other things.
			if parsed, err := url.Parse(destination.URL); err == nil {
				path := strings.TrimRight(parsed.Path, "/")
				if token := path[strings.LastIndex(path, "/")+1:]; len(token) >= 12 {
					secrets = append(secrets, token)
				}
			}
			for _, header := range destination.Headers {
				secrets = append(secrets, header.Value)
			}
		}
	}
	return secrets
}
