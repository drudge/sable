package alerts

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/drudge/sable/internal/config"
)

// MaskSecret keeps only enough of a secret to tell which one it is.
func MaskSecret(secret string) string {
	if len(secret) <= 4 {
		return strings.Repeat("•", len(secret))
	}
	return "••••" + secret[len(secret)-4:]
}

// MaskURL cuts short the part of a destination's URL that works as a password:
// the token that ends a Slack or Discord webhook URL, and the topic of an ntfy
// URL, which is all it takes to read or post to it. Other URLs keep their
// address and lose their path.
func MaskURL(destination config.AlertDestination) string {
	address := destination.URL
	if address == "" {
		return ""
	}
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" {
		return MaskSecret(address)
	}
	path := strings.TrimRight(parsed.Path, "/")
	cut := strings.LastIndex(path, "/")
	if cut < 0 || path[cut+1:] == "" {
		return parsed.Scheme + "://" + parsed.Host + path
	}
	return parsed.Scheme + "://" + parsed.Host + path[:cut+1] + MaskSecret(path[cut+1:])
}

// PreviewBody lays a request body out to be read, with secrets cut short:
// JSON indented, and a form one field per line.
func PreviewBody(built Request) string {
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
		for _, name := range []string{"token", "user", "title", "message", "url", "url_title", "priority"} {
			if !form.Has(name) {
				continue
			}
			value := form.Get(name)
			if name == "token" || name == "user" {
				value = MaskSecret(value)
			}
			lines = append(lines, name+"="+value)
		}
		return strings.Join(lines, "\n")
	}
	return string(built.Body)
}

// PreviewHeaders lists a request's headers with any credential cut short.
func PreviewHeaders(built Request) []Header {
	headers := make([]Header, 0, len(built.Headers))
	for _, header := range built.Headers {
		value := header.Value
		if strings.EqualFold(header.Name, "Authorization") {
			value = MaskSecret(value)
		}
		headers = append(headers, Header{header.Name, value})
	}
	return headers
}
