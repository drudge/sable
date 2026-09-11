package pages

import (
	"bytes"
	"html"

	"github.com/yuin/goldmark"
)

// releaseNotesHTML uses Goldmark's safe defaults: raw HTML and dangerous URLs
// from the GitHub release body are never emitted into the console.
func releaseNotesHTML(notes string) string {
	var rendered bytes.Buffer
	if err := goldmark.Convert([]byte(notes), &rendered); err != nil {
		return "<p>" + html.EscapeString(notes) + "</p>"
	}
	return rendered.String()
}
