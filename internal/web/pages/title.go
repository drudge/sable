package pages

import "strings"

// titleSeparator sits between document title segments. The browser tab reads
// most specific first, so a selected zone or tab wins the truncation contest
// when the tab strip is narrow.
const titleSeparator = " · "

// tabOption describes one entry in a page's tab strip. The same table drives
// the rendered strip and the document title, so a tab can never be labelled one
// way on screen and another way in the browser tab.
type tabOption struct {
	Value string
	Label string
	Icon  string
}

// tabLabel returns the label for value. An unknown or empty value falls back to
// the first tab because that is the panel a page shows when the query parameter
// is missing or bogus.
func tabLabel(options []tabOption, value string) string {
	for _, option := range options {
		if option.Value == value {
			return option.Label
		}
	}
	if len(options) == 0 {
		return ""
	}
	return options[0].Label
}

// documentTitle joins title segments most specific first and drops the empty
// ones, so a page without a selection keeps its plain section title. The layout
// appends the product name.
func documentTitle(segments ...string) string {
	kept := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		kept = append(kept, segment)
	}
	return strings.Join(kept, titleSeparator)
}
