package dhcp

import (
	"strings"
	"unicode"
)

// cleanText turns a client-supplied option (12 host name, 60 vendor class)
// into text the store, DNS, and the console can hold: valid UTF-8 with no
// control characters. Clients pad with NUL ("printer\x00"), and PostgreSQL
// rejects NUL and invalid UTF-8 in TEXT (SQLSTATE 22021).
func cleanText(data []byte) string {
	return strings.Map(func(char rune) rune {
		if unicode.IsControl(char) || char == unicode.ReplacementChar {
			return -1
		}
		return char
	}, strings.ToValidUTF8(string(data), ""))
}
