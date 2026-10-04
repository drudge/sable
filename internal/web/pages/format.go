package pages

import (
	"fmt"
	"strconv"
)

// The console's number, size, and word formatters. Times live in time.go.
// app.js keeps the matching formatFileSize for sizes it shows before upload.

type integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

// formatNumber writes a whole number with thousands separators: 1,234,567.
func formatNumber[T integer](value T) string {
	text := fmt.Sprint(value)
	sign := ""
	if text[0] == '-' {
		sign, text = "-", text[1:]
	}
	for index := len(text) - 3; index > 0; index -= 3 {
		text = text[:index] + "," + text[index:]
	}
	return sign + text
}

// compactNumber shortens a count for a tight space: 1.2K, 3.4M.
func compactNumber(value uint64) string {
	switch {
	case value >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(value)/1_000_000)
	case value >= 1_000:
		return fmt.Sprintf("%.1fK", float64(value)/1_000)
	default:
		return fmt.Sprint(value)
	}
}

// percent writes value's share of total to two decimals.
func percent(value, total uint64) string {
	if total == 0 {
		return "0.00%"
	}
	return fmt.Sprintf("%.2f%%", float64(value)*100/float64(total))
}

// plural picks the word for count: singular for exactly one, plural
// otherwise.
func plural(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

// countLabel writes a count and its word: "1 lookup", "1,204 lookups".
func countLabel(count uint64, singular, plural string) string {
	if count == 1 {
		return "1 " + singular
	}
	return formatNumber(count) + " " + plural
}

// FormatByteSize writes a size in binary units, as the backup list shows
// archives: "512 bytes", "4.0 KiB", "1.5 MiB", "2.1 GiB".
func FormatByteSize(size int64) string {
	switch {
	case size >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(size)/(1<<30))
	case size >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(size)/(1<<20))
	case size >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(size)/(1<<10))
	case size == 1:
		return "1 byte"
	default:
		return strconv.FormatInt(size, 10) + " bytes"
	}
}
