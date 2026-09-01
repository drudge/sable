// Package durationfmt parses and formats elapsed durations, extending Go's
// standard syntax with fixed-length years, months, weeks, and days.
package durationfmt

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

const (
	Day   = 24 * time.Hour
	Week  = 7 * Day
	Month = 30 * Day
	Year  = 365 * Day
)

type unit struct {
	suffix string
	value  time.Duration
}

// Longer suffixes must precede their prefixes so "mo" and "ms" are not
// consumed as minutes followed by an unexpected character.
var parseUnits = []unit{
	{suffix: "mo", value: Month},
	{suffix: "ms", value: time.Millisecond},
	{suffix: "ns", value: time.Nanosecond},
	{suffix: "us", value: time.Microsecond},
	{suffix: "µs", value: time.Microsecond},
	{suffix: "μs", value: time.Microsecond},
	{suffix: "y", value: Year},
	{suffix: "w", value: Week},
	{suffix: "d", value: Day},
	{suffix: "h", value: time.Hour},
	{suffix: "m", value: time.Minute},
	{suffix: "s", value: time.Second},
}

var formatUnits = []unit{
	{suffix: "y", value: Year},
	{suffix: "mo", value: Month},
	{suffix: "w", value: Week},
	{suffix: "d", value: Day},
}

// Parse accepts Go duration syntax plus fixed-length y, mo, w, and d units.
// A month is 30 days and a year is 365 days; m continues to mean minutes.
func Parse(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if parsed, err := time.ParseDuration(value); err == nil {
		return parsed, nil
	}
	return parseExtended(value)
}

func parseExtended(value string) (time.Duration, error) {
	original := value
	negative := false
	if strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		negative = value[0] == '-'
		value = value[1:]
	}
	if value == "" {
		return 0, invalid(original)
	}

	total := new(big.Int)
	for value != "" {
		number, rest, ok := takeNumber(value)
		if !ok {
			return 0, invalid(original)
		}
		matched, rest, ok := takeUnit(rest)
		if !ok {
			return 0, invalid(original)
		}
		component, ok := componentNanoseconds(number, matched.value)
		if !ok {
			return 0, invalid(original)
		}
		total.Add(total, component)
		value = rest
	}
	if negative {
		total.Neg(total)
	}
	if !total.IsInt64() {
		return 0, fmt.Errorf("duration %q exceeds the supported range", original)
	}
	return time.Duration(total.Int64()), nil
}

func takeNumber(value string) (string, string, bool) {
	index := 0
	digits := 0
	for index < len(value) && value[index] >= '0' && value[index] <= '9' {
		index++
		digits++
	}
	if index < len(value) && value[index] == '.' {
		index++
		for index < len(value) && value[index] >= '0' && value[index] <= '9' {
			index++
			digits++
		}
	}
	if digits == 0 {
		return "", value, false
	}
	return value[:index], value[index:], true
}

func takeUnit(value string) (unit, string, bool) {
	for _, candidate := range parseUnits {
		if strings.HasPrefix(value, candidate.suffix) {
			return candidate, value[len(candidate.suffix):], true
		}
	}
	return unit{}, value, false
}

func componentNanoseconds(number string, unitValue time.Duration) (*big.Int, bool) {
	if strings.HasPrefix(number, ".") {
		number = "0" + number
	}
	if strings.HasSuffix(number, ".") {
		number += "0"
	}
	quantity, ok := new(big.Rat).SetString(number)
	if !ok {
		return nil, false
	}
	quantity.Mul(quantity, new(big.Rat).SetInt64(int64(unitValue)))
	return new(big.Int).Quo(quantity.Num(), quantity.Denom()), true
}

func invalid(value string) error {
	return fmt.Errorf("invalid duration %q", value)
}

// Format renders large exact durations with fixed calendar-like units and
// delegates the sub-day remainder to time.Duration.String.
func Format(value time.Duration) string {
	if value == 0 {
		return value.String()
	}

	negative := value < 0
	magnitude := uint64(value)
	if negative {
		magnitude = uint64(-(value + 1)) + 1
	}

	var formatted strings.Builder
	if negative {
		formatted.WriteByte('-')
	}
	for _, candidate := range formatUnits {
		unitValue := uint64(candidate.value)
		if magnitude < unitValue {
			continue
		}
		formatted.WriteString(strconv.FormatUint(magnitude/unitValue, 10))
		formatted.WriteString(candidate.suffix)
		magnitude %= unitValue
	}
	if magnitude > 0 {
		formatted.WriteString(time.Duration(magnitude).String())
	}
	return formatted.String()
}
