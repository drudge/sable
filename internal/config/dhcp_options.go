package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
)

// DHCPOptionType is how a raw option's values are written and encoded.
type DHCPOptionType int

// Option value types from RFC 2132 §2.
const (
	DHCPOptionUnknown DHCPOptionType = iota
	DHCPOptionIPv4List
	DHCPOptionIPv4
	DHCPOptionString
	DHCPOptionUint8
	DHCPOptionUint16
	DHCPOptionUint32
	DHCPOptionInt32
	DHCPOptionBool
)

// dhcpOwnedOptions are set by the engine or by a scope field, so a raw option
// can't set them: protocol mechanics (RFC 2132 §9), relay agent information
// (RFC 3046), client FQDN (RFC 4702), and the codes behind scope fields.
var dhcpOwnedOptions = map[int]string{
	0: "the protocol", 255: "the protocol", 52: "the protocol", 53: "the protocol",
	54: "the protocol", 55: "the protocol", 57: "the protocol", 50: "the protocol",
	61: "the protocol", 81: "the protocol", 82: "the protocol",
	1: "subnet", 3: "router", 6: "dns", 15: "domain", 42: "ntp", 51: "lease",
	58: "lease", 59: "lease", 66: "boot.server_name", 67: "boot.file",
	108: "ipv6_only_preferred", 119: "search", 121: "routes", 150: "boot.next_server",
}

// dhcpOptionTypes are the RFC 2132 options a raw option can set by value.
var dhcpOptionTypes = map[int]DHCPOptionType{
	2: DHCPOptionInt32, 4: DHCPOptionIPv4List, 5: DHCPOptionIPv4List, 7: DHCPOptionIPv4List,
	8: DHCPOptionIPv4List, 9: DHCPOptionIPv4List, 10: DHCPOptionIPv4List, 11: DHCPOptionIPv4List,
	13: DHCPOptionUint16, 14: DHCPOptionString, 16: DHCPOptionIPv4, 17: DHCPOptionString,
	18: DHCPOptionString, 19: DHCPOptionBool, 20: DHCPOptionBool, 22: DHCPOptionUint16,
	23: DHCPOptionUint8, 24: DHCPOptionUint32, 26: DHCPOptionUint16, 27: DHCPOptionBool,
	28: DHCPOptionIPv4, 29: DHCPOptionBool, 30: DHCPOptionBool, 31: DHCPOptionBool,
	32: DHCPOptionIPv4, 34: DHCPOptionBool, 35: DHCPOptionUint32, 36: DHCPOptionBool,
	37: DHCPOptionUint8, 38: DHCPOptionUint32, 39: DHCPOptionBool, 40: DHCPOptionString,
	41: DHCPOptionIPv4List, 44: DHCPOptionIPv4List, 45: DHCPOptionIPv4List, 46: DHCPOptionUint8,
	47: DHCPOptionString, 48: DHCPOptionIPv4List, 49: DHCPOptionIPv4List, 64: DHCPOptionString,
	65: DHCPOptionIPv4List, 68: DHCPOptionIPv4List, 69: DHCPOptionIPv4List, 70: DHCPOptionIPv4List,
	71: DHCPOptionIPv4List, 72: DHCPOptionIPv4List, 73: DHCPOptionIPv4List, 74: DHCPOptionIPv4List,
	75: DHCPOptionIPv4List, 76: DHCPOptionIPv4List,
}

// DHCPOptionTypeOf reports how option code's values are typed.
func DHCPOptionTypeOf(code int) DHCPOptionType { return dhcpOptionTypes[code] }

func validateDHCPOptions(field string, options []DHCPOption) []error {
	var problems []error
	codes := make(map[int]int, len(options))
	for index, option := range options {
		item := fmt.Sprintf("%s.options[%d]", field, index)
		if option.Code < 1 || option.Code > 254 {
			problems = append(problems, fmt.Errorf("%s.code must be between 1 and 254", item))
			continue
		}
		if owner, owned := dhcpOwnedOptions[option.Code]; owned {
			problems = append(problems, fmt.Errorf("%s.code %d is set by %s", item, option.Code, owner))
			continue
		}
		if first, seen := codes[option.Code]; seen {
			problems = append(problems, fmt.Errorf("%s.code duplicates options[%d]", item, first))
		}
		codes[option.Code] = index
		problems = append(problems, validateDHCPOptionData(item, option)...)
	}
	return problems
}

func validateDHCPOptionData(item string, option DHCPOption) []error {
	switch {
	case len(option.Value) > 0 && option.Hex != "":
		return []error{fmt.Errorf("%s needs value or hex, not both", item)}
	case option.Hex != "":
		data, err := hex.DecodeString(option.Hex)
		if err != nil {
			return []error{fmt.Errorf("%s.hex must be hexadecimal", item)}
		}
		if len(data) > math.MaxUint8 {
			return []error{fmt.Errorf("%s.hex must be at most 255 bytes", item)}
		}
		return nil
	case len(option.Value) == 0:
		return []error{fmt.Errorf("%s needs value or hex", item)}
	}
	kind := DHCPOptionTypeOf(option.Code)
	if kind == DHCPOptionUnknown {
		return []error{fmt.Errorf("%s code %d has no known type; use hex", item, option.Code)}
	}
	if kind != DHCPOptionIPv4List && len(option.Value) != 1 {
		return []error{fmt.Errorf("%s.value must hold one value for code %d", item, option.Code)}
	}
	var problems []error
	size := 0
	for index, value := range option.Value {
		width, err := dhcpOptionValueWidth(kind, value)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s.value[%d] %w", item, index, err))
		}
		size += width
	}
	if size > math.MaxUint8 {
		problems = append(problems, fmt.Errorf("%s.value encodes to more than 255 bytes", item))
	}
	return problems
}

// dhcpOptionValueWidth checks one value against its type and returns its
// encoded size.
func dhcpOptionValueWidth(kind DHCPOptionType, value string) (int, error) {
	var bits, width int
	signed := false
	switch kind {
	case DHCPOptionIPv4List, DHCPOptionIPv4:
		if address, err := netip.ParseAddr(value); err != nil || !address.Is4() {
			return 4, errors.New("must be an IPv4 address")
		}
		return 4, nil
	case DHCPOptionString:
		if value == "" {
			return 0, errors.New("must not be empty")
		}
		return len(value), nil
	case DHCPOptionBool:
		if _, err := strconv.ParseBool(value); err != nil {
			return 1, errors.New("must be true or false")
		}
		return 1, nil
	case DHCPOptionUint8:
		bits, width = 8, 1
	case DHCPOptionUint16:
		bits, width = 16, 2
	case DHCPOptionUint32:
		bits, width = 32, 4
	case DHCPOptionInt32:
		bits, width, signed = 32, 4, true
	}
	var err error
	if signed {
		_, err = strconv.ParseInt(value, 10, bits)
	} else {
		_, err = strconv.ParseUint(value, 10, bits)
	}
	if err != nil {
		return width, fmt.Errorf("must be a %d-bit integer", bits)
	}
	return width, nil
}
