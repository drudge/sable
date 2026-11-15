// Package dhcpimport reads DHCP reservations exported from other servers:
// dnsmasq dhcp-host lines (Pi-hole, OpenWrt), AdGuard Home's leases.json or
// /control/dhcp/status, a Technitium scope from /api/dhcp/scopes/get, and a
// UniFi controller's rest/user list. It only parses; the console's DHCP
// service decides what fits a scope.
package dhcpimport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"unicode/utf16"
)

// The formats Parse recognizes.
const (
	FormatDnsmasq    = "dnsmasq"
	FormatAdGuard    = "adguard"
	FormatTechnitium = "technitium"
	FormatUniFi      = "unifi"
)

// Entry is one reservation read from an export. Name is a single DNS label,
// lowercased; a fully qualified name keeps its first label.
type Entry struct {
	// Line is the line of a dnsmasq file, or the 1-based position in a JSON
	// list, so a problem can point at its source.
	Line    int    `json:"line"`
	MAC     string `json:"mac"`
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// Problem is a part of the export that wasn't read as a reservation.
type Problem struct {
	Line int    `json:"line"`
	Text string `json:"text"`
}

// Result is what Parse read.
type Result struct {
	Format   string
	Entries  []Entry
	Problems []Problem
}

// Parse reads data as whichever supported export it is. It fails when data
// is none of them or holds no reservation at all.
func Parse(data []byte) (Result, error) {
	data = decoded(data)
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return Result{}, errors.New("the file is empty")
	}
	var (
		result Result
		err    error
	)
	if trimmed[0] == '{' || trimmed[0] == '[' {
		result, err = parseJSON(trimmed)
	} else {
		result = parseDnsmasq(string(data))
	}
	if err != nil {
		return Result{}, err
	}
	if len(result.Entries) == 0 && len(result.Problems) == 0 {
		return Result{}, fmt.Errorf("found no reservations in the %s export", result.Format)
	}
	return result, nil
}

// Text returns an export as UTF-8 text without a byte order mark, however it
// was saved, for a caller that has to carry it as text before importing it.
func Text(data []byte) string {
	return string(decoded(data))
}

// decoded returns data as UTF-8 without a byte order mark. A file saved on
// Windows often starts with one, and Windows PowerShell 5's ">" and Out-File
// write UTF-16, which the mark gives away.
func decoded(data []byte) []byte {
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}):
		return data[3:]
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		order = binary.LittleEndian
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		order = binary.BigEndian
	default:
		return data
	}
	units := make([]uint16, 0, len(data)/2)
	for index := 2; index+1 < len(data); index += 2 {
		units = append(units, order.Uint16(data[index:]))
	}
	return []byte(string(utf16.Decode(units)))
}

// add appends the entry when its hardware and IPv4 addresses read, and a
// problem naming what's missing when they don't.
func (result *Result) add(line int, mac, address, name, comment string) {
	hardware, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hardware) != 6 {
		result.problem(line, "%q isn't a 6-byte hardware address", mac)
		return
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil || !ip.Is4() {
		result.problem(line, "%q isn't an IPv4 address", address)
		return
	}
	result.Entries = append(result.Entries, Entry{
		Line:    line,
		MAC:     hardware.String(),
		Address: ip.String(),
		Name:    hostLabel(name),
		Comment: strings.TrimSpace(comment),
	})
}

func (result *Result) problem(line int, format string, args ...any) {
	result.Problems = append(result.Problems, Problem{Line: line, Text: fmt.Sprintf(format, args...)})
}

// hostLabel keeps the first label of name, lowercased. Whether it's a valid
// label is the scope validation's call, so the importer can say why.
func hostLabel(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	label, _, _ := strings.Cut(name, ".")
	return label
}
