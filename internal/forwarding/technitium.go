package forwarding

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// TechnitiumForwarderType is Technitium's private-use conditional forwarding RR.
const TechnitiumForwarderType = "TYPE65281"

// ParseTechnitiumRecord decodes RFC 3597 presentation data into Sable's routing
// model. Wire layout:
// https://github.com/TechnitiumSoftware/TechnitiumLibrary/blob/master/TechnitiumLibrary.Net/Dns/ResourceRecords/DnsForwarderRecordData.cs
// Unsupported options are rejected rather than silently changing routing behavior.
func ParseTechnitiumRecord(value string) (Record, bool, error) {
	fields := strings.Fields(value)
	if len(fields) != 3 || fields[0] != `\#` {
		return Record{}, false, errors.New("malformed Technitium FWD data")
	}
	size, err := strconv.Atoi(fields[1])
	data, decodeErr := hex.DecodeString(fields[2])
	if err != nil || decodeErr != nil || len(data) != size || len(data) < 2 {
		return Record{}, false, errors.New("malformed Technitium FWD data")
	}
	protocols := map[byte]string{0: "udp", 1: "tcp", 2: "tls", 5: "quic"}
	protocol, supported := protocols[data[0]]
	if !supported {
		return Record{}, false, fmt.Errorf("Technitium FWD transport %d is not supported", data[0])
	}
	end := 2 + int(data[1])
	if end > len(data) {
		return Record{}, false, errors.New("truncated Technitium FWD address")
	}
	address := string(data[2:end])
	if strings.ContainsAny(address, "()/\\ \t\r\n") {
		return Record{}, false, errors.New("Technitium FWD address syntax is not supported; use a plain IP address or hostname with optional port")
	}
	validation := false
	priority := byte(0)
	options := data[end:]
	switch len(options) {
	case 0:
	case 2, 3:
		if options[0] > 1 {
			return Record{}, false, errors.New("invalid Technitium FWD DNSSEC validation flag")
		}
		validation = options[0] == 1
		if options[1] != 0 && options[1] != 254 {
			return Record{}, false, errors.New("Technitium FWD proxy settings are not supported")
		}
		if len(options) == 3 {
			priority = options[2]
		}
	default:
		return Record{}, false, errors.New("unsupported or truncated Technitium FWD options (including proxy settings)")
	}
	record, err := NewRecord(protocol, strconv.Itoa(int(priority)), address)
	return record, validation, err
}
