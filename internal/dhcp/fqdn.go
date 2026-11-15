package dhcp

import "strings"

// Client FQDN option flag bits (RFC 4702 §2.1).
const (
	fqdnS uint8 = 1 << iota // the server updates the A record
	fqdnO                   // the server overrode the client's S
	fqdnE                   // the name is in wire format (RFC 1035 §3.1)
	fqdnN                   // the server updates nothing
)

// Labeler turns a client's name, or a reservation's when reserved is true,
// into the one DNS label it registers. Empty means it registers nothing.
type Labeler func(name string, reserved bool) string

// clientFQDN is the option 81 a client sent (RFC 4702 §2).
type clientFQDN struct {
	flags uint8
	name  []byte // the Domain Name field exactly as sent (§2.3)
}

func parseClientFQDN(request Packet) (clientFQDN, bool) {
	data, found := request.Option(optionClientFQDN)
	if !found || len(data) < 3 {
		return clientFQDN{}, false
	}
	// §2.1: ignore the MBZ bits; §2.2: ignore RCODE1 and RCODE2.
	return clientFQDN{flags: data[0] & (fqdnS | fqdnO | fqdnE | fqdnN), name: data[3:]}, true
}

// label is the name's first label, in wire format when E is set and in the
// deprecated ASCII encoding otherwise (§2.3.1). A compression pointer or a
// length past the data is no label.
func (fqdn clientFQDN) label() string {
	if fqdn.flags&fqdnE == 0 {
		text, _, _ := strings.Cut(string(fqdn.name), ".")
		return cleanText([]byte(text))
	}
	if len(fqdn.name) == 0 {
		return ""
	}
	size := int(fqdn.name[0])
	if size == 0 || size > 63 || 1+size > len(fqdn.name) {
		return ""
	}
	return cleanText(fqdn.name[1 : 1+size])
}

// reply answers the option (§4). With a name the server registers it (S=1)
// and returns the full FQDN; without one it registers nothing (N=1) and
// echoes the client's name. O marks a reply whose S differs from the
// client's. The encoding follows the client's E bit, and both RCODEs are
// 255 (§2.2).
func (fqdn clientFQDN) reply(name string) Option {
	flags := fqdn.flags & fqdnE
	if name != "" {
		flags |= fqdnS
	} else {
		flags |= fqdnN
	}
	if flags&fqdnS != fqdn.flags&fqdnS {
		flags |= fqdnO
	}
	data := []byte{flags, 255, 255}
	switch {
	case name == "":
		data = append(data, fqdn.name...)
	case flags&fqdnE != 0:
		for label := range strings.SplitSeq(name, ".") {
			data = append(append(data, byte(len(label))), label...)
		}
		data = append(data, 0)
	default:
		data = append(data, name...)
	}
	return Option{Code: optionClientFQDN, Data: data}
}

// clientName is the name a client gave itself: the FQDN option's first
// label, which wins over option 12 when both are sent (§4), or option 12.
func (exchange *exchange) clientName() string {
	if fqdn, found := parseClientFQDN(exchange.request); found {
		if label := fqdn.label(); label != "" {
			return label
		}
	}
	if name, found := exchange.request.Option(optionHostname); found {
		return cleanText(name)
	}
	return ""
}

// registeredName is the FQDN the client's lease publishes, by the namer's
// rule: a named reservation's label, else the client's own name. Empty when
// the scope registers no names or the label is refused.
func (exchange *exchange) registeredName() string {
	compiled, label := exchange.scope, exchange.engine.labeler
	if compiled.domain == "" || label == nil {
		return ""
	}
	host := ""
	if name, found := compiled.reservedNames[exchange.request.CHAddr.String()]; found {
		host = label(name, true)
	}
	if host == "" {
		host = label(exchange.clientName(), false)
	}
	if host == "" {
		return ""
	}
	return host + "." + compiled.domain
}
