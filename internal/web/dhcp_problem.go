package web

import (
	"net/http"
	"regexp"
	"strings"
)

// dhcpProblemPath matches a place in the [dhcp] settings, such as
// dhcp.scopes[0].router or ranges[1], as the validator names it.
var dhcpProblemPath = regexp.MustCompile(`dhcp\.scopes\[\d+\](?:\.(reservations|ranges)\[\d+\])?(?:\.([a-z_]+)(?:\[\d+\])?)?|dhcp\.enabled|\b(scopes|ranges|reservations)\[\d+\]|^(mac|address)\b`)

// dhcpFieldLabels name the settings the way the console's dialogs label them.
var dhcpFieldLabels = map[string]string{
	"id": "ID", "dns": "DNS servers", "lease": "lease time", "mac": "MAC address", "ntp": "time servers",
}

// dhcpProblemText rewrites a refusal for the console, where the settings'
// paths mean nothing: "dhcp.scopes[0].router is inside ranges[0]" reads
// "The router is inside a range". A path that leads a line is the thing the
// operator is editing; one later in the line is another of its kind.
func dhcpProblemText(message string) string {
	lines := strings.Split(message, "\n")
	for index, line := range lines {
		var text strings.Builder
		last := 0
		for _, match := range dhcpProblemPath.FindAllStringSubmatchIndex(line, -1) {
			parts := make([]string, len(match)/2)
			for part := range parts {
				if match[2*part] >= 0 {
					parts[part] = line[match[2*part]:match[2*part+1]]
				}
			}
			text.WriteString(line[last:match[0]])
			text.WriteString(dhcpProblemPlace(parts, match[0] == 0))
			last = match[1]
		}
		text.WriteString(line[last:])
		lines[index] = sentence(text.String())
	}
	return strings.Join(lines, "\n")
}

// dhcpProblemPlace names one matched path: parts are the whole match and its
// groups, and subject says it leads the line.
func dhcpProblemPlace(parts []string, subject bool) string {
	path, child, field, other, bare := parts[0], parts[1], parts[2], parts[3], parts[4]
	switch {
	case path == "dhcp.enabled":
		return "DHCP"
	case bare != "":
		return "the " + dhcpFieldLabel(bare)
	case other == "ranges":
		return "a range"
	case other != "":
		return "another " + strings.TrimSuffix(other, "s")
	case !subject && child == "":
		return "another scope"
	case !subject:
		return "another " + strings.TrimSuffix(child, "s")
	}
	owner := "the scope"
	if child != "" {
		owner = "the " + strings.TrimSuffix(child, "s")
	}
	switch {
	case field == "":
		return owner
	case child == "":
		return "the " + dhcpFieldLabel(field)
	}
	return owner + "'s " + dhcpFieldLabel(field)
}

func dhcpFieldLabel(field string) string {
	if label, ok := dhcpFieldLabels[field]; ok {
		return label
	}
	return strings.ReplaceAll(field, "_", " ")
}

// renderDHCPProblem shows a refusal in a DHCP form's notice, in the words of
// the form rather than of the settings file.
func (server *Server) renderDHCPProblem(writer http.ResponseWriter, request *http.Request, notice string, err error) {
	server.renderFormProblem(writer, request, notice, refuse(serviceStatus(err), "%s", dhcpProblemText(err.Error())))
}
