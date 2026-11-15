package web

import (
	"errors"
	"net/http"
	"strings"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/web/pages"
)

// saveDHCPScope adds a scope, or saves the settings the scope dialog edits.
// Settings the dialog doesn't show, like options and reservations, stay as
// they are.
func (server *Server) saveDHCPScope(writer http.ResponseWriter, request *http.Request) {
	id, add := strings.TrimSpace(request.FormValue("id")), request.FormValue("new") != ""
	notice := "#" + pages.DHCPScopeNoticeID(id, request.FormValue("suggest"), add)
	server.dhcpMutation(writer, request, notice, func(service dhcpService, who actor) (string, error) {
		scope, err := dhcpScopeFromForm(service, who, id, add, request)
		if err != nil {
			return "", err
		}
		saved, err := service.SetScope(request.Context(), who, id, scope)
		if err != nil {
			return "", err
		}
		return "Saved scope " + dhcpScopeLabel(saved), nil
	})
}

func (server *Server) deleteDHCPScope(writer http.ResponseWriter, request *http.Request) {
	server.dhcpMutation(writer, request, "#dhcp-notice", func(service dhcpService, who actor) (string, error) {
		id := strings.TrimSpace(request.FormValue("id"))
		if err := service.RemoveScope(request.Context(), who, id); err != nil {
			return "", err
		}
		return "Removed scope " + id, nil
	})
}

// setDHCPEnabled turns the server on or off. When Turn On's probe finds
// another server, the page says which and offers Turn On Anyway.
func (server *Server) setDHCPEnabled(writer http.ResponseWriter, request *http.Request) {
	enabled, force := request.FormValue("enabled") == "true", request.FormValue("force") == "true"
	err := server.dhcpService().SetEnabled(request.Context(), requestActor(request, ""), enabled, force)
	var probed *dhcpProbeRefusal
	switch {
	case errors.As(err, &probed):
		view := server.dhcpPageView(request)
		view.Error, view.ProbeRefused = probed.Error(), true
		server.render(writer, request, pages.DHCPContent(view))
	case err != nil:
		server.renderFormProblem(writer, request, "#dhcp-notice", err)
	default:
		server.renderDHCP(writer, request, ifThenString(enabled, "Turned DHCP on", "Turned DHCP off"))
	}
}

// dhcpScopeFromForm starts from the saved scope, so a field the dialog
// doesn't show keeps its value, and an add can't replace a scope by reusing
// its ID.
func dhcpScopeFromForm(service dhcpService, who actor, id string, add bool, request *http.Request) (config.DHCPScope, error) {
	scope, err := service.Scope(who, id)
	switch {
	case add && err == nil:
		return config.DHCPScope{}, refuse(http.StatusUnprocessableEntity, "A scope with ID %s already exists", id)
	case add:
		scope = config.DHCPScope{}
	case err != nil:
		return config.DHCPScope{}, err
	}
	field := func(name string) string { return strings.TrimSpace(request.FormValue(name)) }
	scope.Name, scope.Subnet, scope.Router, scope.Domain = field("name"), field("subnet"), field("router"), field("domain")
	scope.DNS = dhcpFormList(request.FormValue("dns"))
	scope.Lease = config.Duration{}
	if lease := field("lease"); lease != "" {
		if err := scope.Lease.UnmarshalText([]byte(lease)); err != nil {
			return config.DHCPScope{}, refuse(http.StatusUnprocessableEntity, "Lease time must be a duration like 24h")
		}
	}
	scope.Ranges, err = dhcpFormRanges(scope.Ranges, field("range_start"), field("range_end"), service.clusterNodes())
	return scope, err
}

// dhcpFirstRange sets the scope's first range, the one the dialog edits, and
// keeps any others; an empty start and end remove it.
func dhcpFirstRange(ranges []config.DHCPRange, start, end string) []config.DHCPRange {
	if start == "" && end == "" {
		if len(ranges) > 0 {
			return ranges[1:]
		}
		return nil
	}
	if len(ranges) == 0 {
		return []config.DHCPRange{{Start: start, End: end}}
	}
	ranges = append([]config.DHCPRange(nil), ranges...)
	ranges[0].Start, ranges[0].End = start, end
	return ranges
}

func dhcpFormList(value string) []string {
	var list []string
	for _, item := range splitFormLines(value) {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	return list
}

func dhcpScopeLabel(scope config.DHCPScope) string {
	if scope.Name != "" {
		return scope.Name
	}
	return scope.ID
}
