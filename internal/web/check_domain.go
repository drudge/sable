package web

import (
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/insights/services"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/web/pages"
)

// domainCheck is what blocking does with one domain for a device, a typical
// one on the Default rules unless one is named. The Check a domain panel and
// MCP's check_domain both tell it. OnAllowList
// and OnBlockList report an exact entry of the domain on the Blocking page's
// Allowed or Blocked tab, not a wildcard entry or a subscribed block list.
type domainCheck struct {
	Domain      string
	Policy      dnsserver.DomainPolicy
	OnAllowList bool
	OnBlockList bool
	// Zone names the zone Sable answers the domain from, before blocking is
	// consulted.
	Zone        string
	PausedUntil time.Time
	// Device names the device checked for, empty for a typical one.
	Device string
}

// errCheckDomainName is the answer to a name that is not a single domain.
var errCheckDomainName = errors.New("domain must be a single name, for example ads.example.com")

// errCheckDevice is the answer to a device Sable can't find.
var errCheckDevice = errors.New("device must be one Sable has seen, an IP address, or a hardware address")

// checkDomain checks one domain against blocking, for the device named by
// device, or a typical one when it is empty. The caller has checked that the
// request may read blocking.
func (server *Server) checkDomain(request *http.Request, raw, device string) (domainCheck, error) {
	domain, err := normalizePolicyEntry(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if err != nil || strings.HasPrefix(domain, "*.") {
		return domainCheck{}, errCheckDomainName
	}
	checker, ok := server.stats.(domainPolicyChecker)
	if !ok {
		return domainCheck{}, errors.New("blocking is unavailable on this server")
	}
	configuration := server.config.Current().Config
	var label, address, mac string
	if device = strings.TrimSpace(device); device != "" {
		entry, ok := readClientEntry(server.ruleSetDeviceEntry(request.Context(), configuration, "", device))
		if !ok {
			return domainCheck{}, errCheckDevice
		}
		label = server.clientLabeler(request.Context())(entry)
		address, mac = entry.Address, entry.MAC
		if prefix, err := netip.ParsePrefix(address); err == nil {
			// A network is checked as a device on it.
			address = prefix.Addr().String()
		}
	}
	lists := configuration.Blocking
	check := domainCheck{
		Domain:      domain,
		Policy:      checker.DomainPolicy(domain, address, mac),
		OnAllowList: slices.Contains(lists.AllowedDomains, domain),
		OnBlockList: slices.Contains(lists.Domains, domain),
		Zone:        server.servingZone(request, domain),
		Device:      label,
	}
	if pauser, ok := server.stats.(blockingPauser); ok {
		check.PausedUntil = pauser.BlockingPausedUntil()
	}
	return check, nil
}

// Blocked reports whether blocking stops the domain.
func (check domainCheck) Blocked() bool {
	return check.Zone == "" && (check.Policy.Decision == querylog.PolicyBlocked || check.Policy.Decision == querylog.PolicyHeld)
}

// Explanation says why in a sentence, with times written by at.
func (check domainCheck) Explanation(at func(time.Time) string) string {
	if check.Zone != "" {
		return "Sable answers this name from its zone " + check.Zone + ", so blocking does not apply to it."
	}
	policy := check.Policy
	switch policy.Decision {
	case querylog.PolicyDisabled:
		return "Blocking is turned off, so nothing is blocked."
	case querylog.PolicyHeld:
		return "Everything is blocked for this device until its hold ends, apart from its allowed domains."
	case querylog.PolicyClientBypass:
		return "Blocking is off for devices in the " + policy.RuleSet + " rule set, so nothing is blocked."
	case querylog.PolicyPaused:
		if !check.PausedUntil.IsZero() {
			return "Blocking is paused until " + at(check.PausedUntil) + ", so nothing is blocked."
		}
		return "Blocking is paused, so nothing is blocked."
	case querylog.PolicyAllowed:
		if policy.OwnRule {
			return "The " + policy.RuleSet + " rule set allows " + policy.Rule + ", so this domain gets through."
		}
		if len(policy.Sources) > 0 {
			return "A block list blocks this domain, but the exception for " + policy.Rule + " on " + strings.Join(policy.Sources, ", ") + " lets it through."
		}
		return "The allow list entry " + policy.Rule + " lets this domain through."
	case querylog.PolicyBlocked:
		if policy.OwnRule {
			if app := ownRuleApp(policy.Rule); app != "" {
				return "Blocked because the " + policy.RuleSet + " rule set blocks " + app + ", and " + policy.Rule + " is one of its domains."
			}
			return "Blocked because the " + policy.RuleSet + " rule set blocks " + policy.Rule + "."
		}
		if len(policy.Sources) > 0 {
			return "Blocked because " + policy.Rule + " is on " + strings.Join(policy.Sources, ", ") + "."
		}
		return "Blocked because " + policy.Rule + " is blocked."
	default:
		return "Nothing blocks this domain."
	}
}

// ownRuleApp names the app a rule set's own rule blocks, when the rule is
// one of the app's domains, or "".
func ownRuleApp(rule string) string {
	if service, found := services.ForSuffix(rule); found {
		return service.Name
	}
	return ""
}

// checkDomainPanel fills the Check a domain panel. Without a domain it asks
// for one.
func (server *Server) checkDomainPanel(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	server.render(writer, request, pages.CheckDomainDrawer(server.checkDomainView(request)))
}

func (server *Server) checkDomainView(request *http.Request) pages.CheckDomainView {
	console := server.consoleView(request)
	query := request.URL.Query()
	view := pages.CheckDomainView{
		Input: strings.TrimSpace(query.Get("domain")), DeviceInput: strings.TrimSpace(query.Get("device")),
		CanWrite: console.CanWriteBlocking && !console.ControlPlaneReadOnly,
	}
	// Devices only answer differently once some are in rule sets.
	configuration := server.config.Current().Config
	if len(configuration.Blocking.RuleSets) > 0 || view.DeviceInput != "" {
		view.DeviceOptions = server.ruleSetDeviceOptions(request.Context(), configuration, "")
	}
	if view.Input == "" {
		return view
	}
	check, err := server.checkDomain(request, view.Input, view.DeviceInput)
	if err != nil {
		view.Error = err.Error()
		return view
	}
	display := requestTimeDisplay(request)
	view.Checked = true
	view.Domain = check.Domain
	view.Verdict = checkDomainVerdict(check)
	view.Explanation = check.Explanation(func(moment time.Time) string { return pages.FormatShortDateTime(moment, display, false) })
	view.Rule = check.Policy.Rule
	for _, source := range check.Policy.Sources {
		if source == blockcompiler.CustomSourceName {
			view.CustomBlocked = true
		} else {
			view.Lists = append(view.Lists, source)
		}
	}
	view.OnBlockList = check.OnBlockList
	view.Zone = check.Zone
	view.Device = check.Device
	view.RuleSet, view.OwnRule = check.Policy.RuleSet, check.Policy.OwnRule
	return view
}

func checkDomainVerdict(check domainCheck) pages.CheckDomainVerdict {
	switch {
	case check.Zone != "":
		return pages.CheckDomainZone
	case check.Blocked():
		return pages.CheckDomainBlocked
	case check.Policy.Decision == querylog.PolicyAllowed:
		return pages.CheckDomainAllowed
	case check.Policy.Decision == querylog.PolicyDisabled || check.Policy.Decision == querylog.PolicyPaused ||
		check.Policy.Decision == querylog.PolicyClientBypass:
		return pages.CheckDomainOff
	default:
		return pages.CheckDomainOpen
	}
}

// checkDomainRule allows or blocks the domain the panel checked, then checks
// it again. The Blocking page beneath updates with the same response.
func (server *Server) checkDomainRule(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		writeBlockingErrorStatus(writer, request, http.StatusBadRequest)
		return
	}
	// The page beneath turns to the list the domain went on.
	allowed := request.FormValue("action") == "allow"
	tab := "domains"
	if allowed {
		tab = "allowed"
	}
	domain := request.FormValue("domain")
	result, err := server.policyService().Add(request.Context(), requestActor(request, ""), "", domain, allowed)
	query := request.URL.Query()
	query.Set("domain", domain)
	query.Set("device", request.FormValue("device"))
	request.URL.RawQuery = query.Encode()
	view := server.checkDomainView(request)
	status := http.StatusOK
	if err != nil {
		view.Error, status = err.Error(), serviceStatus(err)
	} else {
		view.Message = result.Message + "."
	}
	page := server.blockingView(request, "", "", tab)
	page.OutOfBand = true
	writeFragmentStatus(writer, status)
	if !server.render(writer, request, pages.CheckDomainDrawer(view)) {
		return
	}
	server.render(writer, request, pages.BlockingContent(page))
}
