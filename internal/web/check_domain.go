package web

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	blockcompiler "github.com/drudge/sable/internal/blocking"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
	"github.com/drudge/sable/internal/web/pages"
)

// domainCheck is what blocking does with one domain for a typical device.
// The Check a domain panel and MCP's check_domain both tell it. OnAllowList
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
}

// errCheckDomainName is the answer to a name that is not a single domain.
var errCheckDomainName = errors.New("domain must be a single name, for example ads.example.com")

// checkDomain checks one domain against blocking. The caller has checked
// that the request may read blocking.
func (server *Server) checkDomain(request *http.Request, raw string) (domainCheck, error) {
	domain, err := normalizePolicyEntry(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if err != nil || strings.HasPrefix(domain, "*.") {
		return domainCheck{}, errCheckDomainName
	}
	checker, ok := server.stats.(domainPolicyChecker)
	if !ok {
		return domainCheck{}, errors.New("blocking is unavailable on this server")
	}
	lists := server.config.Current().Config.Blocking
	check := domainCheck{
		Domain:      domain,
		Policy:      checker.DomainPolicy(domain),
		OnAllowList: slices.Contains(lists.AllowedDomains, domain),
		OnBlockList: slices.Contains(lists.Domains, domain),
		Zone:        server.servingZone(request, domain),
	}
	if pauser, ok := server.stats.(blockingPauser); ok {
		check.PausedUntil = pauser.BlockingPausedUntil()
	}
	return check, nil
}

// Blocked reports whether blocking stops the domain.
func (check domainCheck) Blocked() bool {
	return check.Zone == "" && check.Policy.Decision == querylog.PolicyBlocked
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
	case querylog.PolicyPaused:
		if !check.PausedUntil.IsZero() {
			return "Blocking is paused until " + at(check.PausedUntil) + ", so nothing is blocked."
		}
		return "Blocking is paused, so nothing is blocked."
	case querylog.PolicyAllowed:
		return "The allow list entry " + policy.Rule + " lets this domain through."
	case querylog.PolicyBlocked:
		if len(policy.Sources) > 0 {
			return "Blocked because " + policy.Rule + " is on " + strings.Join(policy.Sources, ", ") + "."
		}
		return "Blocked because " + policy.Rule + " is blocked."
	default:
		return "Nothing blocks this domain."
	}
}

// checkDomainPanel fills the Check a domain panel. Without a domain it asks
// for one.
func (server *Server) checkDomainPanel(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if err := pages.CheckDomainDrawer(server.checkDomainView(request)).Render(request.Context(), writer); err != nil {
		server.logger.Error("render check domain panel", "error", err)
	}
}

func (server *Server) checkDomainView(request *http.Request) pages.CheckDomainView {
	console := server.consoleView(request)
	view := pages.CheckDomainView{Input: strings.TrimSpace(request.URL.Query().Get("domain")), CanWrite: console.CanWriteBlocking && !console.ControlPlaneReadOnly}
	if view.Input == "" {
		return view
	}
	check, err := server.checkDomain(request, view.Input)
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
	case check.Policy.Decision == querylog.PolicyDisabled || check.Policy.Decision == querylog.PolicyPaused:
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
	result, err := server.policyService().Add(request.Context(), requestActor(request, ""), domain, allowed)
	query := request.URL.Query()
	query.Set("domain", domain)
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
	if err := pages.CheckDomainDrawer(view).Render(request.Context(), writer); err != nil {
		server.logger.Error("render check domain panel", "error", err)
		return
	}
	if err := pages.BlockingContent(page).Render(request.Context(), writer); err != nil {
		server.logger.Error("render blocking page", "error", err)
	}
}
