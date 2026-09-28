package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/dnsserver"
	"github.com/drudge/sable/internal/querylog"
)

type mcpLookupResolver interface {
	Lookup(string, uint16) (dnsserver.LookupResult, error)
}

type mcpCacheNamePurger interface {
	PurgeCacheName(string) int
}

type domainPolicyChecker interface {
	DomainPolicy(string) dnsserver.DomainPolicy
}

type mcpAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

type mcpDomainRuleChange struct {
	Domain  string `json:"domain"`
	Changed bool   `json:"changed"`
	Message string `json:"message"`
}

var mcpDNSTools = []mcpTool{
	{
		Name:  "lookup",
		Title: "Look up a name",
		Description: "Resolve a name through Sable the way a device on the network would, and say where the answer " +
			"came from: one of Sable's zones, a local name, blocking, the cache, or upstream. Use it to confirm a " +
			"change took effect. The lookup is not written to the query log.",
		InputSchema: mcpObjectSchema(map[string]any{
			"name": mcpString("Fully qualified name to resolve, for example app.example.com."),
			"type": mcpString("Optional record type. Defaults to A."),
		}, []string{"name"}),
		Annotations: mcpToolAnnotations{Title: "Look up a name", ReadOnlyHint: true, OpenWorldHint: true},
		call:        (*Server).mcpLookup,
		section:     "lookups",
		grant:       "zones.read",
	},
	{
		Name:  "purge_cache",
		Title: "Forget a cached name",
		Description: "Drop every cached answer for one name on this node, so the next lookup asks upstream again. " +
			"Names in Sable's own zones are never cached, so this is only needed for names Sable forwards. Other " +
			"cluster nodes keep their own cache.",
		InputSchema: mcpObjectSchema(map[string]any{
			"name": mcpString("Fully qualified name, for example app.example.com."),
		}, []string{"name"}),
		Annotations: mcpToolAnnotations{Title: "Forget a cached name", IdempotentHint: true},
		call:        (*Server).mcpPurgeCache,
		section:     "lookups",
		grant:       "settings.write",
	},
	{
		Name:  "check_domain",
		Title: "Check whether a domain is blocked",
		Description: "Say whether blocking stops a domain for a typical device, which rule and block list cause it, " +
			"and whether the domain is on the allow or block list. Devices set to bypass blocking are never blocked. " +
			"Use it when an app or site will not load.",
		InputSchema: mcpObjectSchema(map[string]any{
			"domain": mcpString("Domain to check, for example ads.example.com."),
		}, []string{"domain"}),
		Annotations: mcpToolAnnotations{Title: "Check whether a domain is blocked", ReadOnlyHint: true, IdempotentHint: true},
		call:        (*Server).mcpCheckDomain,
		section:     "blocking",
		grant:       "blocking.read",
	},
	{
		Name:  "allow_domain",
		Title: "Allow a domain",
		Description: "Put a domain on the allow list so no block list stops it, and take it off the block list. " +
			"Use *.example.com to allow every name under a domain.",
		InputSchema: mcpObjectSchema(map[string]any{
			"domain": mcpString("Domain to allow, for example cdn.example.com or *.example.com."),
		}, []string{"domain"}),
		Annotations: mcpToolAnnotations{Title: "Allow a domain", IdempotentHint: true},
		call:        (*Server).mcpAllowDomain,
		section:     "blocking",
		grant:       "blocking.write",
	},
	{
		Name:  "block_domain",
		Title: "Block a domain",
		Description: "Put a domain on the block list, which also blocks every name under it, and take it off " +
			"the allow list.",
		InputSchema: mcpObjectSchema(map[string]any{
			"domain": mcpString("Domain to block, for example tracker.example.com."),
		}, []string{"domain"}),
		Annotations: mcpToolAnnotations{Title: "Block a domain", DestructiveHint: true, IdempotentHint: true},
		call:        (*Server).mcpBlockDomain,
		section:     "blocking",
		grant:       "blocking.write",
	},
	{
		Name:  "remove_domain_rule",
		Title: "Remove a domain from the allow and block lists",
		Description: "Take a domain off both the allow list and the block list, so block lists alone decide " +
			"what happens to it. It does not unblock a domain a block list names; use allow_domain for that.",
		InputSchema: mcpObjectSchema(map[string]any{
			"domain": mcpString("Domain exactly as it appears on the list, for example *.example.com."),
		}, []string{"domain"}),
		Annotations: mcpToolAnnotations{Title: "Remove a domain from the allow and block lists", DestructiveHint: true, IdempotentHint: true},
		call:        (*Server).mcpRemoveDomainRule,
		section:     "blocking",
		grant:       "blocking.write",
	},
}

// mcpMayResolve limits lookups to tokens that can already see DNS state.
// In-process lookups skip the recursion grant a network client would need,
// so an unrelated token, such as one that only reads metrics, may not use
// Sable as a resolver.
func (server *Server) mcpMayResolve(request *http.Request) bool {
	if !server.securityEnabled {
		return true
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	return hasAnyPermission(principal, []string{auth.PermissionZonesRead, auth.PermissionBlockingRead, auth.PermissionSettingsRead})
}

func (server *Server) mcpHasPermission(request *http.Request, permission string) bool {
	if !server.securityEnabled {
		return true
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	return auth.Authorize(principal, permission, "", "")
}

func (server *Server) mcpLookup(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	if !server.mcpMayResolve(request) {
		return nil, errors.New("this token needs zones.read, blocking.read, or settings.read to look up names")
	}
	name, err := mcpQuestionName(input.Name)
	if err != nil {
		return nil, err
	}
	recordType := strings.ToUpper(strings.TrimSpace(input.Type))
	if recordType == "" {
		recordType = "A"
	}
	qtype, found := dns.StringToType[recordType]
	if !found {
		return nil, fmt.Errorf("unsupported record type %q", input.Type)
	}
	resolver, ok := server.stats.(mcpLookupResolver)
	if !ok {
		return nil, errors.New("lookups are unavailable on this server")
	}
	result, err := resolver.Lookup(name, qtype)
	if err != nil {
		return nil, err
	}
	answers := make([]mcpAnswer, 0, len(result.Response.Answer))
	for _, record := range result.Response.Answer {
		header := record.Header()
		answers = append(answers, mcpAnswer{
			Name: strings.TrimSuffix(header.Name, "."), Type: dns.TypeToString[header.Rrtype], TTL: header.Ttl,
			Value: strings.TrimSpace(strings.TrimPrefix(record.String(), header.String())),
		})
	}
	output := map[string]any{
		"name": strings.TrimSuffix(name, "."), "type": recordType,
		"rcode": dns.RcodeToString[result.Response.Rcode], "source": string(result.Source), "answers": answers,
	}
	if result.Decision.Policy != "" && result.Decision.Policy != querylog.PolicyNotEvaluated {
		output["policy"] = string(result.Decision.Policy)
	}
	if result.Decision.PolicyRule != "" {
		output["policy_rule"] = result.Decision.PolicyRule
	}
	return output, nil
}

func (server *Server) mcpPurgeCache(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Name string `json:"name"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	// The console and the API hold cache purges to the same permission.
	if !server.mcpHasPermission(request, auth.PermissionSettingsWrite) {
		return nil, errors.New("this token needs settings.write to clear the cache")
	}
	name, err := mcpQuestionName(input.Name)
	if err != nil {
		return nil, err
	}
	purger, ok := server.stats.(mcpCacheNamePurger)
	if !ok {
		return nil, errors.New("the cache is unavailable on this server")
	}
	removed := purger.PurgeCacheName(name)
	server.logger.Info("cache name purged", "name", name, "removed", removed, "client", requestClientIP(request), "via", "mcp")
	return map[string]any{"name": strings.TrimSuffix(name, "."), "removed": removed}, nil
}

func (server *Server) mcpCheckDomain(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Domain string `json:"domain"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	if !server.mcpHasPermission(request, auth.PermissionBlockingRead) {
		return nil, errors.New("this token needs blocking.read to check blocking")
	}
	check, err := server.checkDomain(request, input.Domain)
	if err != nil {
		return nil, err
	}
	output := map[string]any{
		"domain":        check.Domain,
		"blocked":       check.Policy.Decision == querylog.PolicyBlocked,
		"decision":      string(check.Policy.Decision),
		"on_allow_list": check.OnAllowList,
		"on_block_list": check.OnBlockList,
		"explanation":   check.Explanation(func(moment time.Time) string { return moment.Format(time.RFC3339) }),
	}
	if check.Policy.Rule != "" {
		output["rule"] = check.Policy.Rule
	}
	if len(check.Policy.Sources) > 0 {
		output["block_lists"] = check.Policy.Sources
	}
	if check.Zone != "" {
		output["answered_by_zone"] = check.Zone
	}
	return output, nil
}

// servingZone names the enabled zone that answers a domain before blocking
// is consulted. A zone the operator or token cannot read is not named.
func (server *Server) servingZone(request *http.Request, domain string) string {
	best := ""
	for _, current := range server.zones.Current().Zones {
		// Forwarder and stub zones send queries on, so blocking still applies.
		if current.Disabled || len(current.Name) <= len(best) ||
			(current.Type != "primary" && current.Type != "secondary" && current.Type != "alias") {
			continue
		}
		if domain != current.Name && !strings.HasSuffix(domain, "."+current.Name) {
			continue
		}
		if server.authorizeZoneRequest(request, auth.PermissionZonesRead, current) {
			best = current.Name
		}
	}
	return best
}

func (server *Server) mcpAllowDomain(request *http.Request, arguments json.RawMessage) (any, error) {
	return server.mcpChangeDomainRule(request, arguments, "blocking.allowed_domain.add", allowDomainRule)
}

func (server *Server) mcpBlockDomain(request *http.Request, arguments json.RawMessage) (any, error) {
	return server.mcpChangeDomainRule(request, arguments, "blocking.blocked_domain.add", blockDomainRule)
}

// allowDomainRule puts a domain on the allow list and takes it off the
// block list.
func allowDomainRule(policy *config.Blocking, domain string) (bool, string) {
	added := mcpAddPolicyEntry(&policy.AllowedDomains, domain)
	unblocked := mcpRemovePolicyEntry(&policy.Domains, domain)
	switch {
	case added && unblocked:
		return true, domain + " is now allowed and was taken off the block list"
	case added:
		return true, domain + " is now allowed"
	case unblocked:
		return true, domain + " was already allowed and was taken off the block list"
	}
	return false, domain + " was already allowed"
}

// blockDomainRule puts a domain on the block list and takes it off the
// allow list.
func blockDomainRule(policy *config.Blocking, domain string) (bool, string) {
	if strings.HasPrefix(domain, "*.") {
		// Block list entries already cover every name beneath them.
		domain = strings.TrimPrefix(domain, "*.")
	}
	added := mcpAddPolicyEntry(&policy.Domains, domain)
	disallowed := mcpRemovePolicyEntry(&policy.AllowedDomains, domain)
	switch {
	case added && disallowed:
		return true, domain + " is now blocked and was taken off the allow list"
	case added:
		return true, domain + " is now blocked"
	case disallowed:
		return true, domain + " was already on the block list and was taken off the allow list"
	}
	return false, domain + " was already blocked"
}

func (server *Server) mcpRemoveDomainRule(request *http.Request, arguments json.RawMessage) (any, error) {
	return server.mcpChangeDomainRule(request, arguments, "blocking.domain_rule.remove", func(policy *config.Blocking, domain string) (bool, string) {
		unblocked := mcpRemovePolicyEntry(&policy.Domains, domain)
		disallowed := mcpRemovePolicyEntry(&policy.AllowedDomains, domain)
		switch {
		case unblocked && disallowed:
			return true, domain + " was taken off the block list and the allow list"
		case unblocked:
			return true, domain + " was taken off the block list"
		case disallowed:
			return true, domain + " was taken off the allow list"
		}
		return false, domain + " is not on the allow list or the block list"
	})
}

// mcpChangeDomainRule edits the allow and block lists through the same
// validated configuration transaction as the console. The change is worked
// out against the current lists first, so a repeated call writes nothing.
func (server *Server) mcpChangeDomainRule(
	request *http.Request,
	arguments json.RawMessage,
	action string,
	change func(*config.Blocking, string) (bool, string),
) (any, error) {
	var input struct {
		Domain string `json:"domain"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	if !server.mcpHasPermission(request, auth.PermissionBlockingWrite) {
		return nil, errors.New("this token needs blocking.write to change the allow or block list")
	}
	if server.mcpReplica() {
		return nil, errors.New(replicaWriteMessage)
	}
	return server.changeDomainRule(request, input.Domain, action, "mcp", change)
}

// changeDomainRule makes one change to the allow and block lists, for MCP or
// the console, which via names. The caller has checked the request may.
func (server *Server) changeDomainRule(
	request *http.Request,
	raw string,
	action string,
	via string,
	change func(*config.Blocking, string) (bool, string),
) (mcpDomainRuleChange, error) {
	domain, err := normalizePolicyEntry(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if err != nil {
		return mcpDomainRuleChange{}, fmt.Errorf("domain is invalid: %w", err)
	}
	editor, ok := server.config.(blockingEditor)
	if !ok {
		return mcpDomainRuleChange{}, errors.New("this configuration source is read-only")
	}
	preview := server.config.Current().Config.Blocking
	preview.Domains = slices.Clone(preview.Domains)
	preview.AllowedDomains = slices.Clone(preview.AllowedDomains)
	changed, message := change(&preview, domain)
	if changed {
		err = editor.UpdateBlocking(request.Context(), func(policy *config.Blocking) error {
			changed, message = change(policy, domain)
			return nil
		})
	}
	attributes := []any{"operation", action, "domain", domain, "client", requestClientIP(request), "via", via}
	if err != nil {
		server.logger.Warn("blocking operation failed", append(attributes, "error", err)...)
		return mcpDomainRuleChange{}, err
	}
	if changed {
		server.logger.Info("blocking operation completed", attributes...)
		server.recordControlPlaneAudit(request, action, message+" via="+via)
	}
	return mcpDomainRuleChange{Domain: domain, Changed: changed, Message: message}, nil
}

func mcpAddPolicyEntry(entries *[]string, domain string) bool {
	if slices.Contains(*entries, domain) {
		return false
	}
	*entries = append(*entries, domain)
	slices.Sort(*entries)
	return true
}

func mcpRemovePolicyEntry(entries *[]string, domain string) bool {
	index := slices.Index(*entries, domain)
	if index < 0 {
		return false
	}
	*entries = slices.Delete(*entries, index, index+1)
	return true
}

func mcpQuestionName(value string) (string, error) {
	name := dns.Fqdn(strings.ToLower(strings.TrimSpace(value)))
	if name == "." {
		return "", errors.New("name is required")
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return "", fmt.Errorf("%q is not a valid DNS name", value)
	}
	return name, nil
}
