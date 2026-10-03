package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/auth"
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
			"and whether the domain has its own exact entry among the allowed domains (on_allow_list) or the custom blocked " +
			"domains (on_block_list), apart from any wildcard entry or subscribed block list. Devices set to bypass blocking " +
			"are never blocked. " +
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

// mcpHasPermission reports whether the caller holds a permission outright,
// not scoped to particular zones.
func (server *Server) mcpHasPermission(request *http.Request, permission string) bool {
	if !server.securityEnabled {
		return true
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	return auth.Authorize(principal, permission, "", "")
}

// mcpGranted reports whether the caller holds a tool's grant anywhere. A zone
// grant may cover only some zones, so a zone tool still checks the zone it
// is asked about.
func (server *Server) mcpGranted(request *http.Request, permission string) bool {
	if !server.securityEnabled {
		return true
	}
	principal, _ := request.Context().Value(principalContextKey{}).(auth.Principal)
	return auth.HasPermission(principal, permission)
}

func (server *Server) mcpLookup(request *http.Request, arguments json.RawMessage) (any, error) {
	var input struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
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
	return server.mcpChangeDomainRule(request, arguments, server.policyService().Allow)
}

func (server *Server) mcpBlockDomain(request *http.Request, arguments json.RawMessage) (any, error) {
	return server.mcpChangeDomainRule(request, arguments, server.policyService().Block)
}

func (server *Server) mcpRemoveDomainRule(request *http.Request, arguments json.RawMessage) (any, error) {
	return server.mcpChangeDomainRule(request, arguments, server.policyService().RemoveRule)
}

func (server *Server) mcpChangeDomainRule(
	request *http.Request,
	arguments json.RawMessage,
	change func(context.Context, actor, string) (domainRuleChange, error),
) (any, error) {
	var input struct {
		Domain string `json:"domain"`
	}
	if err := decodeMCPArguments(arguments, &input); err != nil {
		return nil, err
	}
	return change(request.Context(), requestActor(request, "mcp"), input.Domain)
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
