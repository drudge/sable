package dnsserver

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/drudge/sable/internal/querylog"
)

func (handler *Handler) PauseBlocking(duration time.Duration) time.Time {
	until := time.Now().Add(duration)
	handler.pausedUntil.Store(until.UnixNano())
	return until
}

func (handler *Handler) ResumeBlocking() { handler.pausedUntil.Store(0) }

func (handler *Handler) BlockingPausedUntil() time.Time {
	value := handler.pausedUntil.Load()
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value)
}

func (handler *Handler) BlockingPaused() bool {
	until := handler.BlockingPausedUntil()
	if until.IsZero() || !time.Now().Before(until) {
		if !until.IsZero() {
			handler.pausedUntil.CompareAndSwap(until.UnixNano(), 0)
		}
		return false
	}
	return true
}

// DomainPolicy explains how the blocking policy treats a name for a client.
type DomainPolicy struct {
	Decision querylog.PolicyDecision
	Rule     string
	Sources  []string
	// RuleSet names the rule set the client uses, empty on the Default rules
	// or while a hold or pause decides.
	RuleSet string
	// OwnRule says Rule is one of the rule set's own blocked or allowed
	// domains rather than a global one or a block list's.
	OwnRule bool
}

// decision records the policy in the query log beside how the query was
// answered.
func (policy DomainPolicy) decision(cache querylog.CacheDecision, resolver querylog.ResolverDecision) querylog.Decision {
	decision := querylog.Decision{Cache: cache, Resolver: resolver}
	policy.record(&decision)
	return decision
}

// record fills decision's policy fields.
func (policy DomainPolicy) record(decision *querylog.Decision) {
	decision.Policy, decision.PolicyRule, decision.PolicySources = policy.Decision, policy.Rule, policy.Sources
	decision.RuleSet, decision.OwnRule = policy.RuleSet, policy.OwnRule
}

// DomainPolicy explains how blocking treats name for a device: one at
// address, behind hardware address mac. Without either it is a device on the
// Default rules. Given only an address, the device's hardware address comes
// from the device address table, as it does for a query.
func (handler *Handler) DomainPolicy(name, address, mac string) DomainPolicy {
	runtime := handler.runtime.Load()
	if runtime == nil {
		return DomainPolicy{Decision: querylog.PolicyNotEvaluated}
	}
	client, identified := identifyClient(address, handler.DeviceAddressTable())
	if parsed, err := net.ParseMAC(mac); err == nil {
		client.mac, identified = parsed.String(), true
	}
	policy := runtime.policyFor(name, client, identified, handler.BlockingPaused())
	policy.Sources = append([]string(nil), policy.Sources...)
	return policy
}

func (runtime *Runtime) matchesBlocked(name string) bool {
	rule, _ := matchingDomainRule(runtime.blocked, name, nil)
	return rule != ""
}

// matchingDomainRule finds the most specific blocked name that covers name.
// applies, when set, skips entries whose owner set it marks false, so a rule
// set that doesn't use a list sees past that list's entries to a parent's.
func matchingDomainRule(domains map[string]uint32, name string, applies []bool) (string, uint32) {
	if len(domains) == 0 {
		return "", 0
	}
	name = normalizeName(name)
	for name != "" {
		if owner, found := domains[name]; found && (applies == nil || (int(owner) < len(applies) && applies[owner])) {
			return name, owner
		}
		separator := strings.IndexByte(name, '.')
		if separator < 0 {
			return "", 0
		}
		name = name[separator+1:]
	}
	return "", 0
}

// blockedSources names the sources behind an owner set. The slice is shared and
// never modified, so a query can carry it without copying.
func (runtime *Runtime) blockedSources(owner uint32) []string {
	if int(owner) >= len(runtime.blockedOwners) {
		return nil
	}
	return runtime.blockedOwners[owner]
}

// policyDecision decides how blocking treats name for a client. A hold on
// the client blocks everything but its allowed domains, even while blocking
// is paused. Otherwise the client's rule set comes first: its own allowed and
// blocked domains win over the global ones, and only its block lists apply.
// The returned Sources are shared with the runtime; don't change them.
func (runtime *Runtime) policyDecision(name, clientIP string, devices DeviceAddresses, paused bool) DomainPolicy {
	client, identified := identifyClient(clientIP, devices)
	return runtime.policyFor(name, client, identified, paused)
}

func (runtime *Runtime) policyFor(name string, client policyClient, identified, paused bool) DomainPolicy {
	if !runtime.blocking {
		return DomainPolicy{Decision: querylog.PolicyDisabled}
	}
	set := runtime.ruleSetFor(client, identified)
	if identified && !runtime.holds.empty() && runtime.held(client, time.Now) {
		if rule := set.allowedRule(name); rule != "" {
			return DomainPolicy{Decision: querylog.PolicyAllowed, Rule: rule, RuleSet: set.ruleSetName(), OwnRule: true}
		}
		if rule := runtime.allowed.match(name); rule != "" {
			return DomainPolicy{Decision: querylog.PolicyAllowed, Rule: rule}
		}
		return DomainPolicy{Decision: querylog.PolicyHeld}
	}
	if paused {
		return DomainPolicy{Decision: querylog.PolicyPaused}
	}
	// The default set, when the Default rules choose their lists, has no name.
	ruleSet := set.ruleSetName()
	if set != nil {
		if set.off {
			// The fact that the client bypassed policy is useful; persisting the
			// matching address or network would duplicate sensitive configuration.
			return DomainPolicy{Decision: querylog.PolicyClientBypass, RuleSet: ruleSet}
		}
		if rule := set.allowed.match(name); rule != "" {
			return DomainPolicy{Decision: querylog.PolicyAllowed, Rule: rule, RuleSet: ruleSet, OwnRule: true}
		}
		if rule, _ := matchingDomainRule(set.blocked, name, nil); rule != "" {
			return DomainPolicy{Decision: querylog.PolicyBlocked, Rule: rule, RuleSet: ruleSet, OwnRule: true}
		}
	}
	if rule := runtime.allowed.match(name); rule != "" {
		return DomainPolicy{Decision: querylog.PolicyAllowed, Rule: rule, RuleSet: ruleSet}
	}
	applies := set.ownerMask()
	if rule, owner := matchingDomainRule(runtime.blocked, name, applies); rule != "" {
		if exception, exceptionOwner := runtime.matchingException(name, applies); exception != "" {
			return DomainPolicy{Decision: querylog.PolicyAllowed, Rule: exception, Sources: set.ownerSources(runtime, exceptionOwner), RuleSet: ruleSet}
		}
		return DomainPolicy{Decision: querylog.PolicyBlocked, Rule: rule, Sources: set.ownerSources(runtime, owner), RuleSet: ruleSet}
	}
	return DomainPolicy{Decision: querylog.PolicyNoMatch, RuleSet: ruleSet}
}

// matchingException finds a block list's @@ exception for a blocked name. An
// exception lifts blocks from every list, as in AdGuard Home and Technitium,
// but not a $important block or one the operator added. Only exceptions from
// lists the client's rule set uses count.
func (runtime *Runtime) matchingException(name string, applies []bool) (string, uint32) {
	if len(runtime.exceptions) == 0 {
		return "", 0
	}
	exception, owner := matchingDomainRule(runtime.exceptions, name, applies)
	if exception == "" {
		return "", 0
	}
	if len(runtime.firmBlocked) > 0 {
		for candidate := normalizeName(name); candidate != ""; {
			if _, found := runtime.firmBlocked[candidate]; found {
				return "", 0
			}
			_, rest, cut := strings.Cut(candidate, ".")
			if !cut {
				break
			}
			candidate = rest
		}
	}
	return exception, owner
}

func (runtime *Runtime) blockedResponse(request *dns.Msg) *dns.Msg {
	question := request.Question[0]
	if question.Qtype == dns.TypeTXT && runtime.blockTXT {
		response := new(dns.Msg)
		response.SetReply(request)
		response.RecursionAvailable = true
		response.Answer = append(response.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: runtime.blockTTL},
			Txt: []string{"blocked by Sable"},
		})
		return response
	}
	if runtime.blockType == "nxdomain" {
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeNameError)
		response.RecursionAvailable = true
		return response
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.RecursionAvailable = true
	for _, address := range runtime.blockAddrs {
		header := dns.RR_Header{Name: question.Name, Class: dns.ClassINET, Ttl: runtime.blockTTL}
		if address.Is4() && (question.Qtype == dns.TypeA || question.Qtype == dns.TypeANY) {
			header.Rrtype = dns.TypeA
			response.Answer = append(response.Answer, &dns.A{Hdr: header, A: net.IP(address.AsSlice())})
		} else if address.Is6() && (question.Qtype == dns.TypeAAAA || question.Qtype == dns.TypeANY) {
			header.Rrtype = dns.TypeAAAA
			response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: net.IP(address.AsSlice())})
		}
	}
	return response
}
