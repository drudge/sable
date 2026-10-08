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

// DomainPolicy explains how the blocking policy treats a name for a client
// without a bypass.
type DomainPolicy struct {
	Decision querylog.PolicyDecision
	Rule     string
	Sources  []string
}

func (handler *Handler) DomainPolicy(name string) DomainPolicy {
	runtime := handler.runtime.Load()
	if runtime == nil {
		return DomainPolicy{Decision: querylog.PolicyNotEvaluated}
	}
	decision, rule, sources := runtime.policyDecision(name, "", nil, handler.BlockingPaused())
	return DomainPolicy{Decision: decision, Rule: rule, Sources: append([]string(nil), sources...)}
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
func (runtime *Runtime) policyDecision(name, clientIP string, devices DeviceAddresses, paused bool) (querylog.PolicyDecision, string, []string) {
	if !runtime.blocking {
		return querylog.PolicyDisabled, "", nil
	}
	client, identified := identifyClient(clientIP, devices)
	set := runtime.ruleSetFor(client, identified)
	if identified && !runtime.holds.empty() && runtime.held(client, time.Now) {
		if rule := set.allowedRule(name); rule != "" {
			return querylog.PolicyAllowed, rule, nil
		}
		if rule := runtime.allowed.match(name); rule != "" {
			return querylog.PolicyAllowed, rule, nil
		}
		return querylog.PolicyHeld, "", nil
	}
	if paused {
		return querylog.PolicyPaused, "", nil
	}
	if set != nil {
		if set.off {
			// The fact that the client bypassed policy is useful; persisting the
			// matching address or network would duplicate sensitive configuration.
			return querylog.PolicyClientBypass, "", nil
		}
		if rule := set.allowed.match(name); rule != "" {
			return querylog.PolicyAllowed, rule, nil
		}
		if rule, _ := matchingDomainRule(set.blocked, name, nil); rule != "" {
			return querylog.PolicyBlocked, rule, nil
		}
	}
	if rule := runtime.allowed.match(name); rule != "" {
		return querylog.PolicyAllowed, rule, nil
	}
	applies := set.ownerMask()
	if rule, owner := matchingDomainRule(runtime.blocked, name, applies); rule != "" {
		if exception, exceptionOwner := runtime.matchingException(name, applies); exception != "" {
			return querylog.PolicyAllowed, exception, set.ownerSources(runtime, exceptionOwner)
		}
		return querylog.PolicyBlocked, rule, set.ownerSources(runtime, owner)
	}
	return querylog.PolicyNoMatch, "", nil
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
