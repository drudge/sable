package dnsserver

import (
	"net"
	"net/netip"
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
	decision, rule, sources := runtime.policyDecision(name, "", handler.BlockingPaused())
	return DomainPolicy{Decision: decision, Rule: rule, Sources: append([]string(nil), sources...)}
}

func (runtime *Runtime) matchesBlocked(name string) bool {
	rule, _ := matchingDomainRule(runtime.blocked, name)
	return rule != ""
}

func (runtime *Runtime) matchesAllowed(name string) bool {
	return runtime.matchingAllowedRule(name) != ""
}

func (runtime *Runtime) matchingAllowedRule(name string) string {
	name = normalizeName(name)
	if _, found := runtime.allowedExact[name]; found {
		return name
	}
	for {
		separator := strings.IndexByte(name, '.')
		if separator < 0 {
			return ""
		}
		name = name[separator+1:]
		if _, found := runtime.allowedWildcard[name]; found {
			return "*." + name
		}
	}
}

func matchingDomainRule(domains map[string]uint32, name string) (string, uint32) {
	name = normalizeName(name)
	for name != "" {
		if owner, found := domains[name]; found {
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

func (runtime *Runtime) policyDecision(name, clientIP string, paused bool) (querylog.PolicyDecision, string, []string) {
	if !runtime.blocking {
		return querylog.PolicyDisabled, "", nil
	}
	if paused {
		return querylog.PolicyPaused, "", nil
	}
	if runtime.clientBypasses(clientIP) {
		// The fact that the client bypassed policy is useful; persisting the
		// matching address or network would duplicate sensitive configuration.
		return querylog.PolicyClientBypass, "", nil
	}
	if rule := runtime.matchingAllowedRule(name); rule != "" {
		return querylog.PolicyAllowed, rule, nil
	}
	if rule, owner := matchingDomainRule(runtime.blocked, name); rule != "" {
		if exception, exceptionOwner := runtime.matchingException(name); exception != "" {
			return querylog.PolicyAllowed, exception, runtime.blockedSources(exceptionOwner)
		}
		return querylog.PolicyBlocked, rule, runtime.blockedSources(owner)
	}
	return querylog.PolicyNoMatch, "", nil
}

// matchingException finds a block list's @@ exception for a blocked name. An
// exception lifts blocks from every list, as in AdGuard Home and Technitium,
// but not a $important block or one the operator added.
func (runtime *Runtime) matchingException(name string) (string, uint32) {
	if len(runtime.exceptions) == 0 {
		return "", 0
	}
	exception, owner := matchingDomainRule(runtime.exceptions, name)
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

func (runtime *Runtime) clientBypasses(value string) bool {
	if value == "" || len(runtime.bypass) == 0 {
		return false
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	address = address.Unmap()
	for _, prefix := range runtime.bypass {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
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
