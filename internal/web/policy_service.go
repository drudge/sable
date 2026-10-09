package web

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/drudge/sable/internal/auth"
	"github.com/drudge/sable/internal/config"
)

// policyService changes the allow and block lists for every caller: the
// console, MCP, the query log, and the check-domain panel. The two lists are
// exclusive, so putting a domain on one takes it off the other. Each change
// applies to everyone, or to one rule set's own lists when ruleSet names one.
type policyService struct{ server *Server }

func (server *Server) policyService() policyService { return policyService{server} }

type domainRuleChange struct {
	Domain  string `json:"domain"`
	Changed bool   `json:"changed"`
	Message string `json:"message"`
}

func (service policyService) Allow(ctx context.Context, who actor, ruleSet, domain string) (domainRuleChange, error) {
	return service.change(ctx, who, ruleSet, domain, "blocking.allowed_domain.add", allowDomainRule)
}

func (service policyService) Block(ctx context.Context, who actor, ruleSet, domain string) (domainRuleChange, error) {
	return service.change(ctx, who, ruleSet, domain, "blocking.blocked_domain.add", blockDomainRule)
}

// Add puts a domain on the allow list or the block list.
func (service policyService) Add(ctx context.Context, who actor, ruleSet, domain string, allowed bool) (domainRuleChange, error) {
	if allowed {
		return service.Allow(ctx, who, ruleSet, domain)
	}
	return service.Block(ctx, who, ruleSet, domain)
}

// RemoveRule takes a domain off both lists.
func (service policyService) RemoveRule(ctx context.Context, who actor, ruleSet, domain string) (domainRuleChange, error) {
	return service.change(ctx, who, ruleSet, domain, "blocking.domain_rule.remove", func(lists domainLists, domain string) (bool, string) {
		unblocked := removePolicyEntry(lists.blocked, domain)
		disallowed := removePolicyEntry(lists.allowed, domain)
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

// Remove takes a domain off one list.
func (service policyService) Remove(ctx context.Context, who actor, ruleSet, domain string, allowed bool) (domainRuleChange, error) {
	action, list := "blocking.blocked_domain.delete", "block list"
	if allowed {
		action, list = "blocking.allowed_domain.delete", "allow list"
	}
	return service.change(ctx, who, ruleSet, domain, action, func(lists domainLists, domain string) (bool, string) {
		if removePolicyEntry(lists.list(allowed), domain) {
			return true, domain + " was taken off the " + list
		}
		return false, domain + " is not on the " + list
	})
}

// Clear empties one list.
func (service policyService) Clear(ctx context.Context, who actor, ruleSet string, allowed bool) (string, error) {
	action, message := "blocking.blocked_domain.clear", "Custom blocked domains cleared"
	if allowed {
		action, message = "blocking.allowed_domain.clear", "Allowed domains cleared"
	}
	message = forRuleSet(message, ruleSet)
	err := service.update(ctx, who, action, func(policy *config.Blocking) error {
		lists, err := ruleSetLists(policy, ruleSet)
		if err != nil {
			return err
		}
		*lists.list(allowed) = nil
		return nil
	}, ruleSetAttribute(ruleSet)...)
	if err != nil {
		return "", err
	}
	service.finish(ctx, who, action, "", message)
	return message, nil
}

// Import adds many domains to one list and takes them off the other.
// skipped is how many lines of the file were not domains, for the message.
func (service policyService) Import(ctx context.Context, who actor, ruleSet string, domains []string, skipped int, allowed bool) (string, error) {
	action := "blocking.blocked_domain.import"
	if allowed {
		action = "blocking.allowed_domain.import"
	}
	var added, moved int
	err := service.update(ctx, who, action, func(policy *config.Blocking) error {
		lists, err := ruleSetLists(policy, ruleSet)
		if err != nil {
			return err
		}
		added, moved = 0, 0
		target, other := lists.list(allowed), lists.list(!allowed)
		existing := make(map[string]struct{}, len(*target)+len(domains))
		for _, domain := range *target {
			existing[domain] = struct{}{}
		}
		taken := make(map[string]struct{}, len(domains))
		for _, domain := range domains {
			taken[domain] = struct{}{}
			if _, duplicate := existing[domain]; duplicate {
				continue
			}
			existing[domain] = struct{}{}
			*target = append(*target, domain)
			added++
		}
		slices.Sort(*target)
		before := len(*other)
		*other = slices.DeleteFunc(*other, func(domain string) bool {
			_, found := taken[domain]
			return found
		})
		moved = before - len(*other)
		return nil
	}, append(ruleSetAttribute(ruleSet), "added", len(domains))...)
	if err != nil {
		return "", err
	}
	message := forRuleSet(importMessage(added, moved, skipped, allowed), ruleSet)
	service.finish(ctx, who, action, "", message)
	return message, nil
}

// allowDomainRule puts a domain on the allow list and takes it off the
// block list.
func allowDomainRule(lists domainLists, domain string) (bool, string) {
	added := addPolicyEntry(lists.allowed, domain)
	unblocked := removePolicyEntry(lists.blocked, domain)
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
func blockDomainRule(lists domainLists, domain string) (bool, string) {
	added := addPolicyEntry(lists.blocked, domain)
	disallowed := removePolicyEntry(lists.allowed, domain)
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

// domainLists are the block and allow lists one change works on: everyone's,
// or one rule set's own.
type domainLists struct{ blocked, allowed *[]string }

func (lists domainLists) list(allowed bool) *[]string {
	if allowed {
		return lists.allowed
	}
	return lists.blocked
}

// ruleSetLists finds the lists a change applies to: everyone's when ruleSet
// is empty, otherwise that rule set's.
func ruleSetLists(policy *config.Blocking, ruleSet string) (domainLists, error) {
	if ruleSet == "" {
		return domainLists{blocked: &policy.Domains, allowed: &policy.AllowedDomains}, nil
	}
	index := slices.IndexFunc(policy.RuleSets, func(set config.RuleSet) bool { return set.Name == ruleSet })
	if index < 0 {
		return domainLists{}, refuse(http.StatusUnprocessableEntity, "There is no rule set called %s.", ruleSet)
	}
	set := &policy.RuleSets[index]
	return domainLists{blocked: &set.Domains, allowed: &set.AllowedDomains}, nil
}

// forRuleSet says which rule set a message is about, when it is about one.
func forRuleSet(message, ruleSet string) string {
	if ruleSet == "" {
		return message
	}
	return message + " for the " + ruleSet + " rule set"
}

func ruleSetAttribute(ruleSet string) []any {
	if ruleSet == "" {
		return nil
	}
	return []any{"rule_set", ruleSet}
}

// change makes one change to the lists for one domain. The change is worked
// out against the current lists first, so a repeated call writes nothing.
func (service policyService) change(
	ctx context.Context,
	who actor,
	ruleSet, raw, action string,
	change func(domainLists, string) (bool, string),
) (domainRuleChange, error) {
	if err := service.ready(who); err != nil {
		return domainRuleChange{}, err
	}
	ruleSet = strings.TrimSpace(ruleSet)
	domain, err := normalizePolicyEntry(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if err != nil {
		return domainRuleChange{}, refuse(http.StatusUnprocessableEntity, "domain is invalid: %v", err)
	}
	policy := service.server.config.Current().Config.Blocking
	current, err := ruleSetLists(&policy, ruleSet)
	if err != nil {
		return domainRuleChange{}, err
	}
	blocked, allowed := slices.Clone(*current.blocked), slices.Clone(*current.allowed)
	changed, message := change(domainLists{blocked: &blocked, allowed: &allowed}, domain)
	message = forRuleSet(message, ruleSet)
	if !changed {
		return domainRuleChange{Domain: domain, Message: message}, nil
	}
	err = service.update(ctx, who, action, func(policy *config.Blocking) error {
		lists, err := ruleSetLists(policy, ruleSet)
		if err != nil {
			return err
		}
		changed, message = change(lists, domain)
		message = forRuleSet(message, ruleSet)
		return nil
	}, append(ruleSetAttribute(ruleSet), "domain", domain)...)
	if err != nil {
		return domainRuleChange{}, err
	}
	if changed {
		service.finish(ctx, who, action, domain, message)
	}
	return domainRuleChange{Domain: domain, Changed: changed, Message: message}, nil
}

// ready checks that who may change the lists here.
func (service policyService) ready(who actor) error {
	if err := service.server.refuseOnReplica(); err != nil {
		return err
	}
	if !service.server.authorized(who, auth.PermissionBlockingWrite, nil) {
		return refuse(http.StatusForbidden, "you need %s to change the allow and block lists", auth.PermissionBlockingWrite)
	}
	return nil
}

// update runs one validated configuration transaction on the lists and logs
// a failure.
func (service policyService) update(ctx context.Context, who actor, action string, mutate func(*config.Blocking) error, attributes ...any) error {
	if err := service.ready(who); err != nil {
		return err
	}
	editor, ok := service.server.config.(blockingEditor)
	if !ok {
		return refuse(http.StatusNotImplemented, "this configuration source is read-only")
	}
	err := editor.UpdateBlocking(ctx, mutate)
	if err != nil {
		service.server.logger.Warn("blocking operation failed", append(service.logAttributes(who, action, attributes...), "error", err)...)
	}
	return err
}

// finish logs and audits a change that took effect.
func (service policyService) finish(ctx context.Context, who actor, action, domain, message string) {
	var attributes []any
	if domain != "" {
		attributes = []any{"domain", domain}
	}
	service.server.logger.Info("blocking operation completed", service.logAttributes(who, action, attributes...)...)
	service.server.audit(ctx, who, action, message)
}

func (service policyService) logAttributes(who actor, action string, attributes ...any) []any {
	base := []any{"operation", action, "client", who.clientIP}
	if who.principal.Username != "" {
		base = append(base, "user", who.principal.Username)
	}
	if who.via != "" {
		base = append(base, "via", who.via)
	}
	return append(base, attributes...)
}

func addPolicyEntry(entries *[]string, domain string) bool {
	if slices.Contains(*entries, domain) {
		return false
	}
	*entries = append(*entries, domain)
	slices.Sort(*entries)
	return true
}

func removePolicyEntry(entries *[]string, domain string) bool {
	index := slices.Index(*entries, domain)
	if index < 0 {
		return false
	}
	*entries = slices.Delete(*entries, index, index+1)
	return true
}

// importMessage says what an import did.
func importMessage(added, moved, invalid int, allowed bool) string {
	list, other := "blocked", "allow"
	if allowed {
		list, other = "allowed", "block"
	}
	message := fmt.Sprintf("Imported %d domains to the %s list", added, list)
	if moved > 0 {
		message += fmt.Sprintf(" and took %d off the %s list", moved, other)
	}
	if invalid > 0 {
		message += fmt.Sprintf(" (%d invalid lines skipped)", invalid)
	}
	return message
}
