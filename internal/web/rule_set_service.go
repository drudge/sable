package web

import (
	"context"
	"net/http"
	"slices"

	"github.com/drudge/sable/internal/config"
	"github.com/drudge/sable/internal/insights/services"
)

// ruleSetService changes blocking rule sets and the default policy for every
// caller. A rule set's devices live on their [[clients]] entries, so a rename
// or delete changes those in the same transaction.
type ruleSetService struct{ server *Server }

func (server *Server) ruleSetService() ruleSetService { return ruleSetService{server} }

// Save adds a rule set, or renames the one called original and replaces its
// block lists. A rule set's own domains are changed one at a time through
// policyService, and its apps through SetApps, so Save keeps the ones it has,
// and its schedules.
func (service ruleSetService) Save(ctx context.Context, who actor, original string, set config.RuleSet) (string, error) {
	action, message := "blocking.rule_set.add", "Rule set "+set.Name+" added"
	if original != "" {
		action, message = "blocking.rule_set.update", "Rule set "+set.Name+" saved"
	}
	err := service.update(ctx, who, action, func(configuration *config.Config) error {
		if index := slices.IndexFunc(configuration.Blocking.RuleSets, func(existing config.RuleSet) bool { return existing.Name == original }); original != "" && index >= 0 {
			existing := configuration.Blocking.RuleSets[index]
			set.Domains, set.AllowedDomains = slices.Clone(existing.Domains), slices.Clone(existing.AllowedDomains)
			set.Apps = slices.Clone(existing.Apps)
			set.Schedules = existing.Schedules
		}
		return configuration.SaveRuleSet(original, set)
	})
	if err != nil {
		return "", err
	}
	service.server.policyService().finish(ctx, who, action, "", message)
	return message, nil
}

// Delete removes a rule set; its devices go back to the default policy.
func (service ruleSetService) Delete(ctx context.Context, who actor, name string) (string, error) {
	action, message := "blocking.rule_set.delete", "Rule set "+name+" deleted"
	err := service.update(ctx, who, action, func(configuration *config.Config) error {
		return configuration.DeleteRuleSet(name)
	})
	if err != nil {
		return "", err
	}
	service.server.policyService().finish(ctx, who, action, "", message)
	return message, nil
}

// SetApps replaces the apps a rule set blocks. message says what changed.
func (service ruleSetService) SetApps(ctx context.Context, who actor, name string, apps []string, message string) error {
	action := "blocking.rule_set.apps"
	err := service.update(ctx, who, action, func(configuration *config.Config) error {
		index := slices.IndexFunc(configuration.Blocking.RuleSets, func(set config.RuleSet) bool { return set.Name == name })
		if index < 0 {
			return refuse(http.StatusNotFound, "There is no rule set called %s.", name)
		}
		for _, app := range apps {
			if _, found := services.Find(app); !found {
				return refuse(http.StatusUnprocessableEntity, "Sable doesn't know an app called %s.", app)
			}
		}
		sets := slices.Clone(configuration.Blocking.RuleSets)
		sets[index].Apps = slices.Compact(slices.Sorted(slices.Values(apps)))
		configuration.Blocking.RuleSets = sets
		return nil
	})
	if err != nil {
		return err
	}
	service.server.policyService().finish(ctx, who, action, "", message)
	return nil
}

// SetDefaultLists picks the block lists for devices without a rule set. No
// lists means every list.
func (service ruleSetService) SetDefaultLists(ctx context.Context, who actor, lists []string) (string, error) {
	action, message := "blocking.default_lists.update", "Every block list applies to devices without a rule set"
	if len(lists) > 0 {
		message = "Block lists for devices without a rule set saved"
	}
	err := service.update(ctx, who, action, func(configuration *config.Config) error {
		configuration.Blocking.DefaultLists = slices.Clone(lists)
		return nil
	})
	if err != nil {
		return "", err
	}
	service.server.policyService().finish(ctx, who, action, "", message)
	return message, nil
}

// Assign puts a device in a rule set, or takes it out of the one it has with
// an empty name. label names the device in the message. addresses are the
// device's own addresses when it is known by hardware address; see
// config.SetClientRuleSet.
func (service ruleSetService) Assign(ctx context.Context, who actor, device config.Client, addresses []string, label string) (string, error) {
	action, message := "blocking.rule_set.assign", label+" uses the "+device.RuleSet+" rule set"
	if device.RuleSet == "" {
		action, message = "blocking.rule_set.unassign", label+" no longer has a rule set of its own"
	}
	err := service.update(ctx, who, action, func(configuration *config.Config) error {
		if device.RuleSet != "" && !slices.ContainsFunc(configuration.Blocking.RuleSets, func(set config.RuleSet) bool { return set.Name == device.RuleSet }) {
			return refuse(http.StatusUnprocessableEntity, "There is no rule set called %s.", device.RuleSet)
		}
		var err error
		configuration.Clients, err = config.SetClientRuleSet(configuration.Clients, device, addresses...)
		return err
	})
	if err != nil {
		return "", err
	}
	service.server.policyService().finish(ctx, who, action, "", message)
	return message, nil
}

func (service ruleSetService) update(ctx context.Context, who actor, action string, change func(*config.Config) error) error {
	if err := service.server.policyService().ready(who); err != nil {
		return err
	}
	editor, ok := service.server.config.(settingsEditor)
	if !ok {
		return refuse(http.StatusNotImplemented, "this configuration source is read-only")
	}
	err := editor.Update(ctx, change)
	if err != nil {
		service.server.logger.Warn("blocking operation failed", append(service.server.policyService().logAttributes(who, action), "error", err)...)
	}
	return err
}
