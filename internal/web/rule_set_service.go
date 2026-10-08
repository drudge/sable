package web

import (
	"context"
	"net/http"
	"slices"

	"github.com/drudge/sable/internal/config"
)

// ruleSetService changes blocking rule sets and the default policy for every
// caller. A rule set's devices live on their [[clients]] entries, so a rename
// or delete changes those in the same transaction.
type ruleSetService struct{ server *Server }

func (server *Server) ruleSetService() ruleSetService { return ruleSetService{server} }

// Save adds a rule set, or replaces the one called original.
func (service ruleSetService) Save(ctx context.Context, who actor, original string, set config.RuleSet) (string, error) {
	action, message := "blocking.rule_set.add", "Rule set "+set.Name+" added"
	if original != "" {
		action, message = "blocking.rule_set.update", "Rule set "+set.Name+" saved"
	}
	err := service.update(ctx, who, action, func(configuration *config.Config) error {
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
