package devices

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/insights/services"
)

// KindNewApp reports a device that started using an app it never used before.
const KindNewApp = "devices.new-app"

const (
	// maximumAppCandidates bounds how many devices have their full name
	// history read in one analysis.
	maximumAppCandidates = 25
	maximumNewApps       = 3
	maximumAppsPerDevice = 3
)

// newApp is one app a device used for the first time.
type newApp struct {
	service   services.Service
	firstSeen time.Time
	firstName string
	domains   []insights.DomainEvidence
}

// newApps names the apps in a device's history that it first used at or after
// since. History must list every name the device has queried; operating system
// traffic is left out because it changes with every update and says nothing
// about what people are doing.
func newApps(history []insights.DomainEvidence, since time.Time) []newApp {
	byService := make(map[string]*newApp)
	for _, domain := range history {
		service, found := services.Lookup(domain.Name)
		if !found || service.Category == services.CategoryPlatform {
			continue
		}
		app := byService[service.ID]
		if app == nil {
			app = &newApp{service: service}
			byService[service.ID] = app
		}
		if app.firstSeen.IsZero() || domain.FirstSeen.Before(app.firstSeen) {
			app.firstSeen, app.firstName = domain.FirstSeen, domain.Name
		}
		app.domains = append(app.domains, domain)
	}
	apps := make([]newApp, 0)
	for _, app := range byService {
		if !app.firstSeen.Before(since) {
			apps = append(apps, *app)
		}
	}
	slices.SortFunc(apps, func(left, right newApp) int {
		if order := right.firstSeen.Compare(left.firstSeen); order != 0 {
			return order
		}
		return cmp.Compare(left.service.Name, right.service.Name)
	})
	return apps
}

func newAppFindings(input ChangesInput) []insights.Finding {
	if input.DomainHistory == nil || !input.trackedBefore(input.WindowStart) {
		return nil
	}
	candidates := make([]Device, 0)
	for _, device := range input.Devices {
		if device.NewDomains > 0 && device.FirstSeen.Before(input.WindowStart) {
			candidates = append(candidates, device)
		}
	}
	slices.SortFunc(candidates, func(left, right Device) int { return cmp.Compare(right.NewDomains, left.NewDomains) })
	type deviceApps struct {
		device Device
		apps   []newApp
	}
	found := make([]deviceApps, 0)
	for _, device := range candidates[:min(len(candidates), maximumAppCandidates)] {
		history, complete := input.DomainHistory(device)
		if !complete {
			// Without the whole history, an old app could look new.
			continue
		}
		if apps := newApps(history, input.WindowStart); len(apps) > 0 {
			found = append(found, deviceApps{device: device, apps: apps})
		}
	}
	slices.SortFunc(found, func(left, right deviceApps) int { return right.apps[0].firstSeen.Compare(left.apps[0].firstSeen) })
	findings := make([]insights.Finding, 0, min(len(found), maximumNewApps))
	for _, entry := range found[:min(len(found), maximumNewApps)] {
		shown := min(len(entry.apps), maximumAppsPerDevice)
		findings = append(findings, newAppFinding(entry.device, entry.apps[:shown], entry.apps[shown:], input))
	}
	return findings
}

func newAppFinding(device Device, apps, more []newApp, input ChangesInput) insights.Finding {
	names := make([]string, 0, len(apps))
	reasons := make([]insights.Reason, 0, len(apps)+2)
	domains := make([]insights.DomainEvidence, 0)
	for _, app := range apps {
		names = append(names, app.service.Name)
		reasons = append(reasons, insights.Reason{
			Text: fmt.Sprintf("First %s lookup %s ago:", app.service.Name, insights.FormatDuration(input.Now.Sub(app.firstSeen))),
			Code: app.firstName,
		})
		domains = append(domains, app.domains...)
	}
	if len(more) > 0 {
		others := make([]string, 0, len(more))
		for _, app := range more {
			others = append(others, app.service.Name)
		}
		reasons = append(reasons, insights.Reason{Text: "Also new to it: " + insights.JoinAnd(others)})
	}
	if device.NewDomains >= minimumNewDomains {
		reasons = append(reasons, insights.Reason{Text: fmt.Sprintf("%s domains queried for the first time in all", insights.FormatCount(device.NewDomains))})
	}
	reasons = append(reasons, insights.Reason{
		Text: "On the network for " + insights.FormatDuration(input.Now.Sub(device.FirstSeen)) + " without using " + insights.JoinOr(names) + " before",
	})
	slices.SortFunc(domains, func(left, right insights.DomainEvidence) int { return left.FirstSeen.Compare(right.FirstSeen) })
	if len(domains) > maximumListedNames {
		domains = domains[:maximumListedNames]
	}
	title := "Started using a new app"
	if len(apps) > 1 {
		title = "Started using new apps"
	}
	facts := deviceFacts(device, false)
	if len(apps) == 1 {
		facts = append([]insights.Fact{{Label: "App", Value: apps[0].service.Name}, {Label: "Kind", Value: apps[0].service.Category}}, facts...)
	} else {
		facts = append([]insights.Fact{{Label: "Apps", Value: strings.Join(names, ", ")}}, facts...)
	}
	return insights.Finding{
		Kind: KindNewApp, Tone: insights.ToneNotice, Title: title,
		Subject:      deviceSubject(device),
		Headline:     Label(device) + " started using " + insights.JoinAnd(names),
		Summary:      fmt.Sprintf("Started using %s during the selected period.", insights.JoinAnd(names)),
		Reasons:      reasons,
		Facts:        facts,
		Domains:      domains,
		Explanations: []string{"Someone installed the app or signed in to it", "An update to other software now uses this service"},
		Method: "Sable names apps from a built-in list of the domains each one owns. It reports an app when a " + noun(device) +
			" that was already on the network queries that app's domains for the first time. Operating system traffic is left out.",
	}
}
