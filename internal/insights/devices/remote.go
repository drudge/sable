package devices

import (
	"cmp"
	"slices"

	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/insights/services"
)

// KindRemoteAccess reports a device that uses a tunnel or remote control
// tool, which can let someone reach the network from outside.
const KindRemoteAccess = "devices.remote-access"

// remoteAccessFindings reports each device and remote access tool it used in
// the window, whether or not it used the tool before. Something already
// running when Sable started watching matters as much as something new, so
// each stays until the operator marks it normal. Each device and tool is its
// own finding, so marking one normal never hides another tool on the same
// device.
func remoteAccessFindings(input ChangesInput) []insights.Finding {
	if len(input.RemoteAccess) == 0 {
		return nil
	}
	findings := make([]insights.Finding, 0)
	for _, device := range input.Devices {
		byService := make(map[string]*remoteUse)
		for _, address := range device.Addresses {
			for _, name := range input.RemoteAccess[address.Address] {
				service, found := services.Lookup(name)
				if !found || service.Category != services.CategoryRemoteAccess {
					continue
				}
				use := byService[service.ID]
				if use == nil {
					use = &remoteUse{service: service}
					byService[service.ID] = use
				}
				if !slices.Contains(use.names, name) {
					use.names = append(use.names, name)
				}
			}
		}
		uses := make([]*remoteUse, 0, len(byService))
		for _, use := range byService {
			slices.Sort(use.names)
			uses = append(uses, use)
		}
		slices.SortFunc(uses, func(left, right *remoteUse) int { return cmp.Compare(left.service.Name, right.service.Name) })
		for _, use := range uses {
			findings = append(findings, remoteAccessFinding(device, *use))
		}
	}
	return findings
}

// remoteUse is one remote access tool a device used, with the names it
// looked up.
type remoteUse struct {
	service services.Service
	names   []string
}

func remoteAccessFinding(device Device, use remoteUse) insights.Finding {
	name := use.service.Name
	reasons := []insights.Reason{{Text: name + " can let someone reach this network from outside"}}
	for _, looked := range use.names[:min(len(use.names), maximumListedNames)] {
		reasons = append(reasons, insights.Reason{Text: "Looked up", Code: looked})
	}
	reasons = append(reasons, insights.Reason{Text: "Reported whether or not it is new, until you mark it normal"})
	subject := deviceSubject(device)
	return insights.Finding{
		ID:   insights.NewID(KindRemoteAccess, subject) + "/" + use.service.ID,
		Kind: KindRemoteAccess, Tone: insights.ToneAttention, Title: "Remote access in use",
		Subject:  subject,
		Headline: Label(device) + " uses " + name,
		Summary:  "Used " + name + " during the selected period. It can let someone reach this network from outside.",
		Reasons:  reasons,
		Facts:    append([]insights.Fact{{Label: "App", Value: name}}, deviceFacts(device, true)...),
		Explanations: []string{
			"Someone set up remote access to this device on purpose",
			"Software installed a tunnel or remote control tool nobody knew about",
		},
		Method: "Sable reports every device that looks up the servers of a tunnel or remote control tool it recognizes " +
			"during the selected period, whether or not it did before. Mark one normal once you know it is expected; " +
			"another device or tool still shows.",
	}
}
