package pages

import (
	"slices"
	"strconv"
)

// WizardSteps is a setup wizard's steps in the order an operator meets them.
// It is the one place a wizard's position, progress markers, and back and
// forward moves are worked out, so a step name posted by the browser is only
// ever honoured if the wizard actually has that step.
type WizardSteps []string

// Index returns step's 1-based position, or 0 when the wizard has no such step.
func (steps WizardSteps) Index(step string) int {
	return slices.Index(steps, step) + 1
}

// Position is the step number the progress bar shows. An unknown step is drawn
// as the first one.
func (steps WizardSteps) Position(step string) int {
	return max(steps.Index(step), 1)
}

// Class styles the progress marker at position while step is current.
func (steps WizardSteps) Class(step string, position int) string {
	current := steps.Position(step)
	if current > position {
		return "complete"
	}
	if current == position {
		return "current"
	}
	return ""
}

// Marker is the progress marker's label: a tick once the step is behind the
// operator, otherwise its number.
func (steps WizardSteps) Marker(step string, position int) string {
	if steps.Position(step) > position {
		return "✓"
	}
	return strconv.Itoa(position)
}

// Previous returns the nearest earlier step that skip does not pass over, or
// "" from the first step or a step the wizard does not have. A nil skip passes
// over nothing.
func (steps WizardSteps) Previous(step string, skip func(string) bool) string {
	for index := steps.Index(step) - 2; index >= 0; index-- {
		if skip == nil || !skip(steps[index]) {
			return steps[index]
		}
	}
	return ""
}

// Next returns the nearest later step that skip does not pass over, or "" from
// the last step or a step the wizard does not have.
func (steps WizardSteps) Next(step string, skip func(string) bool) string {
	start := steps.Index(step)
	if start == 0 {
		return ""
	}
	for index := start; index < len(steps); index++ {
		if skip == nil || !skip(steps[index]) {
			return steps[index]
		}
	}
	return ""
}

// Back resolves a request to revisit target while current is on screen. Only a
// step the wizard has, at or before current, may be revisited; anything else is
// refused. A target skip passes over falls back to the nearest earlier step, the
// same way the wizard skipped it going forward.
func (steps WizardSteps) Back(current, target string, skip func(string) bool) (string, bool) {
	at, to := steps.Index(current), steps.Index(target)
	if at == 0 || to == 0 || to > at {
		return "", false
	}
	if skip != nil && skip(target) {
		if previous := steps.Previous(target, skip); previous != "" {
			return previous, true
		}
	}
	return target, true
}

// The UniFi wizard's steps.
const (
	UniFiStepConnect  = "connect"
	UniFiStepNetworks = "networks"
	UniFiStepZones    = "zones"
	UniFiStepReview   = "review"
)

// UniFiWizardSteps orders the UniFi wizard.
var UniFiWizardSteps = WizardSteps{UniFiStepConnect, UniFiStepNetworks, UniFiStepZones, UniFiStepReview}

// SkipsStep reports whether the UniFi wizard passes over step. With no network
// selected there are no zones to map, in either direction.
func (wizard UniFiWizardView) SkipsStep(step string) bool {
	return step == UniFiStepZones && len(wizard.Selected) == 0
}

// The SSO wizard's steps, named the same way the UniFi wizard names its own.
const (
	SSOStepProvider = "provider"
	SSOStepClaims   = "claims"
	SSOStepRoles    = "roles"
	SSOStepReview   = "review"
)

// SSOWizardSteps orders the SSO wizard.
var SSOWizardSteps = WizardSteps{SSOStepProvider, SSOStepClaims, SSOStepRoles, SSOStepReview}
