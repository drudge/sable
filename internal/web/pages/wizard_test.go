package pages

import "testing"

func TestWizardStepsMoveOnlyBetweenKnownSteps(t *testing.T) {
	steps := WizardSteps{"a", "b", "c", "d"}
	skipC := func(step string) bool { return step == "c" }
	for _, test := range []struct {
		name, got, want string
	}{
		{"next", steps.Next("a", nil), "b"},
		{"next skips", steps.Next("b", skipC), "d"},
		{"next from last", steps.Next("d", nil), ""},
		{"next from unknown", steps.Next("x", nil), ""},
		{"previous", steps.Previous("c", nil), "b"},
		{"previous skips", steps.Previous("d", skipC), "b"},
		{"previous from first", steps.Previous("a", nil), ""},
		{"previous from unknown", steps.Previous("x", nil), ""},
	} {
		if test.got != test.want {
			t.Errorf("%s = %q, want %q", test.name, test.got, test.want)
		}
	}
	if steps.Position("x") != 1 || steps.Index("x") != 0 || steps.Position("c") != 3 {
		t.Error("an unknown step must have no index but draw as the first")
	}
}

// Back is how a posted wizard_target becomes the step on screen, so it is the
// guard against a browser naming a step the wizard lacks or jumping ahead past
// a step's validation.
func TestWizardStepsBackRefusesIllegalMoves(t *testing.T) {
	steps := WizardSteps{"a", "b", "c", "d"}
	skipC := func(step string) bool { return step == "c" }
	for _, test := range []struct {
		current, target, want string
		skip                  func(string) bool
		ok                    bool
	}{
		{current: "c", target: "a", want: "a", ok: true},
		{current: "c", target: "c", want: "c", ok: true},
		{current: "d", target: "c", want: "b", skip: skipC, ok: true},
		{current: "a", target: "d"},
		{current: "b", target: "c"},
		{current: "c", target: "x"},
		{current: "x", target: "a"},
		{current: "", target: "a"},
	} {
		got, ok := steps.Back(test.current, test.target, test.skip)
		if got != test.want || ok != test.ok {
			t.Errorf("Back(%q, %q) = %q, %v; want %q, %v", test.current, test.target, got, ok, test.want, test.ok)
		}
	}
}

func TestUniFiWizardSkipsZonesOnlyWithoutANetwork(t *testing.T) {
	empty := UniFiWizardView{}
	if UniFiWizardSteps.Next(UniFiStepNetworks, empty.SkipsStep) != UniFiStepReview {
		t.Error("with no network the zones step must be skipped going forward")
	}
	if UniFiWizardSteps.Previous(UniFiStepReview, empty.SkipsStep) != UniFiStepNetworks {
		t.Error("with no network the zones step must be skipped going back")
	}
	selected := UniFiWizardView{Selected: []string{"net-lan"}}
	if UniFiWizardSteps.Next(UniFiStepNetworks, selected.SkipsStep) != UniFiStepZones {
		t.Error("a selected network must reach the zones step")
	}
}
