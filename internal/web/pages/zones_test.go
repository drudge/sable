package pages

import (
	"context"
	"io"
	"strings"
	"testing"
)

// The DNSSEC dialog serves two different jobs. Primary zones manage signing,
// forwarder and stub zones manage validation of their upstream answers, and
// secondary zones inherit both from their primary and get a disabled entry.
func TestZoneDNSSECMenuAndDialogPerZoneType(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		zoneType string
		menu     string
		dialog   []string
		absent   []string
	}{
		{
			zoneType: "primary",
			menu:     `data-dialog-open="dnssec-dialog"`,
			dialog:   []string{"Sign <code>signed.test</code>", `name="zsk_lifetime"`},
			absent:   []string{`name="dnssec_validation"`},
		},
		{
			zoneType: "forwarder",
			menu:     `data-dialog-open="dnssec-dialog"`,
			dialog:   []string{"Validate the answers", `name="dnssec_validation"`, `name="dnssec_validation_present"`},
			absent:   []string{`name="zsk_lifetime"`, `name="enabled"`},
		},
		{
			zoneType: "stub",
			menu:     `data-dialog-open="dnssec-dialog"`,
			dialog:   []string{"Validate the answers", `name="dnssec_validation"`},
			absent:   []string{`name="zsk_lifetime"`},
		},
		{
			zoneType: "secondary",
			menu:     "Signing is managed by the primary server",
			absent:   []string{`data-dialog-open="dnssec-dialog"`},
		},
	} {
		t.Run(testCase.zoneType, func(t *testing.T) {
			t.Parallel()

			zone := ZoneView{Name: "signed.test", Type: testCase.zoneType, CanDNSSEC: true}
			menu := renderComponent(t, ZoneActionMenu(zone, "", "", "settings-dialog", "dnssec-dialog", "clone-dialog", "delete-dialog"))
			if !strings.Contains(menu, testCase.menu) {
				t.Fatalf("%s action menu does not contain %q: %s", testCase.zoneType, testCase.menu, menu)
			}
			if !zoneCanDNSSECDialog(zone) {
				return
			}
			dialog := renderComponent(t, ZoneDNSSECDialog(zone, "dnssec-dialog"))
			for _, expected := range testCase.dialog {
				if !strings.Contains(dialog, expected) {
					t.Errorf("%s DNSSEC dialog does not contain %q", testCase.zoneType, expected)
				}
			}
			for _, unexpected := range testCase.absent {
				if strings.Contains(dialog, unexpected) {
					t.Errorf("%s DNSSEC dialog unexpectedly contains %q", testCase.zoneType, unexpected)
				}
			}
		})
	}
}

// The validation switch moved out of zone settings and into the DNSSEC dialog,
// so no zone type may offer it in two places at once.
func TestZoneSettingsDialogOmitsDNSSECValidation(t *testing.T) {
	t.Parallel()

	for _, zoneType := range []string{"primary", "secondary", "stub", "forwarder"} {
		settings := renderComponent(t, ZoneSettingsDialog(ZoneView{Name: "signed.test", Type: zoneType}, "settings-dialog"))
		if strings.Contains(settings, `name="dnssec_validation"`) {
			t.Errorf("%s zone settings still expose the DNSSEC validation switch", zoneType)
		}
	}
}

func renderComponent(t *testing.T, component interface {
	Render(context.Context, io.Writer) error
},
) string {
	t.Helper()
	builder := &strings.Builder{}
	if err := component.Render(context.Background(), builder); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	return builder.String()
}
