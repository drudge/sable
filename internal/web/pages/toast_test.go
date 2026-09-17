package pages

import (
	"strings"
	"testing"
)

func TestToastAndUpdateNoticeShareNotificationCard(t *testing.T) {
	t.Parallel()
	toast := renderComponent(t, ToastSticky("Saved", "success"))
	update := renderComponent(t, UpdateNotification(UpdateView{
		Available: true, CanApply: true, LatestVersion: "1.2.0",
	}))
	for name, markup := range map[string]string{"toast": toast, "update": update} {
		for _, shared := range []string{
			`class="toast notification`,
			`class="notification-summary"`,
			`class="notification-badge"`,
			`class="notification-copy"`,
			`class="toast-dismiss notification-dismiss"`,
		} {
			if !strings.Contains(markup, shared) {
				t.Errorf("%s notification is missing %q: %s", name, shared, markup)
			}
		}
	}
	if !strings.Contains(update, `class="toast-actions notification-actions"`) {
		t.Fatalf("update actions are outside the shared notification card: %s", update)
	}
}

func TestToastActionUsesSharedActionSlot(t *testing.T) {
	t.Parallel()
	markup := renderComponent(t, ToastWithAction("Restart to apply", "success", ToastAction{
		Label: "Restart Sable",
		Icon:  "power",
		Post:  "/ui/restart",
	}))
	for _, expected := range []string{
		"notification-has-actions",
		`class="toast-actions notification-actions"`,
		`hx-post="/ui/restart"`,
		"Restart Sable",
		"icon-power",
	} {
		if !strings.Contains(markup, expected) {
			t.Errorf("action notification is missing %q: %s", expected, markup)
		}
	}
}
