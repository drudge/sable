package alerts

import "time"

// Sample stands in for a real alert in tests and previews.
func Sample(now time.Time) Alert {
	return Alert{
		ID: "sable.test", Group: "test", Kind: "sable.test", Tone: ToneNotice, Title: "Test alert",
		Subject: "Sable", Headline: "Sable can reach this destination",
		Summary:    "This is a test from Sable. Alerts will arrive like this.",
		Reasons:    []string{"Sent from Settings to show how alerts arrive."},
		Path:       "/settings?tab=alerts",
		PathLabel:  "Open Alerts",
		ObservedAt: now,
	}
}
