package store

import (
	"context"
	"testing"
	"time"

	"github.com/drudge/sable/internal/insights"
)

func TestInsightFeedbackRemembersAndForgets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	opened := openQueryLogStore(t, nil)
	now := time.Now().UTC().Truncate(time.Second)

	for _, feedback := range []insights.Feedback{
		{FindingID: "devices.went-quiet/device:mac:9c:8e:cd:33:0c:c3", Action: insights.FeedbackNormal, Label: "Went quiet: dock-camera-02", CreatedBy: "art", CreatedAt: now},
		{FindingID: "devices.traffic-spike/device:ip:10.0.0.5", Action: insights.FeedbackSnooze, Until: now.Add(time.Hour), CreatedAt: now},
		{FindingID: "devices.new-app/device:ip:10.0.0.9", Action: insights.FeedbackSnooze, Until: now.Add(-time.Minute), CreatedAt: now},
	} {
		if err := opened.SetInsightFeedback(ctx, feedback); err != nil {
			t.Fatal(err)
		}
	}
	feedback, err := opened.InsightFeedback(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(feedback) != 2 {
		t.Fatalf("feedback = %+v, want the expired snooze forgotten", feedback)
	}
	byID := map[string]insights.Feedback{}
	for _, entry := range feedback {
		byID[entry.FindingID] = entry
	}
	if normal := byID["devices.went-quiet/device:mac:9c:8e:cd:33:0c:c3"]; normal.Label != "Went quiet: dock-camera-02" || !normal.Until.IsZero() || normal.CreatedBy != "art" {
		t.Fatalf("normal = %+v", normal)
	}
	if snooze := byID["devices.traffic-spike/device:ip:10.0.0.5"]; !snooze.Until.Equal(now.Add(time.Hour)) {
		t.Fatalf("snooze = %+v", snooze)
	}
	if err := opened.DeleteInsightFeedback(ctx, "devices.went-quiet/device:mac:9c:8e:cd:33:0c:c3"); err != nil {
		t.Fatal(err)
	}
	if feedback, _ := opened.InsightFeedback(ctx, now); len(feedback) != 1 {
		t.Fatalf("after delete = %+v", feedback)
	}
}
