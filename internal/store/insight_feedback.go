package store

import (
	"context"
	"fmt"
	"time"

	"github.com/drudge/sable/internal/insights"
)

func insightFeedbackTable() string {
	return `
CREATE TABLE IF NOT EXISTS sable_insight_feedback (
    finding_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    until_at TIMESTAMP,
    label TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
)`
}

// SetInsightFeedback records what an operator said about a finding, replacing
// anything said about it before.
func (store *Store) SetInsightFeedback(ctx context.Context, feedback insights.Feedback) error {
	var until any
	if !feedback.Until.IsZero() {
		until = feedback.Until.UTC()
	}
	_, err := store.database.ExecContext(ctx, `
INSERT INTO sable_insight_feedback (finding_id, action, until_at, label, created_by, created_at)
VALUES (`+store.placeholders(6)+`)
ON CONFLICT (finding_id) DO UPDATE SET action = excluded.action, until_at = excluded.until_at,
    label = excluded.label, created_by = excluded.created_by, created_at = excluded.created_at`,
		feedback.FindingID, feedback.Action, until, feedback.Label, feedback.CreatedBy, feedback.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("record insight feedback: %w", err)
	}
	return nil
}

// DeleteInsightFeedback forgets what an operator said about a finding.
func (store *Store) DeleteInsightFeedback(ctx context.Context, findingID string) error {
	if _, err := store.database.ExecContext(ctx, "DELETE FROM sable_insight_feedback WHERE finding_id = "+store.placeholder(1), findingID); err != nil {
		return fmt.Errorf("delete insight feedback: %w", err)
	}
	return nil
}

// InsightFeedback lists the feedback that still hides a finding at a moment,
// and forgets snoozes that have run out.
func (store *Store) InsightFeedback(ctx context.Context, now time.Time) ([]insights.Feedback, error) {
	if _, err := store.database.ExecContext(ctx,
		"DELETE FROM sable_insight_feedback WHERE action = "+store.placeholder(1)+" AND until_at <= "+store.placeholder(2),
		insights.FeedbackSnooze, now.UTC()); err != nil {
		return nil, fmt.Errorf("forget expired insight feedback: %w", err)
	}
	rows, err := store.database.QueryContext(ctx,
		"SELECT finding_id, action, until_at, label, created_by, created_at FROM sable_insight_feedback ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("read insight feedback: %w", err)
	}
	defer rows.Close()
	feedback := make([]insights.Feedback, 0)
	for rows.Next() {
		var entry insights.Feedback
		var until, created any
		if err := rows.Scan(&entry.FindingID, &entry.Action, &until, &entry.Label, &entry.CreatedBy, &created); err != nil {
			return nil, fmt.Errorf("scan insight feedback: %w", err)
		}
		if until != nil {
			if entry.Until, err = databaseTime(until); err != nil {
				return nil, fmt.Errorf("read insight feedback end: %w", err)
			}
		}
		if entry.CreatedAt, err = databaseTime(created); err != nil {
			return nil, fmt.Errorf("read insight feedback time: %w", err)
		}
		feedback = append(feedback, entry)
	}
	return feedback, rows.Err()
}

func insightNotifiedTable() string {
	return `
CREATE TABLE IF NOT EXISTS sable_insight_notified (
    target TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    notified_at TIMESTAMP NOT NULL,
    PRIMARY KEY (target, finding_id)
)`
}

// AlertsSent lists the alerts already sent to a destination, each with when it
// was last seen as news. found is false when nothing was ever recorded for the
// destination, so a new one can take stock of what is already there before
// alerting. The table keeps its Insights-era name so records written by older
// releases still count.
func (store *Store) AlertsSent(ctx context.Context, target string) (map[string]time.Time, bool, error) {
	rows, err := store.database.QueryContext(ctx,
		"SELECT finding_id, notified_at FROM sable_insight_notified WHERE target = "+store.placeholder(1), target)
	if err != nil {
		return nil, false, fmt.Errorf("read notified insights: %w", err)
	}
	defer rows.Close()
	notified := make(map[string]time.Time)
	for rows.Next() {
		var id string
		var at any
		if err := rows.Scan(&id, &at); err != nil {
			return nil, false, fmt.Errorf("scan notified insight: %w", err)
		}
		if notified[id], err = databaseTime(at); err != nil {
			return nil, false, fmt.Errorf("read notified insight time: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	_, primed, err := store.rollupMarker(ctx, insightTargetKey(target))
	return notified, primed || len(notified) > 0, err
}

// MarkAlertsSent records alerts as sent to a destination, or as still news when
// they were sent before, and the destination as known even when there was
// nothing to send.
func (store *Store) MarkAlertsSent(ctx context.Context, target string, ids []string, at time.Time) error {
	for _, id := range ids {
		if _, err := store.database.ExecContext(ctx, `
INSERT INTO sable_insight_notified (target, finding_id, notified_at) VALUES (`+store.placeholders(3)+`)
ON CONFLICT (target, finding_id) DO UPDATE SET notified_at = excluded.notified_at`, target, id, at.UTC()); err != nil {
			return fmt.Errorf("record notified insight: %w", err)
		}
	}
	if _, err := store.database.ExecContext(ctx,
		"INSERT INTO sable_metadata (key, value) VALUES ("+store.placeholders(2)+") ON CONFLICT(key) DO NOTHING",
		insightTargetKey(target), at.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("record insight target: %w", err)
	}
	return nil
}

// ForgetAlertsSent drops alerts from a destination's sent list, so each can
// alert again if it comes back.
func (store *Store) ForgetAlertsSent(ctx context.Context, target string, ids []string) error {
	for _, id := range ids {
		if _, err := store.database.ExecContext(ctx,
			"DELETE FROM sable_insight_notified WHERE target = "+store.placeholder(1)+" AND finding_id = "+store.placeholder(2), target, id); err != nil {
			return fmt.Errorf("forget notified insight: %w", err)
		}
	}
	return nil
}

func insightTargetKey(target string) string { return "insights_notified_target:" + target }
