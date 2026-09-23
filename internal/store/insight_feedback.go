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
