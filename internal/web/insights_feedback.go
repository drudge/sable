package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/drudge/sable/internal/insights"
	"github.com/drudge/sable/internal/web/pages"
)

const (
	// A dismissal hides a finding for a day, a snooze for a week.
	dismissFor = 24 * time.Hour
	snoozeFor  = 7 * 24 * time.Hour
	// maximumFeedbackLabel bounds the stored label of a hidden finding.
	maximumFeedbackLabel = 200
)

// insightFeedbackStore is the optional store capability behind hiding
// findings.
type insightFeedbackStore interface {
	SetInsightFeedback(context.Context, insights.Feedback) error
	DeleteInsightFeedback(context.Context, string) error
	InsightFeedback(context.Context, time.Time) ([]insights.Feedback, error)
}

// hideInsightFinding records that an operator dismissed, snoozed, or marked a
// finding normal.
func (server *Server) hideInsightFinding(writer http.ResponseWriter, request *http.Request) {
	store, ok := server.insightFeedbackRequest(writer, request)
	if !ok {
		return
	}
	id := request.FormValue("id")
	label := strings.TrimSpace(request.FormValue("label"))
	if len([]rune(label)) > maximumFeedbackLabel {
		label = string([]rune(label)[:maximumFeedbackLabel])
	}
	now := time.Now()
	feedback := insights.Feedback{FindingID: id, Label: label, CreatedBy: server.consoleView(request).Username, CreatedAt: now}
	summary := "hid finding " + id
	switch request.FormValue("action") {
	case "dismiss":
		feedback.Action, feedback.Until = insights.FeedbackSnooze, now.Add(dismissFor)
		summary = "dismissed finding " + id
	case "snooze":
		feedback.Action, feedback.Until = insights.FeedbackSnooze, now.Add(snoozeFor)
		summary = "snoozed finding " + id + " for a week"
	case "normal":
		feedback.Action = insights.FeedbackNormal
		summary = "marked finding " + id + " normal"
		// A rolled-up finding is normal for the members it lists, so it
		// comes back for a new one.
		if members := request.Form["member"]; len(members) > 0 {
			server.markInsightMembersNormal(writer, request, store, feedback, members)
			return
		}
	default:
		writeFragmentStatus(writer, http.StatusBadRequest)
		return
	}
	if err := store.SetInsightFeedback(request.Context(), feedback); err != nil {
		server.logger.Warn("hide insight finding", "error", err)
		writeFragmentStatus(writer, http.StatusInternalServerError)
		return
	}
	server.recordControlPlaneAudit(request, "insights.finding.hide", summary)
	writer.Header().Set("HX-Trigger", "insightsChanged")
	writer.WriteHeader(http.StatusNoContent)
}

// markInsightMembersNormal records that each member of a rolled-up finding
// is normal, by the member's own identifier.
func (server *Server) markInsightMembersNormal(writer http.ResponseWriter, request *http.Request, store insightFeedbackStore, feedback insights.Feedback, members []string) {
	labels := request.Form["member_label"]
	marked := 0
	for index, member := range members {
		if !isRollupMember(member) {
			writeFragmentStatus(writer, http.StatusBadRequest)
			return
		}
		entry := feedback
		entry.FindingID, entry.Label = member, "Doesn't use Sable"
		if index < len(labels) {
			if label := strings.TrimSpace(labels[index]); label != "" {
				entry.Label += ": " + string([]rune(label)[:min(len([]rune(label)), maximumFeedbackLabel)])
			}
		}
		if err := store.SetInsightFeedback(request.Context(), entry); err != nil {
			server.logger.Warn("mark insight members normal", "error", err)
			writeFragmentStatus(writer, http.StatusInternalServerError)
			return
		}
		marked++
	}
	server.recordControlPlaneAudit(request, "insights.finding.hide", fmt.Sprintf("marked %d %s normal in finding %s", marked, insights.Plural(marked, "device", "devices"), feedback.FindingID))
	writer.Header().Set("HX-Trigger", "insightsChanged")
	writer.WriteHeader(http.StatusNoContent)
}

// showInsightFinding forgets that an operator hid a finding.
func (server *Server) showInsightFinding(writer http.ResponseWriter, request *http.Request) {
	store, ok := server.insightFeedbackRequest(writer, request)
	if !ok {
		return
	}
	id := request.FormValue("id")
	if err := store.DeleteInsightFeedback(request.Context(), id); err != nil {
		server.logger.Warn("show insight finding", "error", err)
		writeFragmentStatus(writer, http.StatusInternalServerError)
		return
	}
	server.recordControlPlaneAudit(request, "insights.finding.show", "showed finding "+id+" again")
	writer.Header().Set("HX-Trigger", "insightsChanged")
	writer.WriteHeader(http.StatusNoContent)
}

func (server *Server) insightFeedbackRequest(writer http.ResponseWriter, request *http.Request) (insightFeedbackStore, bool) {
	console := server.consoleView(request)
	if !console.CanWriteSettings || (!console.CanLogs && !console.CanBlocking) {
		server.authenticationFailure(writer, request, http.StatusForbidden, "")
		return nil, false
	}
	store, ok := server.queries.(insightFeedbackStore)
	if !ok {
		writeFragmentStatus(writer, http.StatusServiceUnavailable)
		return nil, false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumFormBytes)
	if err := request.ParseForm(); err != nil || strings.TrimSpace(request.FormValue("id")) == "" {
		writeFragmentStatus(writer, http.StatusBadRequest)
		return nil, false
	}
	return store, true
}

// insightHiddenViews lists the hidden findings with how long each stays
// hidden.
func insightHiddenViews(hidden []insights.Finding, feedback []insights.Feedback, display pages.TimeDisplay) []pages.InsightHiddenFindingView {
	byID := make(map[string]insights.Feedback, len(feedback))
	for _, entry := range feedback {
		byID[entry.FindingID] = entry
	}
	views := make([]pages.InsightHiddenFindingView, 0, len(hidden))
	for _, finding := range hidden {
		entry := byID[finding.ID]
		status := "Marked normal"
		if entry.Action == insights.FeedbackSnooze {
			status = "Hidden until " + pages.FormatShortDateTime(entry.Until, display, false)
		}
		views = append(views, pages.InsightHiddenFindingView{FindingID: finding.ID, Label: finding.Title + ": " + finding.Subject.Label, Status: status})
	}
	return views
}
