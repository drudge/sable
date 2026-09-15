package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteFragmentStatus(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		marker string
	}{
		{name: "unprocessable", status: http.StatusUnprocessableEntity, marker: "true"},
		{name: "forbidden", status: http.StatusForbidden, marker: "true"},
		{name: "success", status: http.StatusOK, marker: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeFragmentStatus(response, test.status)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
			if got := response.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Fatalf("content type = %q, want HTML", got)
			}
			if got := response.Header().Get(consoleFragmentHeader); got != test.marker {
				t.Fatalf("fragment marker = %q, want %q", got, test.marker)
			}
		})
	}
}
