package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMigrationSourceChecksApplicationStatusAndBearerAuthentication(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		fail       bool
	}{
		{"success", `{"status":"ok"}`, 200, false},
		{"application failure", `{"status":"error","errorMessage":"transfer denied"}`, 200, true},
		{"expired session", `{"status":"invalid-token"}`, 200, true},
		{"HTTP failure", `{"status":"ok"}`, 500, true},
		{"invalid JSON", `<html>login</html>`, 200, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer fixture-token" || r.Method != http.MethodPost || r.FormValue("zone") != "member.test" {
					t.Error("source request lost authentication or form")
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer endpoint.Close()
			source := migrationSource{url: endpoint.URL, token: "fixture-token", client: endpoint.Client()}
			err := source.call(context.Background(), "/api/zones/options/set", url.Values{"zone": {"member.test"}}, nil)
			if (err != nil) != test.fail {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestMigrationRequestRetainsFailureStatusWithoutHTMX(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			return
		}
		if r.Header.Get("HX-Request") != "" {
			t.Error("HTMX would mask zone validation status")
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte("final synchronization failed"))
	}))
	defer endpoint.Close()
	lab := migrationLab{}
	status, body, err := lab.request(context.Background(), newConsole(endpoint.URL), http.MethodPost, "/api/v1/zones/convert-primary", url.Values{"zone": {"member.test"}})
	if err != nil || status != 422 || !strings.Contains(string(body), "failed") {
		t.Fatalf("status=%d body=%s err=%v", status, body, err)
	}
}
