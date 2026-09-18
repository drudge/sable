package web

import (
	"net/http"
	"testing"
)

func TestRequestShowFullRecordNames(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "default", want: false},
		{name: "relative", value: "false", want: false},
		{name: "full", value: "true", want: true},
		{name: "invalid", value: "yes", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, "/zones", nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.value != "" {
				request.AddCookie(&http.Cookie{Name: fullRecordNamesCookie, Value: test.value})
			}
			if got := requestShowFullRecordNames(request); got != test.want {
				t.Fatalf("requestShowFullRecordNames() = %t, want %t", got, test.want)
			}
		})
	}
}
