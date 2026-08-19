package web

import (
	"slices"
	"testing"
)

func TestPendingCertificateNamesFindsUncoveredNames(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		configured []string
		covered    []string
		want       []string
	}{
		{
			name:       "no certificate installed reports nothing",
			configured: []string{"dns.example.test"},
			want:       nil,
		},
		{
			name:       "fully covered reports nothing",
			configured: []string{"dns.example.test"},
			covered:    []string{"dns.example.test"},
			want:       []string{},
		},
		{
			name:       "newly added name is pending",
			configured: []string{"dns.example.test", "console.example.test"},
			covered:    []string{"dns.example.test"},
			want:       []string{"console.example.test"},
		},
		{
			// A trailing dot and a capital letter name the same host, so neither
			// should be reported as missing from the certificate.
			name:       "case and trailing dots do not create false positives",
			configured: []string{"DNS.example.test.", " dns.example.test "},
			covered:    []string{"dns.example.test"},
			want:       []string{},
		},
		{
			name:       "wildcard does not cover its own base name",
			configured: []string{"*.example.test", "example.test"},
			covered:    []string{"*.example.test"},
			want:       []string{"example.test"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := pendingCertificateNames(testCase.configured, testCase.covered)
			if !slices.Equal(got, testCase.want) {
				t.Fatalf("pendingCertificateNames() = %v, want %v", got, testCase.want)
			}
		})
	}
}
