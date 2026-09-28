package web

import (
	"slices"
	"strings"
	"testing"
)

// A development tool's script hashes are the only sources the environment can
// add to the policy. Without them the policy allows no inline script.
func TestContentSecurityPolicyAddsOnlyDevelopmentScriptHashes(t *testing.T) {
	t.Parallel()
	const air = "sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng="
	// Anything that isn't exactly a hash is dropped, including a hash with
	// more policy smuggled after it.
	for value, want := range map[string][]string{
		"":                                  nil,
		air:                                 {air},
		air + ", " + air:                    {air},
		" " + air + "\n":                    {air},
		"'unsafe-inline'":                   nil,
		air + "; script-src *":              nil,
		"sha256-short=":                     nil,
		"sha384-" + strings.Repeat("A", 64): nil,
	} {
		if got := scriptHashSources(value); !slices.Equal(got, want) {
			t.Errorf("scriptHashSources(%q) = %v, want %v", value, got, want)
		}
	}
	if policy := buildContentSecurityPolicy(nil, []string{air}); !strings.Contains(policy, "script-src 'self' '"+air+"';") {
		t.Fatalf("policy with a development script = %s", policy)
	}
	if policy := buildContentSecurityPolicy(nil, nil); !strings.Contains(policy, "script-src 'self';") {
		t.Fatalf("policy without one = %s", policy)
	}
}
