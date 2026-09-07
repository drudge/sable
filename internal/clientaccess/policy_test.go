package clientaccess

import "testing"

func TestRecursionAccess(t *testing.T) {
	for _, test := range []struct {
		mode, client string
		allowed      bool
	}{
		{"", "192.0.2.1", false}, {"", "10.2.3.4", true}, {"private", "127.0.0.1", true},
		{"private", "::1", true}, {"private", "fd12::1", true}, {"private", "2001:db8::1", false},
		{"private", "fe80::1%en0", true}, {"private", "::ffff:192.168.1.2", true},
		{"allow", "192.0.2.1", true}, {"allow", "", false}, {"allow", "invalid", false},
		{"deny", "127.0.0.1", false}, {"acl", "192.0.2.9", true}, {"acl", "192.0.3.1", false},
		{"acl", "::ffff:192.0.2.9", true}, {"acl", "2001:db8::1", true}, {"acl", "2001:db9::1", false},
	} {
		t.Run(test.mode+"/"+test.client, func(t *testing.T) {
			policy, err := Compile(test.mode, []string{"::ffff:192.0.2.0/120", "2001:db8::/32"})
			if err != nil {
				t.Fatal(err)
			}
			if got := policy.Allows(test.client); got != test.allowed {
				t.Fatalf("allowed=%v", got)
			}
		})
	}
	policy, _ := Compile("acl", nil)
	if policy.Allows("127.0.0.1") {
		t.Fatal("empty ACL permits recursion")
	}
	for _, test := range []struct {
		mode    string
		clients []string
	}{
		{"unexpected", nil}, {"acl", []string{"not-an-ip"}}, {"acl", []string{"fe80::1%en0"}}, {"acl", []string{"::ffff:192.0.2.1/64"}},
	} {
		if _, err := Compile(test.mode, test.clients); err == nil {
			t.Fatalf("accepted %+v", test)
		}
	}
}
