package auth

import "testing"

func TestCheckOriginTable(t *testing.T) {
	t.Parallel()
	allow := []string{"https://ui.lab.test"}
	cases := []struct {
		name, origin string
		extra        []string
		ok           bool
	}{
		{name: "missing", origin: "", ok: true},
		{name: "loopback-http", origin: "http://127.0.0.1:8088", ok: true},
		{name: "loopback-localhost", origin: "http://localhost:8088", ok: true},
		{name: "evil", origin: "https://evil.example", ok: false},
		{name: "file-loopback", origin: "file://localhost", ok: false},
		{name: "allowlist-hit", origin: "https://ui.lab.test", extra: allow, ok: true},
		{name: "allowlist-miss", origin: "https://other.example", extra: allow, ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckOrigin(tc.origin, tc.extra)
			if tc.ok && err != nil {
				t.Fatalf("denied: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("allowed")
			}
		})
	}
}
