package noproxy

import "testing"

func TestBypass(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"127.53.1.2", true},
		{"10.0.0.5:443", true},
		{"172.16.0.1:80", true},
		{"172.31.255.255", true},
		{"192.168.1.10:22", true},
		{"169.254.169.254:80", true},
		{"100.64.0.1", true},
		{"0.0.0.0", true},
		{"[::1]:53", true},
		{"fe80::1", true},
		{"fd00::1234", true},
		{"[::ffff:192.168.0.1]:443", true},
		{"localhost:3000", true},
		{"LOCALHOST", true},
		{"foo.localhost:80", true},
		{"localhost.", true},

		{"8.8.8.8:53", false},
		{"1.1.1.1", false},
		{"172.32.0.1:80", false},
		{"192.169.0.1", false},
		{"example.com:443", false},
		{"notlocalhost", false},
		{"2606:4700:4700::1111", false},
		{"", false},
	} {
		if got := Bypass(tc.addr); got != tc.want {
			t.Errorf("Bypass(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
