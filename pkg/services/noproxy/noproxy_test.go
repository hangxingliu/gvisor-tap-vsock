package noproxy

import (
	"net"
	"strings"
	"testing"
)

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

func TestDefaultPolicyMatchesPackageFunctions(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "10.0.0.5:443", "localhost:3000", "8.8.8.8:53", "example.com:443", "[::1]:53"} {
		if got, want := Default().Bypass(addr), Bypass(addr); got != want {
			t.Errorf("Default().Bypass(%q) = %v, Bypass() = %v", addr, got, want)
		}
	}
	var nilPolicy *Policy
	if !nilPolicy.Bypass("127.0.0.1:80") || nilPolicy.Bypass("8.8.8.8:53") {
		t.Fatal("a nil policy must behave like Default()")
	}
}

func TestParsePolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		list string
		addr string
		want bool
	}{
		{"all", "*", "8.8.8.8:53", true},
		{"all hostname", "*", "example.com:443", true},
		{"ipv4 cidr", "10.0.0.0/8, 192.168.0.0/16", "192.168.1.1:22", true},
		{"ipv4 cidr miss", "10.0.0.0/8", "11.0.0.1:22", false},
		{"ipv6 cidr", "fc00::/7", "[fd00::1]:80", true},
		{"ipv4-mapped ipv6", "192.168.0.0/16", "[::ffff:192.168.0.1]:443", true},
		{"port match", "10.1.2.3/32:8080", "10.1.2.3:8080", true},
		{"port mismatch", "10.1.2.3/32:8080", "10.1.2.3:8081", false},
		{"port without dest port", "10.1.2.3/32:8080", "10.1.2.3", false},
		{"ipv6 port", "[::1/128]:8080", "[::1]:8080", true},
		{"ipv6 port mismatch", "[::1/128]:8080", "[::1]:53", false},
		{"empty list", "", "127.0.0.1:80", false},
		{"no hostnames", "127.0.0.0/8", "localhost:80", false},
	} {
		p, err := Parse(tc.list)
		if err != nil {
			t.Fatalf("%s: Parse(%q) error = %v", tc.name, tc.list, err)
		}
		if got := p.Bypass(tc.addr); got != tc.want {
			t.Errorf("%s: Parse(%q).Bypass(%q) = %v, want %v", tc.name, tc.list, tc.addr, got, tc.want)
		}
	}
}

func TestParseRejectsNonCanonicalItems(t *testing.T) {
	for _, list := range []string{
		"192.168.*",
		"example.com",
		"localhost",
		"10.1.2.3",
		"10.0.0.0/99",
		"10.1.2.3/32:0",
		"10.1.2.3/32:70000",
		"fc00::/7:80",
		"[::1/128]",
		"127.0.0.0/8,example.com",
	} {
		if _, err := Parse(list); err == nil {
			t.Errorf("Parse(%q) succeeded, want an error", list)
		} else if !strings.Contains(err.Error(), "invalid bypass item") {
			t.Errorf("Parse(%q) error = %v, want it to name the item", list, err)
		}
	}
}

func TestBypassIPPortZeroOnlyMatchesItemsWithoutPort(t *testing.T) {
	p, err := Parse("10.0.0.0/8,1.2.3.4/32:53")
	if err != nil {
		t.Fatal(err)
	}
	if !p.BypassIP(net.ParseIP("10.9.9.9"), 0) {
		t.Fatal("10.9.9.9 should bypass")
	}
	if p.BypassIP(net.ParseIP("1.2.3.4"), 0) {
		t.Fatal("an item with a port must not match port 0")
	}
	if !p.BypassIP(net.ParseIP("1.2.3.4"), 53) {
		t.Fatal("1.2.3.4:53 should bypass")
	}
}
