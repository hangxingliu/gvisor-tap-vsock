package virtualnetwork

import (
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
)

func TestProxySettings(t *testing.T) {
	empty := ""
	bad := "example.com"
	for _, tc := range []struct {
		name         string
		config       types.Configuration
		wantDNS      bool
		wantBypassLo bool
		wantErr      bool
	}{
		{name: "socks5 defaults", config: types.Configuration{Proxy: "socks5://127.0.0.1:1080"}, wantDNS: true, wantBypassLo: true},
		{name: "socks5 without DNS", config: types.Configuration{Proxy: "socks5://127.0.0.1:1080", NoProxyDNS: true}, wantBypassLo: true},
		{name: "http never carries DNS", config: types.Configuration{Proxy: "http://127.0.0.1:8080"}, wantBypassLo: true},
		{name: "empty bypass list", config: types.Configuration{Proxy: "socks5://127.0.0.1:1080", ProxyBypass: &empty}, wantDNS: true},
		{name: "invalid bypass list", config: types.Configuration{ProxyBypass: &bad}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, upstream, err := ProxySettings(&tc.config)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if upstream.ProxyDNS != tc.wantDNS {
				t.Fatalf("ProxyDNS = %v, want %v", upstream.ProxyDNS, tc.wantDNS)
			}
			if got := opts.Bypasses("127.0.0.1:80"); got != tc.wantBypassLo {
				t.Fatalf("Bypasses(loopback) = %v, want %v", got, tc.wantBypassLo)
			}
			if opts.Bypass != upstream.Bypass {
				t.Fatal("forwarders and DNS must share one bypass policy")
			}
		})
	}
}
