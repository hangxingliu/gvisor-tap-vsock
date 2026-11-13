package dns

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/noproxy"
	mdns "github.com/miekg/dns"
)

func mustBypass(t *testing.T, list string) *noproxy.Policy {
	t.Helper()
	p, err := noproxy.Parse(list)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func noHostServers() []string { return nil }

func hostServers(servers ...string) func() []string {
	return func() []string { return servers }
}

func TestPlanUpstreams(t *testing.T) {
	socks := "socks5://127.0.0.1:1080"
	lan := mustBypass(t, "192.168.0.0/16")
	for _, tc := range []struct {
		name     string
		opts     UpstreamOptions
		host     func() []string
		mode     UpstreamMode
		fromHost bool
		want     []UpstreamInfo
	}{
		{name: "no proxy", opts: UpstreamOptions{}, host: hostServers("192.168.1.88:53"), mode: ModeSystem},
		{name: "http proxy without proxy DNS", opts: UpstreamOptions{Proxy: "http://127.0.0.1:8080"}, host: noHostServers, mode: ModeSystem},
		{name: "custom direct", opts: UpstreamOptions{DNSUpstreams: []string{"1.1.1.1"}}, host: noHostServers, mode: ModeDirect,
			want: []UpstreamInfo{{Address: "1.1.1.1:53"}}},
		{name: "proxied host servers", opts: UpstreamOptions{Proxy: socks, ProxyDNS: true, Bypass: lan}, host: hostServers("192.168.1.88:53", "8.8.8.8:53"),
			mode: ModeProxied, fromHost: true,
			want: []UpstreamInfo{{Address: "192.168.1.88:53"}, {Address: "8.8.8.8:53", Proxied: true}}},
		{name: "proxied fallback", opts: UpstreamOptions{Proxy: socks, ProxyDNS: true}, host: noHostServers,
			mode: ModeProxied, fromHost: true, want: []UpstreamInfo{{Address: "8.8.8.8:53", Proxied: true}}},
		{name: "proxied with empty bypass list", opts: UpstreamOptions{Proxy: socks, ProxyDNS: true, Bypass: mustBypass(t, "")},
			host: hostServers("192.168.1.88:53"), mode: ModeProxied, fromHost: true,
			want: []UpstreamInfo{{Address: "192.168.1.88:53", Proxied: true}}},
		{name: "strict keeps listed upstreams", opts: UpstreamOptions{Proxy: socks, Strict: true, Bypass: lan},
			host: hostServers("192.168.1.88:53", "8.8.8.8:53"), mode: ModeStrict, fromHost: true,
			want: []UpstreamInfo{{Address: "192.168.1.88:53"}, {Address: "8.8.8.8:53", Skipped: true}}},
		{name: "strict refuses without listed upstream", opts: UpstreamOptions{Proxy: socks, Strict: true, Bypass: lan, DNSUpstreams: []string{"8.8.8.8"}},
			host: noHostServers, mode: ModeRefused,
			want: []UpstreamInfo{{Address: "8.8.8.8:53", Skipped: true}}},
		{name: "strict without host servers", opts: UpstreamOptions{Proxy: socks, Strict: true}, host: noHostServers, mode: ModeRefused, fromHost: true},
		{name: "strict without proxy is ignored", opts: UpstreamOptions{Strict: true}, host: noHostServers, mode: ModeSystem},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := planUpstreams(tc.opts, tc.host)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Mode != tc.mode || plan.FromHost != tc.fromHost {
				t.Fatalf("plan = %+v, want mode %s fromHost %v", plan, tc.mode, tc.fromHost)
			}
			if len(plan.Upstreams) != len(tc.want) {
				t.Fatalf("upstreams = %+v, want %+v", plan.Upstreams, tc.want)
			}
			for i := range tc.want {
				if plan.Upstreams[i] != tc.want[i] {
					t.Fatalf("upstreams = %+v, want %+v", plan.Upstreams, tc.want)
				}
			}
			if plan.Describe() == "" {
				t.Fatal("empty description")
			}
		})
	}
}

func TestPlanUpstreamsRejectsProxyDNSOverHTTP(t *testing.T) {
	if _, err := planUpstreams(UpstreamOptions{Proxy: "http://127.0.0.1:8080", ProxyDNS: true}, noHostServers); err == nil {
		t.Fatal("ProxyDNS with an HTTP proxy must fail")
	}
}

func TestUpstreamPlanDescribe(t *testing.T) {
	plan := UpstreamPlan{Mode: ModeProxied, FromHost: true, Upstreams: []UpstreamInfo{
		{Address: "192.168.1.88:53"}, {Address: "8.8.8.8:53", Proxied: true},
	}}
	want := "upstreams from /etc/resolv.conf: 192.168.1.88:53 (direct, in bypass list), 8.8.8.8:53 (via proxy)"
	if got := plan.Describe(); got != want {
		t.Fatalf("Describe() = %q, want %q", got, want)
	}
	refused := UpstreamPlan{Mode: ModeRefused, Upstreams: []UpstreamInfo{{Address: "8.8.8.8:53", Skipped: true}}}
	if got := refused.Describe(); !strings.Contains(got, "REFUSED") || !strings.Contains(got, "--dns") {
		t.Fatalf("Describe() = %q", got)
	}
}

func TestStrictModeRefusesWithoutListedUpstream(t *testing.T) {
	spec, err := buildUpstreamSpecWith(UpstreamOptions{
		Proxy: "socks5://127.0.0.1:1", Strict: true, Bypass: mustBypass(t, "192.168.0.0/16"),
	}, hostServers("8.8.8.8:53"))
	if err != nil {
		t.Fatal(err)
	}
	server := newWithSpec(nil, nil, nil, spec)
	for _, qtype := range []uint16{mdns.TypeA, mdns.TypeSOA} {
		if got := ask(server, qtype); got.Rcode != mdns.RcodeRefused {
			t.Fatalf("qtype %d rcode = %d, want REFUSED", qtype, got.Rcode)
		}
	}
}

func TestStrictModeQueriesListedUpstreamDirectly(t *testing.T) {
	addr, done := listenFixtureDNS(t, "udp")
	defer done()
	var proxyDials atomic.Int32
	proxyURL, doneProxy := startSocks5ConnectServer(t, &proxyDials, addr)
	defer doneProxy()

	server, err := New(nil, nil, nil, UpstreamOptions{
		Proxy: proxyURL, Strict: true, Bypass: mustBypass(t, "127.0.0.0/8"),
		DNSUpstreams: []string{"8.8.8.8", addr},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := server.handler.nameservers; len(got) != 1 || got[0] != addr {
		t.Fatalf("nameservers = %v, want only %s", got, addr)
	}
	a := ask(server, mdns.TypeA)
	if len(a.Answer) == 0 {
		t.Fatalf("A answer empty rcode %d", a.Rcode)
	}
	if rec, ok := a.Answer[0].(*mdns.A); !ok || !rec.A.Equal(net.ParseIP("203.0.113.10")) {
		t.Fatalf("A answer = %v", a.Answer)
	}
	if n := proxyDials.Load(); n != 0 {
		t.Fatalf("strict mode contacted the proxy %d times", n)
	}
}

func TestProxiedDNSFailureIsServfail(t *testing.T) {
	// Nothing listens on this port, so the SOCKS5 dial fails.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := "socks5://" + ln.Addr().String()
	ln.Close()

	server, err := New(nil, nil, nil, UpstreamOptions{
		Proxy: proxyURL, ProxyDNS: true, Bypass: mustBypass(t, ""), DNSUpstreams: []string{"8.8.8.8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, qtype := range []uint16{mdns.TypeA, mdns.TypeTXT, mdns.TypeSOA} {
		if got := ask(server, qtype); got.Rcode != mdns.RcodeServerFailure {
			t.Fatalf("qtype %d rcode = %d, want SERVFAIL", qtype, got.Rcode)
		}
	}
}

func TestHangingProxyIsServfailBeforeTheGuestGivesUp(t *testing.T) {
	// The proxy accepts connections and never answers.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()

	server, err := New(nil, nil, nil, UpstreamOptions{
		Proxy: "socks5://" + ln.Addr().String(), ProxyDNS: true, Bypass: mustBypass(t, ""), DNSUpstreams: []string{"8.8.8.8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if got := ask(server, mdns.TypeA); got.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", got.Rcode)
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("SERVFAIL took %v; a guest resolver gives up after 5s", elapsed)
	}
}

func TestProxiedDNSFollowsTheBypassList(t *testing.T) {
	// With an empty bypass list even a loopback upstream goes through the
	// proxy.
	dnsAddr, doneDNS := listenFixtureDNS(t, "tcp")
	defer doneDNS()
	var proxyDials atomic.Int32
	proxyURL, doneProxy := startSocks5ConnectServer(t, &proxyDials, dnsAddr)
	defer doneProxy()

	server, err := New(nil, nil, nil, UpstreamOptions{
		Proxy: proxyURL, ProxyDNS: true, Bypass: mustBypass(t, ""), DNSUpstreams: []string{dnsAddr},
	})
	if err != nil {
		t.Fatal(err)
	}
	if a := ask(server, mdns.TypeA); len(a.Answer) == 0 {
		t.Fatalf("A answer empty rcode %d", a.Rcode)
	}
	if proxyDials.Load() == 0 {
		t.Fatal("the proxy was not used for an upstream outside the bypass list")
	}
}

func TestNoProxyDNSUsesHostResolver(t *testing.T) {
	server, err := New(nil, nil, nil, UpstreamOptions{Proxy: "socks5://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if server.handler.dialNameserver != nil {
		t.Fatal("DNS must not use the proxy without ProxyDNS")
	}
	if _, ok := server.handler.upstream.(*net.Resolver); !ok {
		t.Fatalf("upstream = %T, want the host resolver", server.handler.upstream)
	}
}
