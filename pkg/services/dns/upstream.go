package dns

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/containers/gvisor-tap-vsock/pkg/services/netproxy"
	"github.com/containers/gvisor-tap-vsock/pkg/services/noproxy"
)

// UpstreamOptions configures where the gateway forwards DNS queries.
type UpstreamOptions struct {
	// Proxy is the outbound proxy URL, or empty.
	Proxy string
	// ProxyDNS sends queries for upstreams outside Bypass through Proxy. Only
	// socks5:// proxies can carry DNS; with an http:// or https:// proxy it is
	// an error.
	ProxyDNS bool
	// Strict, with a Proxy and without ProxyDNS, only uses upstreams in
	// Bypass. The host system resolver is never used then.
	Strict bool
	// Bypass lists the upstreams that are queried directly. nil means
	// noproxy.Default().
	Bypass *noproxy.Policy
	// DNSUpstreams replaces the host's nameservers (/etc/resolv.conf). A
	// missing port means 53.
	DNSUpstreams []string
}

// UpstreamMode says how forwarded queries leave the gateway.
type UpstreamMode string

const (
	// ModeSystem uses the host system resolver, not proxied.
	ModeSystem UpstreamMode = "system"
	// ModeDirect queries the listed upstreams directly, not proxied.
	ModeDirect UpstreamMode = "direct"
	// ModeProxied queries each upstream through the proxy unless it is in
	// the bypass list.
	ModeProxied UpstreamMode = "proxied"
	// ModeStrict only queries upstreams in the bypass list, directly.
	ModeStrict UpstreamMode = "strict"
	// ModeRefused has no usable upstream; every forwarded query is answered
	// with REFUSED.
	ModeRefused UpstreamMode = "refused"
)

// UpstreamInfo describes one upstream nameserver.
type UpstreamInfo struct {
	Address string
	// Proxied is true when queries go through the proxy.
	Proxied bool
	// Skipped is true when strict mode does not use this upstream.
	Skipped bool
}

// UpstreamPlan is the resolved upstream configuration.
type UpstreamPlan struct {
	Mode      UpstreamMode
	Upstreams []UpstreamInfo
	// FromHost is true when the upstreams come from /etc/resolv.conf rather
	// than DNSUpstreams.
	FromHost bool
}

// Describe returns a one-line, human-readable summary of the upstream plan.
func (p UpstreamPlan) Describe() string {
	source := "--dns"
	if p.FromHost {
		source = "/etc/resolv.conf"
	}
	switch p.Mode {
	case ModeSystem:
		return "host system resolver (direct, not proxied)"
	case ModeRefused:
		return fmt.Sprintf("no upstream from %s is in the bypass list (%s); every query is answered with REFUSED", source, p.list())
	default:
		return fmt.Sprintf("upstreams from %s: %s", source, p.list())
	}
}

func (p UpstreamPlan) list() string {
	parts := make([]string, 0, len(p.Upstreams))
	for _, u := range p.Upstreams {
		switch {
		case u.Skipped:
			parts = append(parts, u.Address+" (skipped, not in bypass list)")
		case u.Proxied:
			parts = append(parts, u.Address+" (via proxy)")
		case p.Mode == ModeProxied || p.Mode == ModeStrict:
			parts = append(parts, u.Address+" (direct, in bypass list)")
		default:
			parts = append(parts, u.Address+" (direct)")
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// PlanUpstreams resolves opts into an UpstreamPlan. It reads the host's
// /etc/resolv.conf when no DNSUpstreams are given and the upstream plan needs the
// nameserver list.
func PlanUpstreams(opts UpstreamOptions) (UpstreamPlan, error) {
	return planUpstreams(opts, hostNameservers)
}

func planUpstreams(opts UpstreamOptions, hostServers func() []string) (UpstreamPlan, error) {
	upstreams := normalizeDNSAddrs(opts.DNSUpstreams)
	_, socks := socks5ProxyURL(opts.Proxy)
	if opts.ProxyDNS && opts.Proxy != "" && !socks {
		return UpstreamPlan{}, fmt.Errorf("DNS can only be sent through a socks5:// proxy")
	}
	proxied := opts.ProxyDNS && socks
	strict := !proxied && opts.Strict && opts.Proxy != ""

	if !proxied && !strict {
		// Not proxied: the host resolves directly, as without a proxy.
		if len(upstreams) == 0 {
			return UpstreamPlan{Mode: ModeSystem}, nil
		}
		plan := UpstreamPlan{Mode: ModeDirect}
		for _, ns := range upstreams {
			plan.Upstreams = append(plan.Upstreams, UpstreamInfo{Address: ns})
		}
		return plan, nil
	}

	plan := UpstreamPlan{}
	nameservers := upstreams
	if len(nameservers) == 0 {
		plan.FromHost = true
		nameservers = hostServers()
		if len(nameservers) == 0 && proxied {
			nameservers = []string{"8.8.8.8:53"}
		}
	}

	if proxied {
		plan.Mode = ModeProxied
		for _, ns := range nameservers {
			plan.Upstreams = append(plan.Upstreams, UpstreamInfo{Address: ns, Proxied: !opts.Bypass.Bypass(ns)})
		}
		return plan, nil
	}

	plan.Mode = ModeRefused
	for _, ns := range nameservers {
		inList := opts.Bypass.Bypass(ns)
		plan.Upstreams = append(plan.Upstreams, UpstreamInfo{Address: ns, Skipped: !inList})
		if inList {
			plan.Mode = ModeStrict
		}
	}
	return plan, nil
}

// upstreamSpec describes how forwarded DNS queries leave the gateway.
// customized is false when the caller asked for the stock host resolver.
type upstreamSpec struct {
	resolver       *net.Resolver
	nameservers    []string
	dialNameserver func(ctx context.Context, network, address string) (net.Conn, error)
	customized     bool
	// refuseAll answers every forwarded query with REFUSED.
	refuseAll bool
}

// buildUpstreamSpec chooses the resolver and the nameserver list.
//
// The pure-Go resolver still reads /etc/resolv.conf for the server list and
// then calls Dial with those addresses. To honor DNSUpstreams (and to send
// the system resolvers through a SOCKS5 proxy), Dial ignores the address the
// resolver picked and dials our list instead.
//
// A proxied upstream that cannot be reached (the proxy is down, refuses the
// request, or the upstream times out) makes the query fail. There is no
// fallback to a direct dial or to the host system resolver.
func buildUpstreamSpec(opts UpstreamOptions) (upstreamSpec, error) {
	return buildUpstreamSpecWith(opts, hostNameservers)
}

func buildUpstreamSpecWith(opts UpstreamOptions, hostServers func() []string) (upstreamSpec, error) {
	plan, err := planUpstreams(opts, hostServers)
	if err != nil {
		return upstreamSpec{}, err
	}
	switch plan.Mode {
	case ModeSystem:
		return upstreamSpec{}, nil
	case ModeRefused:
		return upstreamSpec{customized: true, refuseAll: true}, nil
	}

	socksURL, _ := socks5ProxyURL(opts.Proxy)
	nameservers := make([]string, 0, len(plan.Upstreams))
	proxiedNS := map[string]bool{}
	for _, u := range plan.Upstreams {
		if u.Skipped {
			continue
		}
		nameservers = append(nameservers, u.Address)
		proxiedNS[u.Address] = u.Proxied
	}

	dialOne := func(ctx context.Context, network, address string) (net.Conn, error) {
		if proxiedNS[address] {
			// SOCKS5 UDP associate is a poor fit for short DNS queries.
			// DNS-over-TCP is a stream, which every SOCKS5 proxy can carry.
			// Returning a non-PacketConn makes net.Resolver write the TCP
			// length prefix, and makes miekg/dns do the same.
			return netproxy.DialSOCKS5(ctx, socksURL, "tcp", address)
		}
		if network != "tcp" {
			network = "udp"
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var lastErr error
			for _, ns := range nameservers {
				conn, err := dialOne(ctx, network, ns)
				if err != nil {
					lastErr = fmt.Errorf("dial %s: %w", ns, err)
					continue
				}
				return conn, nil
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("no upstream DNS server")
			}
			return nil, lastErr
		},
	}

	spec := upstreamSpec{
		resolver:    resolver,
		nameservers: nameservers,
		customized:  true,
	}
	// Raw queries (SOA, PTR, AAAA, ...) go through the same dialer when a
	// proxy or the strict bypass filter applies. Custom upstreams without a
	// proxy are dialled directly by dns.Client, using nameservers.
	if plan.Mode == ModeProxied || plan.Mode == ModeStrict {
		spec.dialNameserver = dialOne
	}
	return spec, nil
}

// normalizeDNSAddrs returns host:port addresses. A missing port becomes 53.
// Empty entries are dropped. The input slice is not modified.
func normalizeDNSAddrs(addrs []string) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(addr); err == nil {
			out = append(out, addr)
			continue
		}
		out = append(out, net.JoinHostPort(strings.Trim(addr, "[]"), "53"))
	}
	return out
}

// socks5ProxyURL reports the proxy string when it is a socks5 URL.
// Other schemes, an empty string, and unparseable URLs are not SOCKS5.
func socks5ProxyURL(proxy string) (string, bool) {
	if proxy == "" {
		return "", false
	}
	u, err := url.Parse(proxy)
	if err != nil || !strings.EqualFold(u.Scheme, "socks5") || u.Host == "" {
		return "", false
	}
	return proxy, true
}
