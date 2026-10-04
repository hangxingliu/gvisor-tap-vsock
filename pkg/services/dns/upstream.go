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

// upstreamSpec describes how forwarded DNS queries leave the gateway.
// customized is false when the caller asked for the stock host resolver.
type upstreamSpec struct {
	resolver       *net.Resolver
	nameservers    []string
	dialNameserver func(ctx context.Context, network, address string) (net.Conn, error)
	customized     bool
}

// buildUpstreamSpec chooses the resolver and the nameserver list.
//
// The pure-Go resolver still reads /etc/resolv.conf for the server list and
// then calls Dial with those addresses. To honor DNSUpstreams (and to send
// the system resolvers through a SOCKS5 proxy), Dial ignores the address the
// resolver picked and dials our list instead.
func buildUpstreamSpec(proxy string, dnsUpstreams []string) upstreamSpec {
	upstreams := normalizeDNSAddrs(dnsUpstreams)
	socksURL, socks := socks5ProxyURL(proxy)
	if !socks && len(upstreams) == 0 {
		return upstreamSpec{}
	}

	nameservers := upstreams
	if len(nameservers) == 0 {
		// No custom upstreams: keep the host's resolvers, but carry them
		// through the proxy when they are not on the local network.
		nameservers = hostNameservers()
		if len(nameservers) == 0 {
			nameservers = []string{"8.8.8.8:53"}
		}
	}

	dialOne := func(ctx context.Context, network, address string) (net.Conn, error) {
		if socks && !noproxy.Bypass(address) {
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
	// Raw queries (SOA, PTR, AAAA, ...) go through the same dialer only when
	// a proxy has to be applied. Custom upstreams without a proxy are dialled
	// directly by dns.Client, using nameservers.
	if socks {
		spec.dialNameserver = dialOne
	}
	return spec
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
// HTTP proxies cannot carry DNS and are intentionally ignored.
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
