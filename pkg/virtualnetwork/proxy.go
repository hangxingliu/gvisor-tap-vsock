package virtualnetwork

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/containers/gvisor-tap-vsock/pkg/services/dns"
	"github.com/containers/gvisor-tap-vsock/pkg/services/netproxy"
	"github.com/containers/gvisor-tap-vsock/pkg/services/noproxy"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
)

// ProxySettings derives the forwarder and DNS proxy options from
// configuration. The bypass list is parsed once and shared by both.
func ProxySettings(configuration *types.Configuration) (netproxy.Options, dns.UpstreamOptions, error) {
	policy := noproxy.Default()
	if configuration.ProxyBypass != nil {
		parsed, err := noproxy.Parse(*configuration.ProxyBypass)
		if err != nil {
			return netproxy.Options{}, dns.UpstreamOptions{}, fmt.Errorf("proxy bypass list: %w", err)
		}
		policy = parsed
	}
	opts := netproxy.Options{
		Proxy:    configuration.Proxy,
		ProxyUDP: configuration.ProxyUDP,
		Strict:   configuration.StrictProxy,
		Bypass:   policy,
	}
	upstream := dns.UpstreamOptions{
		Proxy:        configuration.Proxy,
		ProxyDNS:     !configuration.NoProxyDNS && isSOCKS5(configuration.Proxy),
		Strict:       configuration.StrictProxy,
		Bypass:       policy,
		DNSUpstreams: configuration.DNSUpstreams,
	}
	return opts, upstream, nil
}

func isSOCKS5(proxy string) bool {
	u, err := url.Parse(proxy)
	return err == nil && strings.EqualFold(u.Scheme, "socks5") && u.Host != ""
}
