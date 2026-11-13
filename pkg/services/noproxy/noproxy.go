// Package noproxy decides which destinations are dialled directly even when an
// HTTP or SOCKS proxy is configured (a NO_PROXY policy).
//
// When a proxy is configured, outbound connections are normally tunnelled
// through it. A Policy lists the destinations that skip the proxy. Default
// returns the built-in policy (loopback, private ranges, link-local, and so
// on). Parse builds a policy from a canonical list of CIDRs.
package noproxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// bypassCIDRs are the destination networks of the built-in policy:
// loopback, RFC1918 private ranges, link-local, CGNAT, and multicast or
// reserved space.
//
// The built-in CIDRs and hostnames are a stable contract.
var bypassCIDRs = []string{
	"0.0.0.0/8",          // "this host on this network"
	"10.0.0.0/8",         // RFC1918 private
	"127.0.0.0/8",        // IPv4 loopback
	"169.254.0.0/16",     // IPv4 link-local
	"172.16.0.0/12",      // RFC1918 private
	"192.168.0.0/16",     // RFC1918 private
	"100.64.0.0/10",      // RFC6598 carrier-grade NAT
	"192.0.0.0/24",       // IETF protocol assignments
	"198.18.0.0/15",      // benchmarking
	"224.0.0.0/4",        // multicast
	"255.255.255.255/32", // broadcast
	"::1/128",            // IPv6 loopback
	"fc00::/7",           // IPv6 unique local
	"fe80::/10",          // IPv6 link-local
	"ff00::/8",           // IPv6 multicast
}

// bypassHosts are hostnames of the built-in policy (matched
// case-insensitively, also as a domain suffix).
var bypassHosts = []string{
	"localhost",
	"localhost.localdomain",
}

// portNet is a network that is bypassed only for one destination port.
type portNet struct {
	net  *net.IPNet
	port uint16
}

// Policy is a set of destinations that are dialled directly.
// A nil *Policy behaves like Default().
type Policy struct {
	all      bool
	nets     []*net.IPNet
	portNets []portNet
	hosts    []string
}

var defaultPolicy = func() *Policy {
	p := &Policy{hosts: bypassHosts}
	for _, cidr := range bypassCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("noproxy: invalid built-in CIDR %q: %v", cidr, err))
		}
		p.nets = append(p.nets, n)
	}
	return p
}()

// Default returns the built-in policy. The returned value must not be
// modified.
func Default() *Policy {
	return defaultPolicy
}

// Parse builds a policy from a comma-separated canonical list. Each item is
// one of:
//
//	"*"            every destination
//	CIDR           for example 10.0.0.0/8 or ::1/128
//	CIDR:port      an IPv4 CIDR for one port, for example 10.1.2.3/32:8080
//	[CIDR]:port    an IPv6 CIDR for one port, for example [::1/128]:8080
//
// Spaces around items are ignored. An empty string gives an empty policy that
// bypasses nothing. Hostnames, bare IPs, and wildcards such as 192.168.* are
// rejected: callers convert user input to this form first.
func Parse(list string) (*Policy, error) {
	p := &Policy{}
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if item == "*" {
			p.all = true
			continue
		}
		n, port, err := parseItem(item)
		if err != nil {
			return nil, fmt.Errorf("invalid bypass item %q: %w", item, err)
		}
		if port == 0 {
			p.nets = append(p.nets, n)
		} else {
			p.portNets = append(p.portNets, portNet{net: n, port: port})
		}
	}
	return p, nil
}

func parseItem(item string) (*net.IPNet, uint16, error) {
	if rest, ok := strings.CutPrefix(item, "["); ok {
		cidr, portText, ok := strings.Cut(rest, "]:")
		if !ok {
			return nil, 0, fmt.Errorf("expected [CIDR]:port")
		}
		n, err := parseCIDR(cidr)
		if err != nil {
			return nil, 0, err
		}
		port, err := parsePort(portText)
		if err != nil {
			return nil, 0, err
		}
		return n, port, nil
	}
	if n, err := parseCIDR(item); err == nil {
		return n, 0, nil
	}
	idx := strings.LastIndex(item, ":")
	if idx < 0 {
		return nil, 0, fmt.Errorf("expected *, CIDR, CIDR:port, or [CIDR]:port")
	}
	n, err := parseCIDR(item[:idx])
	if err != nil {
		return nil, 0, err
	}
	if n.IP.To4() == nil {
		return nil, 0, fmt.Errorf("an IPv6 CIDR with a port must be written as [CIDR]:port")
	}
	port, err := parsePort(item[idx+1:])
	if err != nil {
		return nil, 0, err
	}
	return n, port, nil
}

func parseCIDR(s string) (*net.IPNet, error) {
	if !strings.Contains(s, "/") {
		return nil, fmt.Errorf("%q is not a CIDR", s)
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return n, nil
}

func parsePort(s string) (uint16, error) {
	port, err := strconv.ParseUint(s, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(port), nil
}

// Bypass reports whether addr must be dialled directly. addr may be a bare
// host or IP, or a "host:port" pair. Items with a port only match an addr
// with the same port.
func (p *Policy) Bypass(addr string) bool {
	if p == nil {
		p = defaultPolicy
	}
	host := addr
	var port uint16
	if h, portText, err := net.SplitHostPort(addr); err == nil {
		host = h
		if n, err := strconv.ParseUint(portText, 10, 16); err == nil {
			port = uint16(n)
		}
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	if p.all {
		return true
	}

	if ip := net.ParseIP(host); ip != nil {
		return p.BypassIP(ip, port)
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range p.hosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// BypassIP reports whether ip must be dialled directly. port 0 means the port
// is unknown (ICMP, for example); then only items without a port match.
func (p *Policy) BypassIP(ip net.IP, port uint16) bool {
	if p == nil {
		p = defaultPolicy
	}
	if ip == nil {
		return false
	}
	if p.all {
		return true
	}
	// An IPv4-mapped IPv6 address must be checked against the IPv4 rules.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range p.nets {
		if n.Contains(ip) {
			return true
		}
	}
	if port == 0 {
		return false
	}
	for _, pn := range p.portNets {
		if pn.port == port && pn.net.Contains(ip) {
			return true
		}
	}
	return false
}

// Bypass reports whether addr must be dialled directly under the built-in
// policy.
func Bypass(addr string) bool {
	return defaultPolicy.Bypass(addr)
}

// BypassIP reports whether ip must be dialled directly under the built-in
// policy.
func BypassIP(ip net.IP) bool {
	return defaultPolicy.BypassIP(ip, 0)
}
