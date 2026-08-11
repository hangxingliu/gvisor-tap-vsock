// Package noproxy implements a fixed, built-in NO_PROXY policy.
//
// When an HTTP/SOCKS proxy is configured, every outbound connection is
// normally tunnelled through it.  That breaks traffic aimed at the local
// machine or at the LAN, which the proxy usually cannot reach.  The
// destinations listed here are therefore always dialled directly.
package noproxy

import (
	"net"
	"strings"
)

// bypassCIDRs are the destination networks that are always dialled directly,
// even when a proxy is configured: loopback, RFC1918 private ranges,
// link-local, CGNAT and multicast/reserved space.
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

// bypassHosts are hostnames (matched case-insensitively, also as a domain
// suffix) that are always dialled directly.
var bypassHosts = []string{
	"localhost",
	"localhost.localdomain",
}

var bypassNets = func() []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(bypassCIDRs))
	for _, cidr := range bypassCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		nets = append(nets, n)
	}
	return nets
}()

// Bypass reports whether addr must be dialled directly, ignoring any
// configured proxy.  addr may be a bare host/IP or a "host:port" pair.
func Bypass(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}

	if ip := net.ParseIP(host); ip != nil {
		return BypassIP(ip)
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range bypassHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// BypassIP reports whether ip must be dialled directly, ignoring any
// configured proxy.
func BypassIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// An IPv4-mapped IPv6 address must be checked against the IPv4 rules.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range bypassNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
