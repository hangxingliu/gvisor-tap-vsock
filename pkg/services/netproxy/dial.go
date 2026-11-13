// Package netproxy dials TCP and UDP destinations either directly or through
// an HTTP CONNECT or SOCKS5 proxy.
//
// An empty proxy URL, and any destination covered by the NO_PROXY policy, is
// always dialled directly. The direct path is what upstream gvisor-tap-vsock
// does when no proxy is configured.
package netproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/noproxy"
	socks5 "github.com/txthinking/socks5"
)

// ErrNotProxied is returned in strict mode for traffic that cannot be carried
// by the proxy and is not covered by the NO_PROXY policy. Callers drop it.
var ErrNotProxied = errors.New("strict proxy mode: traffic cannot be sent through the proxy")

// Options configures how outbound guest traffic leaves the host.
type Options struct {
	// Proxy is an http://, https://, or socks5:// URL. Empty means direct.
	Proxy string
	// ProxyUDP sends UDP through a socks5:// Proxy.
	ProxyUDP bool
	// Strict drops traffic that cannot be sent through Proxy instead of
	// sending it directly. Destinations in Bypass are still dialled directly.
	Strict bool
	// Bypass lists the destinations that are dialled directly. nil means
	// noproxy.Default().
	Bypass *noproxy.Policy
}

// Bypasses reports whether dest ("host:port") is dialled directly because no
// proxy is set or the NO_PROXY policy covers it.
func (o Options) Bypasses(dest string) bool {
	return o.Proxy == "" || o.Bypass.Bypass(dest)
}

// BypassesIP is Bypasses for a destination without a port (ICMP).
func (o Options) BypassesIP(ip net.IP) bool {
	return o.Proxy == "" || o.Bypass.BypassIP(ip, 0)
}

// CarriesUDP reports whether UDP can be sent through Proxy.
func (o Options) CarriesUDP() bool {
	return o.ProxyUDP && isSOCKS5(o.Proxy)
}

// DropsUDP reports whether UDP to dest is dropped: strict mode, a proxy that
// cannot carry UDP, and a destination outside the NO_PROXY policy.
func (o Options) DropsUDP(dest string) bool {
	return o.Strict && !o.Bypasses(dest) && !o.CarriesUDP()
}

// DropsICMP reports whether an ICMP echo to ip is dropped: strict mode and a
// destination outside the NO_PROXY policy. Proxies never carry ICMP.
func (o Options) DropsICMP(ip net.IP) bool {
	return o.Strict && !o.BypassesIP(ip)
}

func isSOCKS5(proxy string) bool {
	u, err := url.Parse(proxy)
	return err == nil && strings.EqualFold(u.Scheme, "socks5")
}

// DialTCP dials dest. When opts.Proxy is empty, or dest is covered by the
// NO_PROXY policy, the dial is direct and obeys ctx. Otherwise the connection
// is made through an http://, https://, or socks5:// proxy. A failed proxy
// dial is returned as an error; it never falls back to a direct dial.
//
// https:// uses HTTP CONNECT on a plain TCP connection to the proxy. The
// proxy session itself is not wrapped in TLS.
func DialTCP(ctx context.Context, opts Options, dest string) (net.Conn, error) {
	ctx = nonNil(ctx)
	if opts.Bypasses(dest) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", dest)
	}

	u, err := url.Parse(opts.Proxy)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	switch strings.ToLower(u.Scheme) {
	case "socks5":
		return dialSOCKS5(ctx, u, "tcp", dest)
	case "http", "https":
		return dialHTTPConnect(ctx, u, dest)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
}

// DialUDP dials dest. UDP is sent through the proxy when opts.ProxyUDP is set,
// opts.Proxy is a socks5:// URL, and dest is not covered by the NO_PROXY
// policy. HTTP proxies cannot carry UDP. UDP that the proxy cannot carry is
// sent directly, or rejected with ErrNotProxied in strict mode.
func DialUDP(ctx context.Context, opts Options, dest string) (net.Conn, error) {
	ctx = nonNil(ctx)
	if opts.Bypasses(dest) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dest)
	}
	if !opts.ProxyUDP {
		if opts.Strict {
			return nil, ErrNotProxied
		}
		return (&net.Dialer{}).DialContext(ctx, "udp", dest)
	}

	u, err := url.Parse(opts.Proxy)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "socks5") {
		return nil, fmt.Errorf("UDP proxy only supported for socks5://, got %q", u.Scheme)
	}
	return dialSOCKS5(ctx, u, "udp", dest)
}

// DialSOCKS5 dials dest through a socks5:// proxy URL.
// network is "tcp" or "udp". Callers that need DNS-over-TCP pass "tcp" even
// when the resolver asked for UDP: a stream connection makes the Go resolver
// use TCP DNS framing, which SOCKS5 proxies support without UDP associate.
func DialSOCKS5(ctx context.Context, proxyURL, network, dest string) (net.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}
	if !strings.EqualFold(u.Scheme, "socks5") {
		return nil, fmt.Errorf("not a socks5 proxy: %q", proxyURL)
	}
	return dialSOCKS5(nonNil(ctx), u, network, dest)
}

func dialSOCKS5(ctx context.Context, u *url.URL, network, dest string) (net.Conn, error) {
	host := hostWithDefaultPort(u.Host, "1080")
	username := ""
	password := ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	// txthinking/socks5 treats this value as a deadline on the finished
	// connection, not only as a dial timeout. It is cleared after Dial returns
	// so a forwarded stream is not killed when the connect timeout elapses.
	timeoutSec := 0
	if deadline, ok := ctx.Deadline(); ok {
		if d := time.Until(deadline); d > 0 {
			timeoutSec = int(d.Seconds())
			if timeoutSec < 1 {
				timeoutSec = 1
			}
		}
	}

	client, err := socks5.NewClient(host, username, password, timeoutSec, timeoutSec)
	if err != nil {
		return nil, fmt.Errorf("socks5 client: %w", err)
	}
	client.DialTCP = func(network, _, raddr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, raddr)
	}
	client.DialUDP = func(network, _, raddr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, raddr)
	}

	conn, err := client.Dial(network, dest)
	if err != nil {
		return nil, err
	}
	if err := clearSocksDeadlines(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// clearSocksDeadlines removes the dial deadline the SOCKS5 client installs on
// the control connection and on the returned conn.
func clearSocksDeadlines(conn net.Conn) error {
	if c, ok := conn.(*socks5.Client); ok && c.TCPConn != nil {
		if err := c.TCPConn.SetDeadline(time.Time{}); err != nil {
			return err
		}
	}
	return conn.SetDeadline(time.Time{})
}

// dialHTTPConnect connects to dest via an HTTP proxy using CONNECT.
func dialHTTPConnect(ctx context.Context, proxyURL *url.URL, dest string) (net.Conn, error) {
	proxyAddr := hostWithDefaultPort(proxyURL.Host, "8080")
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to HTTP proxy %s: %w", proxyAddr, err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, err
		}
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: dest},
		Host:   dest,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		// Set both headers. Authorization is what many CONNECT clients send.
		// Proxy-Authorization is what an HTTP proxy is required to look at.
		req.SetBasicAuth(username, password)
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT request: %w", err)
	}

	// Keep the buffered reader for the life of the tunnel. Bytes the proxy
	// sends immediately after the CONNECT response would otherwise be stuck
	// in the buffer and never reach the caller.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if err := resp.Body.Close(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("close CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy CONNECT returned %d %s", resp.StatusCode, resp.Status)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return &bufferedConn{Conn: conn, reader: br}, nil
}

// bufferedConn serves reads from reader so bytes buffered past the CONNECT
// response are not discarded. Writes and deadlines go to the underlying conn.
type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// hostWithDefaultPort appends port when host has none. IPv6 literals may be
// bracketed ("[::1]") or bare.
func hostWithDefaultPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port)
}

func nonNil(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
