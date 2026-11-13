package netproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/noproxy"
)

func TestDialTCPBypassesProxyForPrivateDestinations(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	// Unreachable proxy: a successful dial proves the bypass happened.
	const proxy = "socks5://127.0.0.1:1"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := DialTCP(ctx, Options{Proxy: proxy}, ln.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP() to loopback = %v, want direct connection", err)
	}
	conn.Close()

	if _, err := DialTCP(ctx, Options{Proxy: proxy}, "93.184.216.34:80"); err == nil {
		t.Fatal("DialTCP() to a public address unexpectedly succeeded; the proxy was not used")
	}
}

func TestDialTCPThroughHTTPConnect(t *testing.T) {
	echo := startEcho(t)
	// Public destination so the NO_PROXY bypass cannot satisfy the dial.
	// The test proxy relays that CONNECT to the local echo instead.
	const dest = "93.184.216.34:80"
	proxy := startConnectProxy(t, "", echo)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := DialTCP(ctx, Options{Proxy: proxy}, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "pong" {
		t.Fatalf("got %q, want pong", buf)
	}
}

func TestDialTCPPreservesBytesAfterConnectResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Method != http.MethodConnect {
			return
		}
		// "early" is sent in the same write as the response headers so a
		// buffered CONNECT reader must not drop it.
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\nearly")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := DialTCP(ctx, Options{Proxy: "http://" + ln.Addr().String()}, "93.184.216.34:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "early" {
		t.Fatalf("got %q, want early", buf)
	}
}

func TestDialTCPHTTPConnectAuth(t *testing.T) {
	echo := startEcho(t)
	const dest = "93.184.216.34:80"
	proxy := startConnectProxy(t, "user:secret", echo)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := DialTCP(ctx, Options{Proxy: proxy}, dest); err == nil {
		t.Fatal("DialTCP() without credentials succeeded")
	}

	authed := "http://user:secret@" + strings.TrimPrefix(proxy, "http://")
	conn, err := DialTCP(ctx, Options{Proxy: authed}, dest)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestDialUDPBypassAndScheme(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := DialUDP(ctx, Options{Proxy: "socks5://127.0.0.1:1", ProxyUDP: true}, pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("DialUDP() to loopback = %v, want direct connection", err)
	}
	conn.Close()

	_, err = DialUDP(ctx, Options{Proxy: "http://127.0.0.1:8080", ProxyUDP: true}, "93.184.216.34:53")
	if err == nil || !strings.Contains(err.Error(), "socks5") {
		t.Fatalf("DialUDP() via http proxy error = %v, want a socks5-only error", err)
	}

	_, err = DialUDP(ctx, Options{Proxy: "socks5://127.0.0.1:1", ProxyUDP: true}, "93.184.216.34:53")
	if err == nil {
		t.Fatal("DialUDP() to a public address unexpectedly succeeded; the proxy was not used")
	}
}

func TestHostWithDefaultPort(t *testing.T) {
	if got := hostWithDefaultPort("127.0.0.1", "1080"); got != "127.0.0.1:1080" {
		t.Fatalf("got %q", got)
	}
	if got := hostWithDefaultPort("127.0.0.1:9050", "1080"); got != "127.0.0.1:9050" {
		t.Fatalf("got %q", got)
	}
	if got := hostWithDefaultPort("[::1]", "1080"); got != "[::1]:1080" {
		t.Fatalf("got %q", got)
	}
	if got := hostWithDefaultPort("::1", "1080"); got != "[::1]:1080" {
		t.Fatalf("got %q", got)
	}
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				if string(buf) == "ping" {
					_, _ = io.WriteString(c, "pong")
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startConnectProxy serves HTTP CONNECT. userpass is "user:pass" when basic
// auth is required, or empty when it is not. relayTo is dialled instead of
// the CONNECT target so tests can use a public destination (which is not
// covered by the NO_PROXY bypass) without leaving the machine.
func startConnectProxy(t *testing.T, userpass, relayTo string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConnect(c, userpass, relayTo)
		}
	}()
	return "http://" + ln.Addr().String()
}

func handleConnect(c net.Conn, userpass, relayTo string) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if userpass != "" {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(userpass))
		if req.Header.Get("Proxy-Authorization") != want || req.Header.Get("Authorization") != want {
			_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
			return
		}
	}
	target := req.Host
	if relayTo != "" {
		target = relayTo
	}
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	go func() { _, _ = io.Copy(upstream, br) }()
	_, _ = io.Copy(c, upstream)
}

func mustPolicy(t *testing.T, list string) *noproxy.Policy {
	t.Helper()
	p, err := noproxy.Parse(list)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDialTCPUsesTheConfiguredBypassList(t *testing.T) {
	echo := startEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// The proxy is unreachable: a successful dial proves a direct connection.
	const proxy = "socks5://127.0.0.1:1"
	conn, err := DialTCP(ctx, Options{Proxy: proxy, Bypass: mustPolicy(t, "127.0.0.0/8")}, echo)
	if err != nil {
		t.Fatalf("listed destination = %v, want a direct connection", err)
	}
	conn.Close()

	for _, list := range []string{"", "10.0.0.0/8"} {
		if _, err := DialTCP(ctx, Options{Proxy: proxy, Bypass: mustPolicy(t, list)}, echo); err == nil {
			t.Fatalf("bypass list %q: loopback was dialled directly; the proxy was not used", list)
		}
	}
}

func TestDialUDPStrictMode(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dest := pc.LocalAddr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	empty := mustPolicy(t, "")

	for _, opts := range []Options{
		{Proxy: "http://127.0.0.1:1", Bypass: empty},
		{Proxy: "socks5://127.0.0.1:1", ProxyUDP: false, Bypass: empty},
	} {
		conn, err := DialUDP(ctx, opts, dest)
		if err != nil {
			t.Fatalf("%+v non-strict = %v, want a direct dial", opts, err)
		}
		conn.Close()
		if opts.DropsUDP(dest) {
			t.Fatalf("%+v non-strict DropsUDP = true", opts)
		}

		opts.Strict = true
		if _, err := DialUDP(ctx, opts, dest); !errors.Is(err, ErrNotProxied) {
			t.Fatalf("%+v strict = %v, want ErrNotProxied", opts, err)
		}
		if !opts.DropsUDP(dest) {
			t.Fatalf("%+v strict DropsUDP = false", opts)
		}

		// A destination in the bypass list stays direct in strict mode.
		opts.Bypass = mustPolicy(t, "127.0.0.0/8")
		conn, err = DialUDP(ctx, opts, dest)
		if err != nil {
			t.Fatalf("%+v strict, listed destination = %v, want a direct dial", opts, err)
		}
		conn.Close()
		if opts.DropsUDP(dest) {
			t.Fatalf("%+v strict DropsUDP for a listed destination = true", opts)
		}
	}

	socks := Options{Proxy: "socks5://127.0.0.1:1", ProxyUDP: true, Strict: true, Bypass: empty}
	if socks.DropsUDP(dest) {
		t.Fatal("UDP that the SOCKS5 proxy carries must not be dropped")
	}
}

func TestDropsICMP(t *testing.T) {
	ip := net.ParseIP("1.1.1.1")
	lan := net.ParseIP("192.168.1.88")
	opts := Options{Proxy: "socks5://127.0.0.1:1", Bypass: mustPolicy(t, "192.168.0.0/16")}
	if opts.DropsICMP(ip) || opts.DropsICMP(lan) {
		t.Fatal("non-strict mode must not drop ICMP")
	}
	opts.Strict = true
	if !opts.DropsICMP(ip) {
		t.Fatal("strict mode must drop ICMP outside the bypass list")
	}
	if opts.DropsICMP(lan) {
		t.Fatal("strict mode must keep ICMP to the bypass list")
	}
	if (Options{Strict: true}).DropsICMP(ip) {
		t.Fatal("without a proxy nothing is dropped")
	}
}
