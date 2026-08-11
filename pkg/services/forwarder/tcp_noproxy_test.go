package forwarder

import (
	"net"
	"testing"
)

// dialTCP must ignore the proxy for destinations covered by the built-in
// NO_PROXY policy, and use it for everything else.
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

	conn, err := dialTCP(proxy, ln.Addr().String())
	if err != nil {
		t.Fatalf("dialTCP() to loopback = %v, want direct connection", err)
	}
	conn.Close()

	if _, err := dialTCP(proxy, "93.184.216.34:80"); err == nil {
		t.Fatal("dialTCP() to public address unexpectedly succeeded, proxy was not used")
	}
}
