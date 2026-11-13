package forwarder

import (
	"net"
	"sync"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/services/netproxy"
	"github.com/containers/gvisor-tap-vsock/pkg/services/noproxy"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestTranslateReportsNATHits(t *testing.T) {
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 5, 2})
	host := tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
	other := tcpip.AddrFrom4([4]byte{1, 1, 1, 1})
	nat := map[tcpip.Address]tcpip.Address{gateway: host}
	var lock sync.Mutex

	if got, ok := translate(nat, &lock, gateway); !ok || got != host {
		t.Fatalf("translate(gateway) = %v, %v; want %v, true", got, ok, host)
	}
	if got, ok := translate(nat, &lock, other); ok || got != other {
		t.Fatalf("translate(other) = %v, %v; want %v, false", got, ok, other)
	}
}

func TestNATTargetsAreAlwaysDirect(t *testing.T) {
	empty, err := noproxy.Parse("")
	if err != nil {
		t.Fatal(err)
	}
	opts := netproxy.Options{Proxy: "socks5://127.0.0.1:1", ProxyUDP: true, Strict: true, Bypass: empty}

	// With an empty bypass list the host's loopback is proxied, unless it was
	// reached through the NAT table.
	if dialOptions(opts, false).Bypasses("127.0.0.1:8000") {
		t.Fatal("a non-NAT loopback destination must follow the empty bypass list")
	}
	if !dialOptions(opts, true).Bypasses("127.0.0.1:8000") {
		t.Fatal("a NAT target must be dialled directly")
	}
	if dialOptions(opts, true).DropsUDP("127.0.0.1:53") {
		t.Fatal("UDP to a NAT target must not be dropped")
	}
}

func TestICMPAllowed(t *testing.T) {
	lan, err := noproxy.Parse("192.168.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	public := net.ParseIP("1.1.1.1")
	local := net.ParseIP("192.168.1.88")
	loopback := net.ParseIP("127.0.0.1")

	nonStrict := netproxy.Options{Proxy: "socks5://127.0.0.1:1", Bypass: lan}
	strict := nonStrict
	strict.Strict = true

	for _, tc := range []struct {
		name   string
		opts   netproxy.Options
		natted bool
		dest   net.IP
		want   bool
	}{
		{"non-strict public", nonStrict, false, public, true},
		{"non-strict listed", nonStrict, false, local, true},
		{"strict public", strict, false, public, false},
		{"strict listed", strict, false, local, true},
		{"strict NAT target", strict, true, loopback, true},
		{"strict without proxy", netproxy.Options{Strict: true}, false, public, true},
	} {
		if got := icmpAllowed(tc.opts, tc.natted, tc.dest); got != tc.want {
			t.Errorf("%s: icmpAllowed = %v, want %v", tc.name, got, tc.want)
		}
	}
}
