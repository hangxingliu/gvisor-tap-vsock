package forwarder

import (
	"sync"
	"testing"

	"github.com/containers/gvisor-tap-vsock/pkg/services/netproxy"
	"github.com/containers/gvisor-tap-vsock/pkg/services/noproxy"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestDroppedICMPReleasesPacketBuffer(t *testing.T) {
	public := tcpip.AddrFrom4([4]byte{1, 1, 1, 1})
	loopback := tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
	broadcast := header.IPv4Broadcast
	listed := tcpip.AddrFrom4([4]byte{10, 1, 2, 3})
	gateway := tcpip.AddrFrom4([4]byte{192, 168, 5, 2})

	empty, err := noproxy.Parse("")
	if err != nil {
		t.Fatal(err)
	}
	lan, err := noproxy.Parse("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	strictEmpty := netproxy.Options{Proxy: "socks5://127.0.0.1:1", Strict: true, Bypass: empty}
	strictLAN := netproxy.Options{Proxy: "socks5://127.0.0.1:1", Strict: true, Bypass: lan}
	direct := netproxy.Options{}

	for _, tc := range []struct {
		name string
		opts netproxy.Options
		nat  map[tcpip.Address]tcpip.Address
		dest tcpip.Address
		kind string
	}{
		{name: "loopback echo", opts: direct, dest: loopback, kind: "echo"},
		{name: "broadcast echo", opts: direct, dest: broadcast, kind: "echo"},
		{name: "strict public echo", opts: strictEmpty, dest: public, kind: "echo"},
		{name: "strict public short header", opts: strictEmpty, dest: public, kind: "short"},
		{name: "direct public short header", opts: direct, dest: public, kind: "short"},
		{name: "direct public non-echo", opts: direct, dest: public, kind: "non-echo"},
		{name: "strict listed non-echo", opts: strictLAN, dest: listed, kind: "non-echo"},
		{
			name: "strict NAT target non-echo",
			opts: strictEmpty,
			nat:  map[tcpip.Address]tcpip.Address{gateway: loopback},
			dest: gateway,
			kind: "non-echo",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt, released := icmpPacket(t, tc.kind)
			assertICMPDropped(t, tc.opts, tc.nat, tc.dest, pkt, released)
		})
	}
}

func TestNilICMPPacketDoesNotPanic(t *testing.T) {
	public := tcpip.AddrFrom4([4]byte{8, 8, 8, 8})
	empty, err := noproxy.Parse("")
	if err != nil {
		t.Fatal(err)
	}
	strict := netproxy.Options{Proxy: "socks5://127.0.0.1:1", Strict: true, Bypass: empty}

	for _, tc := range []struct {
		name string
		opts netproxy.Options
	}{
		{name: "direct", opts: netproxy.Options{}},
		{name: "strict", opts: strict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var natLock sync.Mutex
			f := ICMP(nil, map[tcpip.Address]tcpip.Address{}, &natLock, tc.opts)
			f.handler(NewICMPForwarderRequest(nil, stack.TransportEndpointID{LocalAddress: public}, nil))
		})
	}
}

// assertICMPDropped delivers one packet the way the stack does and checks
// that the forwarder released the extra reference before HandlePacket
// returned. Echo packets in these cases are filtered before handlePingRequest,
// so the check is synchronous.
func assertICMPDropped(t *testing.T, opts netproxy.Options, nat map[tcpip.Address]tcpip.Address, dest tcpip.Address, pkt *stack.PacketBuffer, released *bool) {
	t.Helper()
	if nat == nil {
		nat = map[tcpip.Address]tcpip.Address{}
	}
	var natLock sync.Mutex
	f := ICMP(nil, nat, &natLock, opts)
	if !f.HandlePacket(stack.TransportEndpointID{LocalAddress: dest}, pkt) {
		t.Fatal("HandlePacket returned false")
	}
	refs := pkt.ReadRefs()
	if refs != 1 {
		t.Errorf("refs = %d after a dropped packet, want 1 (the caller's reference)", refs)
	}
	// Release exactly the references still recorded above. Recounting with
	// ReadRefs after the last DecRef would touch a buffer that has returned
	// to the pool.
	for refs > 0 {
		pkt.DecRef()
		refs--
	}
	if !*released {
		t.Fatal("PacketBuffer was not released")
	}
}

func icmpPacket(t *testing.T, kind string) (*stack.PacketBuffer, *bool) {
	t.Helper()
	headerLen := header.ICMPv4MinimumSize
	icmpType := header.ICMPv4Echo
	switch kind {
	case "echo":
	case "non-echo":
		icmpType = header.ICMPv4DstUnreachable
	case "short":
		headerLen = 4
	default:
		t.Fatalf("unknown packet kind %q", kind)
	}

	released := false
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: headerLen,
		OnRelease:          func() { released = true },
	})
	view := pkt.TransportHeader().Push(headerLen)
	if headerLen >= header.ICMPv4MinimumSize {
		header.ICMPv4(view).SetType(icmpType)
	} else {
		view[0] = byte(icmpType)
	}
	return pkt, &released
}
