package dns

import (
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestNewLeavesDefaultResolverUntouched(t *testing.T) {
	for _, proxy := range []string{"", "http://127.0.0.1:8080", "https://proxy.example:8443", "not a url"} {
		server, err := New(nil, nil, nil, proxy, nil)
		if err != nil {
			t.Fatalf("New(proxy=%q) error = %v", proxy, err)
		}
		if server.handler.dialNameserver != nil {
			t.Fatalf("proxy %q installed a DNS dialer; only socks5 should", proxy)
		}
	}
}

func TestNewNormalizesCustomUpstreams(t *testing.T) {
	server, err := New(nil, nil, nil, "", []string{"8.8.8.8", "1.1.1.1:5353", "  ", "[2001:db8::1]"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"8.8.8.8:53", "1.1.1.1:5353", "[2001:db8::1]:53"}
	got := server.handler.nameservers
	if len(got) != len(want) {
		t.Fatalf("nameservers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("nameservers = %v, want %v", got, want)
		}
	}
	if server.handler.dialNameserver != nil {
		t.Fatal("custom upstreams without a socks5 proxy should be dialled directly")
	}
}

func TestCustomUpstreamAnswersAndRawRecords(t *testing.T) {
	addr, done := listenFixtureDNS(t, "udp")
	defer done()

	server, err := New(nil, nil, nil, "", []string{addr})
	if err != nil {
		t.Fatal(err)
	}

	a := ask(server, mdns.TypeA)
	if a.Rcode != mdns.RcodeSuccess || len(a.Answer) == 0 {
		t.Fatalf("A response = rcode %d answers %d", a.Rcode, len(a.Answer))
	}
	arec, ok := a.Answer[0].(*mdns.A)
	if !ok || !arec.A.Equal(net.ParseIP("203.0.113.10")) {
		t.Fatalf("A answer = %v, want 203.0.113.10", a.Answer)
	}

	soa := ask(server, mdns.TypeSOA)
	if soa.Rcode != mdns.RcodeSuccess || len(soa.Answer) == 0 {
		t.Fatalf("SOA response = rcode %d answers %d", soa.Rcode, len(soa.Answer))
	}
	if _, ok := soa.Answer[0].(*mdns.SOA); !ok {
		t.Fatalf("SOA answer type = %T", soa.Answer[0])
	}
}

func TestSocks5DNSAndLocalBypass(t *testing.T) {
	dnsAddr, doneDNS := listenFixtureDNS(t, "tcp")
	defer doneDNS()

	// 8.8.8.8 is not covered by the NO_PROXY policy, so the query has to
	// traverse the proxy. The test proxy relays that CONNECT to the local
	// DNS server instead of the public address.
	var proxyDials atomic.Int32
	proxyURL, doneProxy := startSocks5ConnectServer(t, &proxyDials, dnsAddr)
	defer doneProxy()

	server, err := New(nil, nil, nil, proxyURL, []string{"8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	a := ask(server, mdns.TypeA)
	if len(a.Answer) == 0 {
		t.Fatalf("proxied A answer empty rcode %d dials %d", a.Rcode, proxyDials.Load())
	}
	arec, ok := a.Answer[0].(*mdns.A)
	if !ok || !arec.A.Equal(net.ParseIP("203.0.113.10")) {
		t.Fatalf("proxied A answer = %v (rcode %d) dials %d", a.Answer, a.Rcode, proxyDials.Load())
	}
	soa := ask(server, mdns.TypeSOA)
	if len(soa.Answer) == 0 {
		t.Fatalf("proxied SOA answer empty rcode %d", soa.Rcode)
	}
	if _, ok := soa.Answer[0].(*mdns.SOA); !ok {
		t.Fatalf("proxied SOA answer = %v (rcode %d)", soa.Answer, soa.Rcode)
	}
	if proxyDials.Load() == 0 {
		t.Fatal("SOCKS5 proxy was never contacted")
	}

	// A loopback upstream must be dialled directly even when a proxy is set.
	udpAddr, doneUDP := listenFixtureDNS(t, "udp")
	defer doneUDP()
	proxyDials.Store(0)
	bypassed, err := New(nil, nil, nil, proxyURL, []string{udpAddr})
	if err != nil {
		t.Fatal(err)
	}
	got := ask(bypassed, mdns.TypeA)
	if len(got.Answer) == 0 {
		t.Fatalf("bypassed A answer empty rcode %d dials %d", got.Rcode, proxyDials.Load())
	}
	rec, ok := got.Answer[0].(*mdns.A)
	if !ok || !rec.A.Equal(net.ParseIP("203.0.113.10")) {
		t.Fatalf("bypassed A answer = %v (rcode %d)", got.Answer, got.Rcode)
	}
	if n := proxyDials.Load(); n != 0 {
		t.Fatalf("local upstream contacted the proxy %d times", n)
	}
}

func ask(server *Server, qtype uint16) *mdns.Msg {
	m := new(mdns.Msg)
	m.SetQuestion("example.test.", qtype)
	server.handler.addAnswers(m)
	return m
}

func listenFixtureDNS(t *testing.T, network string) (string, func()) {
	t.Helper()
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		if len(r.Question) == 0 {
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		hdr := mdns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: mdns.ClassINET, Ttl: 60}
		switch q.Qtype {
		case mdns.TypeA:
			m.Answer = append(m.Answer, &mdns.A{Hdr: hdr, A: net.ParseIP("203.0.113.10").To4()})
		case mdns.TypeAAAA:
			m.Answer = append(m.Answer, &mdns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::10")})
		case mdns.TypeSOA:
			m.Answer = append(m.Answer, &mdns.SOA{
				Hdr:  hdr,
				Ns:   "ns.example.test.",
				Mbox: "hostmaster.example.test.",
			})
		}
		_ = w.WriteMsg(m)
	})

	srv := &mdns.Server{Handler: mux, Net: network}
	if network == "tcp" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv.Listener = ln
		go func() { _ = srv.ActivateAndServe() }()
		return ln.Addr().String(), func() { _ = srv.Shutdown() }
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.PacketConn = pc
	go func() { _ = srv.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

// startSocks5ConnectServer accepts unauthenticated CONNECT requests and relays
// the byte stream. dials counts accepted clients.
func startSocks5ConnectServer(t *testing.T, dials *atomic.Int32, relayTo string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			go serveSocks5Connect(c, relayTo)
		}
	}()
	return "socks5://" + ln.Addr().String(), func() { _ = ln.Close() }
}

func serveSocks5Connect(c net.Conn, relayTo string) {
	defer c.Close()
	buf := make([]byte, 258)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	nmethods := int(buf[1])
	if nmethods == 0 || nmethods > len(buf) {
		return
	}
	if _, err := io.ReadFull(c, buf[:nmethods]); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		n := int(buf[0])
		if _, err := io.ReadFull(c, buf[:n]); err != nil {
			return
		}
		host = string(buf[:n])
	case 0x04:
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		return
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])
	target := net.JoinHostPort(host, strconv.Itoa(port))
	if relayTo != "" {
		target = relayTo
	}
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(upstream, c) }()
	_, _ = io.Copy(c, upstream)
}
