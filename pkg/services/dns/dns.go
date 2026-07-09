package dns

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	socks5 "github.com/txthinking/socks5"
)

type upstreamResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type dnsHandler struct {
	zones     []types.Zone
	zonesLock sync.RWMutex
	upstream  upstreamResolver
}

func (h *dnsHandler) handle(w dns.ResponseWriter, r *dns.Msg, responseMessageSize int) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	h.addAnswers(m)
	edns0 := r.IsEdns0()
	if edns0 != nil {
		responseMessageSize = int(edns0.UDPSize())
	}
	m.Truncate(responseMessageSize)
	if err := w.WriteMsg(m); err != nil {
		log.Error(err)
	}
}

func (h *dnsHandler) handleTCP(w dns.ResponseWriter, r *dns.Msg) {
	h.handle(w, r, dns.MaxMsgSize)
}

func (h *dnsHandler) handleUDP(w dns.ResponseWriter, r *dns.Msg) {
	h.handle(w, r, dns.MinMsgSize)
}

func (h *dnsHandler) addLocalAnswers(m *dns.Msg, q dns.Question) bool {
	h.zonesLock.RLock()
	defer h.zonesLock.RUnlock()

	for _, zone := range h.zones {
		zoneSuffix := fmt.Sprintf(".%s", zone.Name)
		if strings.HasSuffix(q.Name, zoneSuffix) {
			if q.Qtype != dns.TypeA {
				return false
			}
			for _, record := range zone.Records {
				withoutZone := strings.TrimSuffix(q.Name, zoneSuffix)
				if (record.Name != "" && record.Name == withoutZone) ||
					(record.Regexp != nil && record.Regexp.MatchString(withoutZone)) {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    0,
						},
						A: record.IP,
					})
					return true
				}
			}
			if !zone.DefaultIP.Equal(net.IP("")) {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					A: zone.DefaultIP,
				})
				return true
			}
			m.Rcode = dns.RcodeNameError
			return true
		}
	}
	return false
}

func splitTxt(s string) []string {
	const k = 255
	var c []string

	if len(s) <= k {
		return []string{s}
	}

	for len(s) > k {
		c = append(c, s[:k])
		s = s[k:]
	}

	if len(s) > 0 {
		c = append(c, s)
	}

	return c
}
func (h *dnsHandler) addAnswers(m *dns.Msg) {
	for _, q := range m.Question {
		if done := h.addLocalAnswers(m, q); done {
			return
		}

		resolver := h.upstream
		switch q.Qtype {
		case dns.TypeA:
			ips, err := resolver.LookupIPAddr(context.TODO(), q.Name)
			if err != nil {
				m.Rcode = dns.RcodeNameError
				return
			}
			for _, ip := range ips {
				if len(ip.IP.To4()) != net.IPv4len {
					continue
				}
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					A: ip.IP.To4(),
				})
			}
		case dns.TypeCNAME:
			cname, err := resolver.LookupCNAME(context.TODO(), q.Name)
			if err != nil {
				m.Rcode = dns.RcodeNameError
				return
			}
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Target: cname,
			})
		case dns.TypeMX:
			records, err := resolver.LookupMX(context.TODO(), q.Name)
			if err != nil {
				m.Rcode = dns.RcodeNameError
				return
			}
			for _, mx := range records {
				m.Answer = append(m.Answer, &dns.MX{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeMX,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					Mx:         mx.Host,
					Preference: mx.Pref,
				})
			}
		case dns.TypeNS:
			records, err := resolver.LookupNS(context.TODO(), q.Name)
			if err != nil {
				m.Rcode = dns.RcodeNameError
				return
			}
			for _, ns := range records {
				m.Answer = append(m.Answer, &dns.NS{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					Ns: ns.Host,
				})
			}
		case dns.TypeSRV:
			_, records, err := resolver.LookupSRV(context.TODO(), "", "", q.Name)
			if err != nil {
				m.Rcode = dns.RcodeNameError
				return
			}
			for _, srv := range records {
				m.Answer = append(m.Answer, &dns.SRV{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeSRV,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					Port:     srv.Port,
					Priority: srv.Priority,
					Target:   srv.Target,
					Weight:   srv.Weight,
				})
			}
		case dns.TypeTXT:
			txts, err := resolver.LookupTXT(context.TODO(), q.Name)
			if err != nil {
				m.Rcode = dns.RcodeNameError
				return
			}

			for _, txt := range txts {
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    0,
					},
					Txt: splitTxt(txt),
				})
			}

		}
	}
}

type Server struct {
	udpConn net.PacketConn
	tcpLn   net.Listener
	handler *dnsHandler
}

// New creates a DNS server. When proxy is a socks5:// URL, upstream DNS
// queries are forwarded through the SOCKS5 proxy to prevent DNS leaks.
// HTTP proxies do not support DNS proxying and are silently ignored.
// When dnsUpstreams is non-empty those addresses are used as the upstream
// resolvers instead of the host system's /etc/resolv.conf nameservers.
func New(udpConn net.PacketConn, tcpLn net.Listener, zones []types.Zone, proxy string, dnsUpstreams []string) (*Server, error) {
	upstream := buildUpstreamResolver(proxy, dnsUpstreams)
	return NewWithUpstreamResolver(udpConn, tcpLn, zones, upstream)
}

// buildUpstreamResolver returns a net.Resolver appropriate for the given proxy
// and upstream DNS configuration.
//
//   - dnsUpstreams: explicit nameserver addresses (e.g. "8.8.8.8:53", "1.1.1.1").
//     When non-empty these override the system /etc/resolv.conf nameservers.
//     A bare IP without a port has ":53" appended automatically.
//   - proxy: if a socks5:// URL, all DNS queries are tunnelled through it.
//     http:// proxies are silently ignored (DNS over HTTP CONNECT is not practical).
//
// When both are empty the default system resolver is used unchanged.
func buildUpstreamResolver(proxy string, dnsUpstreams []string) *net.Resolver {
	// Normalise custom upstream addresses: append ":53" if no port given.
	for i, addr := range dnsUpstreams {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			dnsUpstreams[i] = net.JoinHostPort(addr, "53")
		}
	}

	// Determine whether we need to route through a SOCKS5 proxy.
	isSocks5 := false
	var proxyHost, username, password string
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err == nil && strings.EqualFold(u.Scheme, "socks5") {
			isSocks5 = true
			proxyHost = u.Host
			if _, _, err := net.SplitHostPort(proxyHost); err != nil {
				proxyHost = proxyHost + ":1080"
			}
			if u.User != nil {
				username = u.User.Username()
				password, _ = u.User.Password()
			}
		}
	}

	// If neither a proxy nor custom upstreams are requested, use the default
	// system resolver (fastest path, no extra goroutines or deps).
	if !isSocks5 && len(dnsUpstreams) == 0 {
		return &net.Resolver{PreferGo: false}
	}

	// Determine the nameserver list to dial.
	nameservers := dnsUpstreams
	if len(nameservers) == 0 {
		// No custom upstreams – use system nameservers so that the SOCKS5
		// tunnel still carries queries to the user's normal DNS servers.
		nameservers = systemNameservers()
		if len(nameservers) == 0 {
			// Ultimate fallback: well-known public resolver.
			nameservers = []string{"8.8.8.8:53"}
		}
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var lastErr error
			for _, ns := range nameservers {
				if isSocks5 {
					client, err := socks5.NewClient(proxyHost, username, password, 0, 0)
					if err != nil {
						lastErr = fmt.Errorf("socks5 client: %w", err)
						continue
					}
					// DNS resolvers accept both TCP and UDP; net.Resolver
					// will pass "udp" as network when PreferGo=true.
					// SOCKS5 UDP-Associate is complex; use TCP instead which
					// is universally supported and sufficient for DNS.
					conn, err := client.Dial("tcp", ns)
					if err != nil {
						lastErr = fmt.Errorf("dial %s via socks5: %w", ns, err)
						continue
					}
					return conn, nil
				}
				// Direct connection (custom upstreams, no proxy).
				conn, err := (&net.Dialer{}).DialContext(ctx, "udp", ns)
				if err != nil {
					lastErr = fmt.Errorf("dial %s: %w", ns, err)
					continue
				}
				return conn, nil
			}
			return nil, lastErr
		},
	}
}

// systemNameservers reads nameserver addresses from /etc/resolv.conf and
// returns them as "host:53" strings. Returns nil if the file cannot be read.
func systemNameservers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[1]
		if net.ParseIP(ip) != nil {
			servers = append(servers, net.JoinHostPort(ip, "53"))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil
	}
	return servers
}

func NewWithUpstreamResolver(udpConn net.PacketConn, tcpLn net.Listener, zones []types.Zone, upstream upstreamResolver) (*Server, error) {
	handler := &dnsHandler{zones: zones, upstream: upstream}
	return &Server{udpConn: udpConn, tcpLn: tcpLn, handler: handler}, nil
}

func (s *Server) Serve() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handler.handleUDP)
	srv := &dns.Server{
		PacketConn: s.udpConn,
		Handler:    mux,
	}
	return srv.ActivateAndServe()
}

func (s *Server) ServeTCP() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handler.handleTCP)
	tcpSrv := &dns.Server{
		Listener: s.tcpLn,
		Handler:  mux,
	}
	return tcpSrv.ActivateAndServe()
}

func (s *Server) Mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/all", func(w http.ResponseWriter, _ *http.Request) {
		s.handler.zonesLock.RLock()
		_ = json.NewEncoder(w).Encode(s.handler.zones)
		s.handler.zonesLock.RUnlock()
	})

	mux.HandleFunc("/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post only", http.StatusBadRequest)
			return
		}
		var req types.Zone
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		s.addZone(req)
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func (s *Server) addZone(req types.Zone) {
	s.handler.zonesLock.Lock()
	defer s.handler.zonesLock.Unlock()
	for i, zone := range s.handler.zones {
		if zone.Name == req.Name {
			req.Records = append(req.Records, zone.Records...)
			s.handler.zones[i] = req
			return
		}
	}
	// No existing zone for req.Name, add new one
	s.handler.zones = append(s.handler.zones, req)
}
