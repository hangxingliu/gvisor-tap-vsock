package forwarder

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"

	socks5 "github.com/txthinking/socks5"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// UDP creates a UDP forwarder.  When proxyUDP is true and proxy is a socks5://
// URL, UDP datagrams are sent through the SOCKS5 UDP-Associate relay.
// Otherwise datagrams are sent directly.
func UDP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, ec2MetadataAccess bool, proxy string, proxyUDP bool) *udp.Forwarder {
	return udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		localAddress := r.ID().LocalAddress

		if (!ec2MetadataAccess) && linkLocal().Contains(localAddress) || (localAddress == header.IPv4Broadcast) {
			return true
		}

		natLock.Lock()
		if replaced, ok := nat[localAddress]; ok {
			localAddress = replaced
		}
		natLock.Unlock()

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			if _, ok := tcpErr.(*tcpip.ErrConnectionRefused); ok {
				// transient error
				log.Debugf("r.CreateEndpoint() = %v", tcpErr)
			} else {
				log.Errorf("r.CreateEndpoint() = %v", tcpErr)
			}
			return false
		}

		dest := net.JoinHostPort(localAddress.String(), strconv.Itoa(int(r.ID().LocalPort)))

		var dialer func() (net.Conn, error)
		if proxyUDP && proxy != "" {
			dialer = makeSocks5UDPDialer(proxy, dest)
		} else {
			dialer = func() (net.Conn, error) {
				return net.Dial("udp", dest)
			}
		}

		p, _ := NewUDPProxy(&autoStoppingListener{underlying: gonet.NewUDPConn(&wq, ep)}, dialer)
		go func() {
			p.Run()

			// note that at this point packets that are sent to the current forwarder session
			// will be dropped. We will start processing the packets again when we get a new
			// forwarder request.
			ep.Close()
		}()
		return true
	})
}

// makeSocks5UDPDialer returns a dialer func that opens a new SOCKS5 UDP
// Associate connection bound to dest each time it is called.
func makeSocks5UDPDialer(proxy, dest string) func() (net.Conn, error) {
	return func() (net.Conn, error) {
		u, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", proxy, err)
		}
		if !strings.EqualFold(u.Scheme, "socks5") {
			return nil, fmt.Errorf("UDP proxy only supported for socks5://, got %q", u.Scheme)
		}

		host := u.Host
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = host + ":1080"
		}
		username := ""
		password := ""
		if u.User != nil {
			username = u.User.Username()
			password, _ = u.User.Password()
		}

		client, err := socks5.NewClient(host, username, password, 0, 0)
		if err != nil {
			return nil, fmt.Errorf("socks5 client: %w", err)
		}
		return client.Dial("udp", dest)
	}
}
