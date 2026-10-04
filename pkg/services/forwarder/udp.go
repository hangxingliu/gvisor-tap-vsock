package forwarder

import (
	"context"
	"net"
	"strconv"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/services/netproxy"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// UDP creates a UDP forwarder. When proxyUDP is true and proxy is a socks5://
// URL, datagrams are sent through the SOCKS5 UDP-associate relay. HTTP proxies
// do not carry UDP. Destinations covered by the NO_PROXY policy, and every
// datagram when proxyUDP is false, are sent directly.
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
		p, _ := NewUDPProxy(&autoStoppingListener{underlying: gonet.NewUDPConn(&wq, ep)}, func(_ net.Addr) (net.Conn, error) {
			return netproxy.DialUDP(context.Background(), proxy, proxyUDP, dest)
		})
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
