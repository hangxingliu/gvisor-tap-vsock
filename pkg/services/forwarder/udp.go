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

// UDP creates a UDP forwarder. When opts.ProxyUDP is true and opts.Proxy is a
// socks5:// URL, datagrams are sent through the SOCKS5 UDP-associate relay.
// HTTP proxies do not carry UDP. Destinations covered by the NO_PROXY policy
// and NAT targets are sent directly. Other datagrams that the proxy cannot
// carry are sent directly, or dropped when opts.Strict is set.
func UDP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, ec2MetadataAccess bool, opts netproxy.Options) *udp.Forwarder {
	return udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		localAddress := r.ID().LocalAddress

		if (!ec2MetadataAccess) && linkLocal().Contains(localAddress) || (localAddress == header.IPv4Broadcast) {
			return true
		}

		localAddress, natted := translate(nat, natLock, localAddress)
		dest := net.JoinHostPort(localAddress.String(), strconv.Itoa(int(r.ID().LocalPort)))
		destOpts := dialOptions(opts, natted)
		if destOpts.DropsUDP(dest) {
			log.Debugf("strict proxy mode: dropping UDP to %s", dest)
			return true
		}

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

		p, _ := NewUDPProxy(&autoStoppingListener{underlying: gonet.NewUDPConn(&wq, ep)}, func(_ net.Addr) (net.Conn, error) {
			return netproxy.DialUDP(context.Background(), destOpts, dest)
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
