package forwarder

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/netproxy"
	"github.com/inetaf/tcpproxy"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	linkLocalSubnet = "169.254.0.0/16"

	defaultTCPMaxInFlight    = 128
	defaultTCPConnectTimeout = 30 * time.Second
)

// TCP creates a TCP forwarder. Outbound connections are dialled directly
// unless opts.Proxy is a non-empty http://, https://, or socks5:// URL.
// Destinations covered by the NO_PROXY policy (opts.Bypass) and NAT targets
// are always dialled directly. A failed proxy dial resets the guest
// connection; it never falls back to a direct dial.
//
// maxInFlight and connectTimeout keep their upstream meaning. Non-positive
// values select the defaults. connectTimeout bounds the direct dial and the
// proxy handshake. An empty proxy preserves the direct-connect behavior.
func TCP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, ec2MetadataAccess bool, maxInFlight int, connectTimeout time.Duration, opts netproxy.Options) *tcp.Forwarder {
	if maxInFlight <= 0 {
		maxInFlight = defaultTCPMaxInFlight
	}
	if connectTimeout <= 0 {
		connectTimeout = defaultTCPConnectTimeout
	}
	return tcp.NewForwarder(s, 0, maxInFlight, func(r *tcp.ForwarderRequest) {
		localAddress := r.ID().LocalAddress

		if (!ec2MetadataAccess) && linkLocal().Contains(localAddress) {
			r.Complete(true)
			return
		}

		localAddress, natted := translate(nat, natLock, localAddress)
		dest := net.JoinHostPort(localAddress.String(), fmt.Sprint(r.ID().LocalPort))
		ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		outbound, err := netproxy.DialTCP(ctx, dialOptions(opts, natted), dest)
		cancel()
		if err != nil {
			log.Tracef("netproxy.DialTCP() = %v", err)
			r.Complete(true)
			return
		}

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		r.Complete(false)
		if tcpErr != nil {
			if err := outbound.Close(); err != nil {
				log.Debugf("close outbound connection: %v", err)
			}
			if _, ok := tcpErr.(*tcpip.ErrConnectionRefused); ok {
				// transient error
				log.Debugf("r.CreateEndpoint() = %v", tcpErr)
			} else {
				log.Errorf("r.CreateEndpoint() = %v", tcpErr)
			}
			return
		}

		remote := tcpproxy.DialProxy{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return outbound, nil
			},
		}
		remote.HandleConn(gonet.NewTCPConn(&wq, ep))
	})
}

func linkLocal() *tcpip.Subnet {
	_, parsedSubnet, _ := net.ParseCIDR(linkLocalSubnet) // CoreOS VM tries to connect to Amazon EC2 metadata service
	subnet, _ := tcpip.NewSubnet(tcpip.AddrFromSlice(parsedSubnet.IP), tcpip.MaskFromBytes(parsedSubnet.Mask))
	return &subnet
}
