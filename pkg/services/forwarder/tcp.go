package forwarder

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/inetaf/tcpproxy"
	socks5 "github.com/txthinking/socks5"
	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const linkLocalSubnet = "169.254.0.0/16"

// TCP creates a TCP forwarder that routes outbound connections through an
// optional proxy.  When proxy is empty, the behaviour is identical to the
// original direct-connect implementation.
func TCP(s *stack.Stack, nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, ec2MetadataAccess bool, proxy string) *tcp.Forwarder {
	return tcp.NewForwarder(s, 0, 10, func(r *tcp.ForwarderRequest) {
		localAddress := r.ID().LocalAddress

		if (!ec2MetadataAccess) && linkLocal().Contains(localAddress) {
			r.Complete(true)
			return
		}

		natLock.Lock()
		if replaced, ok := nat[localAddress]; ok {
			localAddress = replaced
		}
		natLock.Unlock()

		dest := net.JoinHostPort(localAddress.String(), fmt.Sprint(r.ID().LocalPort))
		outbound, err := dialTCP(proxy, dest)
		if err != nil {
			log.Tracef("dialTCP() = %v", err)
			r.Complete(true)
			return
		}

		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		r.Complete(false)
		if tcpErr != nil {
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

// dialTCP dials dest via proxy (if non-empty) or directly.
func dialTCP(proxy, dest string) (net.Conn, error) {
	if proxy == "" {
		return net.Dial("tcp", dest)
	}

	u, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxy, err)
	}

	switch strings.ToLower(u.Scheme) {
	case "socks5":
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
		return client.Dial("tcp", dest)

	case "http", "https":
		return dialHTTPConnect(u, dest)

	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
}

func linkLocal() *tcpip.Subnet {
	_, parsedSubnet, _ := net.ParseCIDR(linkLocalSubnet) // CoreOS VM tries to connect to Amazon EC2 metadata service
	subnet, _ := tcpip.NewSubnet(tcpip.AddrFromSlice(parsedSubnet.IP), tcpip.MaskFromBytes(parsedSubnet.Mask))
	return &subnet
}
