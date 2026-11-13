package forwarder

import (
	"net"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/services/netproxy"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// translate returns the NAT target for addr, and whether the NAT table had
// an entry for it.
func translate(nat map[tcpip.Address]tcpip.Address, natLock *sync.Mutex, addr tcpip.Address) (tcpip.Address, bool) {
	natLock.Lock()
	defer natLock.Unlock()
	if replaced, ok := nat[addr]; ok {
		return replaced, true
	}
	return addr, false
}

// dialOptions returns the proxy options for one destination. A NAT target
// (for example the gateway mapped to the host's loopback) is always dialled
// directly, whatever the bypass list says.
func dialOptions(opts netproxy.Options, natted bool) netproxy.Options {
	if natted {
		return netproxy.Options{}
	}
	return opts
}

// icmpAllowed reports whether an ICMP echo to dest is sent from the host.
// Strict proxy mode only lets NAT targets and destinations in the bypass list
// through.
func icmpAllowed(opts netproxy.Options, natted bool, dest net.IP) bool {
	return natted || !opts.DropsICMP(dest)
}
