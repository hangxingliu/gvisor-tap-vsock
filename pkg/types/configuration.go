package types

import (
	"net"
	"regexp"
)

type Configuration struct {
	// Print packets on stderr
	Debug bool `yaml:"debug,omitempty"`

	// Record all packets coming in and out in a file that can be read by Wireshark (pcap)
	CaptureFile string `yaml:"capture-file,omitempty"`

	// Length of packet
	// Larger packets means less packets to exchange for the same amount of data (and less protocol overhead)
	MTU int `yaml:"mtu,omitempty"`

	// Network reserved for the virtual network
	Subnet string `yaml:"subnet,omitempty"`

	// IP address of the virtual gateway
	GatewayIP string `yaml:"gatewayIP,omitempty"`

	// IP address of the device in the virtual network
	DeviceIP string `yaml:"deviceIP,omitempty"`

	// IP address of the host in the virtual network
	HostIP string `yaml:"hostIP,omitempty"`

	// MAC address of the virtual gateway
	GatewayMacAddress string `yaml:"gatewayMacAddress,omitempty"`

	// Built-in DNS records that will be served by the DNS server embedded in the gateway
	DNS []Zone `yaml:"dns,omitempty"`

	// List of search domains that will be added in all DHCP replies
	DNSSearchDomains []string `yaml:"dnsSearchDomains,omitempty"`

	// Port forwarding between the machine running the gateway and the virtual network.
	Forwards map[string]string `yaml:"forwards,omitempty"`

	// Address translation of incoming traffic.
	// Useful for reaching the host itself (localhost) from the virtual network.
	NAT map[string]string `yaml:"nat,omitempty"`

	// IPs assigned to the gateway that can answer to ARP requests
	GatewayVirtualIPs []string `yaml:"gatewayVirtualIPs,omitempty"`

	// DHCP static leases. Allow to assign pre-defined IP to virtual machine based on the MAC address
	DHCPStaticLeases map[string]string `yaml:"dhcpStaticLeases,omitempty"`

	// Only for Hyperkit
	// Allow to assign a pre-defined MAC address to an Hyperkit VM
	VpnKitUUIDMacAddresses map[string]string `yaml:"vpnKitUUIDMacAddresses,omitempty"`

	// Protocol to be used. Only for /connect mux
	Protocol Protocol `yaml:"-"`

	// EC2 Metadata Service Access
	Ec2MetadataAccess bool `yaml:"ec2MetadataAccess,omitempty"`

	// Maximum number of in-flight TCP connection forwarding attempts (default: 128)
	TCPMaxInFlight int `yaml:"tcpMaxInFlight,omitempty"`

	// Timeout in seconds for outbound TCP connection attempts (default: 30)
	TCPConnectTimeout int `yaml:"tcpConnectTimeout,omitempty"`

	// Proxy is an optional HTTP or SOCKS5 proxy for outbound guest TCP
	// connections, and for UDP when ProxyUDP is set.
	// Supported schemes are http, https, and socks5.
	// https uses HTTP CONNECT on a plain TCP connection to the proxy; the
	// proxy session itself is not wrapped in TLS.
	// Loopback, link-local, and private destinations bypass the proxy.
	Proxy string `yaml:"proxy,omitempty"`

	// ProxyUDP routes outbound UDP through Proxy. Only socks5:// proxies
	// support UDP. Ignored when Proxy is empty or uses another scheme.
	ProxyUDP bool `yaml:"proxyUDP,omitempty"`

	// DNSUpstreams, when non-empty, replaces the host resolver for queries
	// the gateway forwards. An address may omit the port; 53 is used then.
	// With a socks5 Proxy, queries to non-local upstreams are tunnelled
	// through that proxy. http proxies do not carry DNS.
	DNSUpstreams []string `yaml:"dnsUpstreams,omitempty"`
}

type Protocol string

const (
	// HyperKitProtocol is handshake, then 16bits little endian size of packet, then the packet.
	HyperKitProtocol Protocol = "hyperkit"
	// QemuProtocol is 32bits big endian size of the packet, then the packet.
	QemuProtocol Protocol = "qemu"
	// BessProtocol transfers bare L2 packets as SOCK_SEQPACKET.
	BessProtocol Protocol = "bess"
	// StdioProtocol is HyperKitProtocol without the handshake
	StdioProtocol Protocol = "stdio"
	// VfkitProtocol transfers bare L2 packets as SOCK_DGRAM.
	VfkitProtocol Protocol = "vfkit"
)

type Zone struct {
	Name      string   `yaml:"name,omitempty"`
	Records   []Record `yaml:"records,omitempty"`
	DefaultIP net.IP   `yaml:"defaultIP,omitempty"`
	// Protected zones cannot be modified or overwritten via the API.
	// Set this in the YAML configuration or in code to prevent a zone
	// from being changed at runtime.
	Protected bool `yaml:"protected,omitempty"`
}

type Record struct {
	Name   string         `yaml:"name,omitempty"`
	IP     net.IP         `yaml:"ip,omitempty"`
	Regexp *regexp.Regexp `json:",omitempty" yaml:"regexp,omitempty"`
}
