// Copyright 2023 SCION Association
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cases

import (
	"fmt"
	"hash"
	"net"
	"net/netip"
	"strings"

	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/scrypto"
)

// Topology (see accept/router_benchmark/conf/topology.json)
//    AS2 (br2) ---+== (br1a) AS1 (br1b) ---- (br4) AS4
//                 |
//    AS3 (br3) ---+
//
// We're only executing and monitoring br1a. All the others are a fiction (except for the knowledge
// about them configured in br1a) from which we construct packets that get injected at one of the
// br1a interfaces.
//
// To reduce maintainers headaches, the topology follows a convention to assign addresses, so that
// an address can be derived from a minimal information:
// * AS-1 is the hub of the test. Others are hereafter called children.
// * All IPs are V4.
// * Interface numbers are equal to the index of AS to which they connect.
// * ISD/AS: <1 or 2>-ff00:0:<AS index>
// * subnets are 192.168.<child AS number> except internal subnets that are 192.168.10*<AS>.<rtr>
// * hosts are 192.168.s.<interface number>
// * Mac addressed (when we can choose) derive from the IP
// * Ports are always 50000 for external interfaces and 30042 for internal interfaces.
//
// Example:
// * AS2 has only interface number 1 with IP 192.168.2.2 and mac address f0:0d:cafe:02:02 that
//   connects to AS 1 interface number 2.
// * AS1's interface number 2 has IP 192.168.2.1 and mac address f0:0d:cafe:02:01.
// * AS1's 1st router interface 0 has IP 192.168.10.1 and mac address f0:0d:cafe:10:01.
//
// Functions are provided to generate all addresses following that scheme.

// intfDesc describes an interface requirement
type intfDesc struct {
	ip     netip.Addr
	peerIP netip.Addr
}

// publicIP returns the IP address that is assigned to external interface designated by the given
// AS index and the peer AS (that is, the AS that this interface connects to).
// Per our scheme, the subnet number is the largest of the two AS numbers and the host is always
// the local AS. This works if there are no cycles. Else there could be subnet number collisions.
func PublicIP(localAS byte, remoteAS byte) netip.Addr {
	subnetNr := max(remoteAS, localAS)
	return netip.AddrFrom4([4]byte{192, 168, subnetNr, localAS})
}

// publicIP returns the IP address that is assigned to external interface designated by the given
// AS index and the peer AS, plus the port to go with.
func PublicIPPort(localAS byte, remoteAS byte) (netip.Addr, layers.UDPPort) {
	return PublicIP(localAS, remoteAS), layers.UDPPort(50000)
}

// internalIP returns the IP address that is assigned to the internal interface of the given
// router in the AS of the given index.
func InternalIP(AS byte, routerIndex byte) netip.Addr {
	return netip.AddrFrom4([4]byte{192, 168, AS * 10, routerIndex})
}

// internalIPPort returns internalIP and the UDPPort to go with.
func InternalIPPort(AS byte, routerIndex byte) (netip.Addr, layers.UDPPort) {
	return InternalIP(AS, routerIndex), layers.UDPPort(30042)
}

// isdAS returns a complete string form ISD/AS number for the given AS index.
// All are in ISD-1, except AS 4.
func ISDAS(AS byte) addr.IA {
	if AS == 4 {
		return xtest.MustParseIA(fmt.Sprintf("2-ff00:0:%d", AS))
	}
	return xtest.MustParseIA(fmt.Sprintf("1-ff00:0:%d", AS))
}

func FakeMAC(AS byte) hash.Hash {
	macGen, err := scrypto.HFMacFactory([]byte{AS})
	if err != nil {
		panic(err)
	}
	return macGen()
}

func Underlay(
	srcIP netip.Addr,
	srcPort layers.UDPPort,
	dstIP netip.Addr,
	dstPort layers.UDPPort) (*layers.Ethernet, *layers.IPv4, *layers.UDP) {

	// Point-to-point.
	ethernet := &layers.Ethernet{
		SrcMAC:       MACAddr(srcIP),
		DstMAC:       MACAddr(dstIP),
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Point-to-point. This is the real IP: the underlay network.
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    srcIP.AsSlice(),
		DstIP:    dstIP.AsSlice(),
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	udp := &layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	return ethernet, ip, udp
}

// interfaceLabel returns a string label for the given AS and interface indices.
// Such names are those used when responding to the show-interfaces command and when translating
// the --interface option.
func interfaceLabel(AS int, intf int) string {
	return fmt.Sprintf("%d_%d", AS, intf)
}

var (
	// intfMap lists the required interfaces. That's what we use to respond to showInterfaces
	intfMap map[string]intfDesc = map[string]intfDesc{
		interfaceLabel(1, 0): {InternalIP(1, 1), InternalIP(1, 2)},
		interfaceLabel(1, 2): {PublicIP(1, 2), PublicIP(2, 1)},
		interfaceLabel(1, 3): {PublicIP(1, 3), PublicIP(3, 1)},
	}

	// deviceNames holds the real (os-given) names of our required network interfaces. It is
	// created and populated from the values of the --interface options by InitInterfaces.
	deviceNames map[string]string

	// macAddresses keeps the mac addresses associated with each IP. It is created and populated
	// from the values of the --interface options by InitInterfaces. There can be two items for each
	// interface since we record the neighbor's addresses too. Additional IPs not from intfMap have
	// no known mac addresses; we are free to make them up to make credible packets.
	macAddrs map[netip.Addr]net.HardwareAddr
)

// InitInterfaces collects the names and mac addresses for the interfaces setup by the invoker
// according to instructions given via listInterfaces().
// This information is indexed by our own interface labels.
func InitInterfaces(pairs []string) {
	deviceNames = make(map[string]string, len(pairs))
	macAddrs = make(map[netip.Addr]net.HardwareAddr, len(pairs)*2)
	for _, pair := range pairs {
		p := strings.Split(pair, "=")
		label := p[0]
		info := strings.Split(p[1], ",")
		addr, err := net.ParseMAC(info[1])
		if err != nil {
			panic(err)
		}
		peerAddr, err := net.ParseMAC(info[2])
		if err != nil {
			panic(err)
		}
		deviceNames[label] = info[0]               // host-side name
		macAddrs[intfMap[label].ip] = addr         // ip->mac
		macAddrs[intfMap[label].peerIP] = peerAddr // peerIP->peerMAC
	}
}

// interfaceName returns the name of the host interface that this test must use in order to exchange
// traffic with the interface designated by the given AS and interface indices.
func DeviceName(AS int, intf int) string {
	return deviceNames[interfaceLabel(AS, intf)]
}

// macAddr returns the mac address assigned to the interface that has the given IP address.
// if that address is imposed by our environment it is listed in the macAddrs map and that is what
// this function returns. Else, the address is made-up according to our scheme.
func MACAddr(ip netip.Addr) net.HardwareAddr {
	// Look it up or make it up.
	mac, ok := macAddrs[ip]
	if ok {
		return mac
	}
	as4 := ip.As4()
	return net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, as4[2], as4[3]}
}

// hostAddr returns a the SCION Hosts addresse that corresponds to the given underlay address.
// Except for SVC addresses (which we do not support here), this is a restating of the underlay
// address.
func HostAddr(ip netip.Addr) addr.Host {
	return addr.HostIP(ip)
}

// ListInterfaces outputs a string describing the interfaces of the router under test.
// The invoker of this test gets this when using the show-interfaces command and is expected
// to set up the network accordingly before executing the test without that option.
// We do not choose interface names or mac addresses those will be provided by the invoker
// via the --interfaces options.
func ListInterfaces() string {
	var sb strings.Builder
	for l, i := range intfMap {
		sb.WriteString(l)
		sb.WriteString(",")
		sb.WriteString("24")
		sb.WriteString(",")
		sb.WriteString(i.ip.String())
		sb.WriteString(",")
		sb.WriteString(i.peerIP.String())
		sb.WriteString("\n")
	}
	// "our_label,24,<ip on router side>,<ip on far side>\n"

	return sb.String()
}
