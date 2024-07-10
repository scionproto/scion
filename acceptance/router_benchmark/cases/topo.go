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
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
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
// * subnets are 10.123.<child AS number> except internal subnets that are 10.123.10*<AS>.<rtr>
// * hosts are 10.123.s.<interface number>
// * Mac addressed (when we can choose) derive from the IP
// * Ports are always 50000 for external interfaces and 30042 for internal interfaces.
//
// Example:
// * AS2 has only interface number 1 with IP 10.123.2.2 and mac address f0:0d:cafe:02:02 that
//   connects to AS 1 interface number 2.
// * AS1's interface number 2 has IP 10.123.2.1 and mac address f0:0d:cafe:02:01.
// * AS1's 1st router interface 0 has IP 10.123.10.1 and mac address f0:0d:cafe:10:01.
//
// Functions are provided to generate all addresses following that scheme.

// intfDesc describes an interface requirement.
// The "exclusive" attribute is a directive to the test harness. It means that this connection must
// have an exclusive pair of physical interfaces. The test harness may assign multiple non-exclusive
// address pairs to the same pair of physical interfaces.
// Purpose: Each test case uses only one of the external interface so they can all share the same
// physical link, which simplifies the physical infrastructure of real devices tests.
type intfDesc struct {
	ip        netip.Addr
	peerIP    netip.Addr
	exclusive bool
}

// publicIP returns the IP address that is assigned to external interface designated by the given
// AS index and the peer AS (that is, the AS that this interface connects to).
// Per our scheme, the subnet number is the largest of the two AS numbers and the host is always
// the local AS. This works if there are no cycles. Else there could be subnet number collisions.
func PublicIP(localAS byte, remoteAS byte) netip.Addr {
	subnetNr := max(remoteAS, localAS)
	return netip.AddrFrom4([4]byte{10, 123, subnetNr, localAS})
}

// publicIP returns the IP address that is assigned to external interface designated by the given
// AS index and the peer AS, plus the port to go with.
func PublicIPPort(localAS byte, remoteAS byte) (netip.Addr, layers.UDPPort) {
	return PublicIP(localAS, remoteAS), layers.UDPPort(50000)
}

// internalIP returns the IP address that is assigned to the internal interface of the given
// router in the AS of the given index.
func InternalIP(AS byte, routerIndex byte) netip.Addr {
	return netip.AddrFrom4([4]byte{10, 123, AS * 10, routerIndex})
}

// internalIPPort returns internalIP and the UDPPort to go with.
func InternalIPPort(AS byte, routerIndex byte) (netip.Addr, layers.UDPPort) {
	return InternalIP(AS, routerIndex), layers.UDPPort(30042)
}

// isdAS returns a complete string form ISD/AS number for the given AS index.
// All are in ISD-1, except AS 4.
func ISDAS(AS byte) addr.IA {
	if AS == 4 {
		return addr.MustParseIA(fmt.Sprintf("2-ff00:0:%d", AS))
	}
	return addr.MustParseIA(fmt.Sprintf("1-ff00:0:%d", AS))
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
		interfaceLabel(1, 0): {InternalIP(1, 1), InternalIP(1, 2), true},
		interfaceLabel(1, 2): {PublicIP(1, 2), PublicIP(2, 1), false},
		interfaceLabel(1, 3): {PublicIP(1, 3), PublicIP(3, 1), false},
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

// InitInterfaces collects the names (OS device name) and mac addresses for the interfaces setup by
// the invoker according to instructions given via listInterfaces().
// This information is indexed by our own interface labels.
//
// Returns a list of unique device names that any label maps to. (i.e. devices that at least one
// test will need to open.
func InitInterfaces(pairs []string) []string {
	asSet := make(map[string]struct{}, len(pairs))
	deviceNames = make(map[string]string, len(pairs))
	macAddrs = make(map[netip.Addr]net.HardwareAddr, len(pairs)*2)
	for _, pair := range pairs {
		p := strings.Split(pair, "=")
		label := p[0]
		info := strings.Split(p[1], ",")
		name := info[0]
		deviceNames[label] = name // host-side name (brload's side)
		asSet[name] = struct{}{}
		subjectIP := intfMap[label].ip
		peerIP := intfMap[label].peerIP

		// Now find the MAC addresses, so we don't have to be told.
		device, err := net.InterfaceByName(name)
		if err != nil {
			panic(err)
		}

		// PeerMac (our side): By default we use the real one, but we can be told to use another.
		// (If the link is virtual ethernet, using the real mac address causes serious performance
		// issues, the cause of which has yet to be found).
		peerMAC := device.HardwareAddr
		if len(info) > 1 {
			peerMAC, err = net.ParseMAC(info[1])
			if err != nil {
				panic(err)
			}
		}

		// The subject's MAC needs to be arp'ed.
		arpClient, err := arp.Dial(device)
		if err != nil {
			panic(err)
		}
		err = arpClient.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			panic(err)
		}
		subjectMAC, err := arpClient.Resolve(subjectIP)
		if err != nil {
			panic(err)
		}

		// Done.
		macAddrs[subjectIP] = subjectMAC // ip->mac (side of router under test)
		macAddrs[peerIP] = peerMAC       // peerIP->peerMAC (side mocked by brload)

		// Respond to arp requests so there's no need to add a static arp entry on the router
		// side. We can't assign our address to the interface, so the kernel won't do that for us.
		err = arpClient.SetReadDeadline(time.Time{})
		if err != nil {
			panic(err)
		}
		go func() {
			defer log.HandlePanic()
			// We only respond to the subject, so the reply is always the same.
			reply := arp.Packet{
				HardwareType:       1,
				ProtocolType:       uint16(ethernet.EtherTypeIPv4),
				HardwareAddrLength: 6,
				IPLength:           4,
				Operation:          arp.OperationReply,
				SenderHardwareAddr: peerMAC, // peer is us.
				SenderIP:           peerIP,  // peer is us
				TargetHardwareAddr: subjectMAC,
				TargetIP:           subjectIP,
			}
			for {
				p, _, err := arpClient.Read()
				if err == nil && p.SenderIP == subjectIP {
					_ = arpClient.WriteTo(&reply, subjectMAC)
				}
			}
		}()
	}
	deduped := make([]string, 0, len(asSet))
	for n := range asSet {
		deduped = append(deduped, n)
	}
	return deduped
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

	// This component makes no assumption regarding how the topology is used. We have to support all
	// hosts that the topology describes, even fictional ones, should a test case refer to it.
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
		sb.WriteString(",")
		sb.WriteString(strconv.FormatBool(i.exclusive))
		sb.WriteString("\n")
	}
	// "our_label,24,<ip on router side>,<ip on far side>\n"

	return sb.String()
}
