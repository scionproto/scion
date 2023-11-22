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

package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
)

// Topology (see accept/router_newbenchmark/conf/topology.json)
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
// * ISD/AS: <1 or 2>-ff00:0:<AS index>
// * subnets are 192.168.<child AS number> except internal subnets that are 192.168.10*<AS>.<rtr>
// * hosts are 192.168.s.<interface number>
// * Mac addressed (when we can choose) derive from the IP
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
func publicIP(localAS byte, remoteAS byte) netip.Addr {
	if remoteAS > localAS {
		return netip.AddrFrom4([4]byte{192, 168, remoteAS, localAS})
	}
	return netip.AddrFrom4([4]byte{192, 168, localAS, localAS})
}

// internalIP returns the IP address that is assigned to the internal interface of the given
// router in the AS of the given index.
func internalIP(AS byte, routerIndex byte) netip.Addr {
	return netip.AddrFrom4([4]byte{192, 168, AS * 10, routerIndex})
}

// interfaceLabel returns a string label for the gievn AS and interface indices.
// Such names are those used when responding to --show_interfaces and when translating --interface.
func interfaceLabel(AS int, intf int) string {
	return fmt.Sprintf("%d_%d", AS, intf)
}

// isdAS returns a complete string form ISD/AS number for the given AS index.
// All are in ISD-1, except AS 4.
func isdAS(AS byte) addr.IA {
	if AS == 4 {
		return xtest.MustParseIA(fmt.Sprintf("2-ff00:0:%d", AS))
	}
	return xtest.MustParseIA(fmt.Sprintf("1-ff00:0:%d", AS))
}

var (
	// intfMap lists the required interfaces. That's what we use to respond to showInterfaces
	intfMap map[string]intfDesc = map[string]intfDesc{
		interfaceLabel(1, 0): {internalIP(1, 1), internalIP(1, 2)},
		interfaceLabel(1, 2): {publicIP(1, 2), publicIP(2, 1)},
		interfaceLabel(1, 3): {publicIP(1, 3), publicIP(3, 1)},
	}

	// intfNames holds the real names of our required interfaces. It is populated from the values of
	// the --interface options.
	intfNames map[string]string = map[string]string{}

	// macAddresses keeps the mac addresses associated with each IP. It is populated from the values
	// of the --interface options. There are more than intfMap interfaces since we need the peer
	// addresses too. Additional IPS not from intfMap have no known mac addresses; we are free to
	// make them up to make credible packets.
	macAddrs map[netip.Addr]net.HardwareAddr = map[netip.Addr]net.HardwareAddr{}
)

// initInterfaces collects the names and mac addresses for the interfaces setup by the invoker
// according to instructions given via listInterfaces().
// This information is indexed by our own interface labels.
func initInterfaces(pairs []string) {
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
		intfNames[label] = info[0]                 // host-side name
		macAddrs[intfMap[label].ip] = addr         // ip->mac
		macAddrs[intfMap[label].peerIP] = peerAddr // peerIP->peerMAC
	}
}

// interfaceName returns the name of the host interface that this test must use in order to exchange
// traffic with the interface designated by the given AS and interface indices.
func interfaceName(AS int, intf int) string {
	return intfNames[interfaceLabel(AS, intf)]
}

// macAddr returns the mac address assigned to the interface that has the given IP address.
// if that address is imposed by our environment it is listed in the macAddrs map and that is what
// this function returns. Else, the address is made-up according to our scheme.
func macAddr(ip netip.Addr) net.HardwareAddr {
	// Look it up or make it up.
	mac, ok := macAddrs[ip]
	if ok {
		return mac
	}
	as4 := ip.As4()
	return net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, as4[2], as4[3]}
}

// hostAddr returns a the SCION Hosts addresse that corresponds to the given underlay address.
// Except for SVC addresses (which we do not support here), this is a restating of the underlay
// address.
func hostAddr(ip netip.Addr) addr.Host {
	return addr.HostIP(ip)
}

// ListInterfaces outputs a string describing the interfaces of the router under test.
// The invoker of this test gets this when using the --show_interfaces option and is expected
// to set up the network accordingly before executing the test without that option.
// We do not choose interface names or mac addresses those will be provided by the invoker
// via the --interfaces options.
func listInterfaces() string {
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

	return sb.String()
}
