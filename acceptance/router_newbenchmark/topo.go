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
// To further simplify the explicit configuration that we need, the topology follows a convention
// to assign addresses, so that an address can be derived from a minimal descriptor. AS-1 is the hub
// of the test.
// All IPs are V4.
// ISD/AS: <1 or 2>-ff00:0:<AS index>
// interface number: <remote AS index>
// public IP address for interfaces of AS-1: 192.168.<remote AS index>.<local AS index>
// public IP address for interfaces of others: 192.168.<local AS index>.<local AS index>
// internal IP address: 192.168.<AS index>*10.<router index>
// MAC Address: 0xf0, 0x0d, 0xfe, 0xbe, <last two bytes of IP>
// Internal port: 30042
// External port: 50000
// As a result, children ASes (like AS2) have addresses ending in N.N and interface N where N is
// the AS number. For br1a/b, interfaces are numbered after the child on the other side, the
// public IPS are <childAS>.1 and the internal IP ends in 0.1 or 0.2. The MAC addresses follow.
//
// The invoker of this test is in charge of configuring a router with the custom topology
// (conf/topology.json) and to setup host-side interfaces as needed, through which this test can
// inject traffic. This test does not control the names of the host-side interfaces; they're
// supplied by the invoker.
//
// To make the invoker's life easier, this test output what host side interfaces it may need
// (and connected to what) when invoked with --show_interfaces. If the router runs inside a network
// namespace, the invoker must configure veths accordingly; otherwise, find which real interfaces
// this test should use.

var (
	intfMap map[string]string = map[string]string{}
)

func LoadInterfaceMap(pairs []string) {
	for _, pair := range pairs {
		p := strings.Split(pair, "=")
		intfMap[p[0]] = p[1]
	}
}

// We give abstract names to our interfaces. These names are those used when responding to
// --show_interfaces and used to translate --interface.
func interfaceLabel(AS int, intf int) string {
	return fmt.Sprintf("%d_%d", AS, intf)
}

func interfaceName(AS int, intf int) string {
	return intfMap[interfaceLabel(AS, intf)]
}

// Local and remote AS are enough. One of them is the central AS (1). The subnet number is that of
// the other AS. The host is always the local AS. If neither is 1, then we follow the lowest, but
// it's an unexpected config
func publicIP(localAS byte, remoteAS byte) net.IP {
	if localAS < remoteAS {
		return net.IP{192, 168, remoteAS, localAS}
	}
	return net.IP{192, 168, localAS, localAS}
}

func internalIP(AS byte, router byte) net.IP {
	return net.IP{192, 168, AS * 10, router}
}

// All are in ISD-1, except AS 4.
func isdAS(AS byte) addr.IA {
	if AS == 4 {
		return xtest.MustParseIA(fmt.Sprintf("2-ff00:0:%d", AS))
	}
	return xtest.MustParseIA(fmt.Sprintf("1-ff00:0:%d", AS))
}

// Macs derive from IP in the most straighforward manner.
func macAddr(ip net.IP) net.HardwareAddr {
	return net.HardwareAddr{0xf0, 0x0d, 0xca, 0xfe, ip[2], ip[3]}
}

// SCION Hosts addresses are (except for SVC addresses, a restating of the underlay public IP.
func hostAddr(ip net.IP) addr.Host {
	as4bytes := [4]uint8{ip[0], ip[1], ip[2], ip[3]}
	return addr.HostIP(netip.AddrFrom4(as4bytes))
}

// Outputs a string describing the interfaces of the router under test.
// This test needs access to interfaces that connect to them. In a container setting, it also needs
// the container network configured accordingly, (hence the inclusion of router-side addresses.
// The given names are only labels, the real interface names (and mac addresses associated with
// them) shall be provided when the test is executed for real (without the --show_interfaces
// option).
func ShowInterfaces() string {
	// For now, we only need:
	// AS1 interface 0 (internal)
	// AS1 interface 2
	// AS1 interface 3
	return "" +
		interfaceLabel(1, 0) + " 24 192.168.10.1 f0:0d:ca:fe:10:01 192.168.10.2 f0:0d:ca:fe:10:02\n" +
		interfaceLabel(1, 2) + " 24 192.168.2.1 f0:0d:ca:fe:02:01 192.168.2.2 f0:0d:ca:fe:02:02\n" +
		interfaceLabel(1, 3) + " 24 192.168.3.1 f0:0d:ca:fe:03:01 192.168.3.3 f0:0d:ca:fe:03:03\n"

}
