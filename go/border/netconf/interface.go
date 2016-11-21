// Copyright 2016 ETH Zurich
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

// Package netconf handles the network configuration of the router as described
// by the topology.
//
// Multiple interfaces can share the same local addresses, so this package
// supplies support for determining the local address for a given interface,
// and for determining a list of interfaces for a given local address.
// (Local address is defined as an address internal to the local AS.)
package netconf

import (
	"net"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/topology"
)

// NetConf contains the local addresses, interface config, and some maps for
// accessing these by different methods.
type NetConf struct {
	// LocAddr is a slice containing the local addresses in order from the
	// topology.
	LocAddr []*overlay.UDP
	// IFs maps interface IDs to Interfaces.
	IFs map[spath.IntfID]*Interface
	// LocAddrMap maps local address strings to LocAddr indices.
	LocAddrMap map[string]int
	// IFAddrMap maps external address strings to interface IDs.
	IFAddrMap map[string]spath.IntfID
	// LocAddrIFIDMap maps local address strings to (potentially multiple)
	// interface IDs.
	LocAddrIFIDMap map[string][]spath.IntfID
}

// FromTopo creates a NetConf instance from the topology.
func FromTopo(t *topology.TopoBR) *NetConf {
	n := &NetConf{}
	// TODO(kormat): support multiple addresses
	n.LocAddr = append(n.LocAddr, overlay.NewUDP(t.BasicElem.Addr.IP, t.BasicElem.Port))
	n.IFs = make(map[spath.IntfID]*Interface)
	n.LocAddrMap = make(map[string]int, len(n.LocAddr))
	n.IFAddrMap = make(map[string]spath.IntfID, len(n.IFs))
	n.LocAddrIFIDMap = make(map[string][]spath.IntfID, len(n.LocAddr))
	// TODO(kormat): support multiple interfaces
	x := intfFromTopoIF(t.IF)
	n.IFs[x.Id] = x
	for i, addr := range n.LocAddr {
		n.LocAddrMap[addr.BindAddr().String()] = i
	}
	for ifid, intf := range n.IFs {
		// Add mapping of interface bind address to this interface ID.
		n.IFAddrMap[intf.IFAddr.BindAddr().String()] = ifid
		key := n.LocAddr[intf.LocAddrIdx].BindAddr().String()
		// Add interface ID to local addr -> ifid mapping.
		n.LocAddrIFIDMap[key] = append(n.LocAddrIFIDMap[key], ifid)
	}
	return n
}

// IntfLocalAddr retrieves the local address for a given interface.
func (n *NetConf) IntfLocalAddr(ifid spath.IntfID) *overlay.UDP {
	intf := n.IFs[ifid]
	return n.LocAddr[intf.LocAddrIdx]
}

// Interface describes the configuration of a router interface.
type Interface struct {
	// Id is the interface ID. It is unique per AS.
	Id spath.IntfID
	// LocAddrIdx specifies which local address is associated with this
	// interface.
	LocAddrIdx int
	// IFAddr contains both the bind address and the public address of the
	// interface. Normally these are the same, but for example in the case of
	// NAT, the bind address may differ from the address visible from outside
	// the AS.
	IFAddr *overlay.UDP
	// RemoteAddr is the public address of the border router on the other end
	// of the link.
	RemoteAddr *net.UDPAddr
	// RemoteIA is the ISD-AS of the other end of the link.
	RemoteIA *addr.ISD_AS
	// BW is the bandwidth of the link.
	BW int
	// MTU is the maximum packet size allowed on the link, in bytes.
	MTU int
	// Type describes the type of link, in terms of relationship between this
	// AS and the remote AS.
	// TODO(kormat): switch to a non-string type.
	Type string
}

// intfFromTopoIF is a constructor to create a new Interface instance from a
// TopoIF.
func intfFromTopoIF(t *topology.TopoIF) *Interface {
	intf := Interface{}
	intf.Id = spath.IntfID(t.IFID)
	// FIXME(kormat): to be changed when the topo format is updated.
	intf.LocAddrIdx = 0
	intf.IFAddr = overlay.NewUDP(t.Addr.IP, t.UdpPort)
	intf.RemoteAddr = &net.UDPAddr{IP: t.ToAddr.IP, Port: t.ToUdpPort}
	intf.RemoteIA = t.IA
	intf.BW = t.BW
	intf.MTU = t.MTU
	intf.Type = t.LinkType
	return &intf
}
