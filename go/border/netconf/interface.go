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
	"fmt"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/topology"
)

// NetConf contains the local addresses, interface config, and some maps for
// accessing these by different methods.
type NetConf struct {
	// LocAddr is a slice containing the local addresses in order from the
	// topology.
	LocAddr []*topology.TopoAddr
	// IFs maps interface IDs to Interfaces.
	IFs map[common.IFIDType]*Interface
	// LocAddrMap maps local public address strings to LocAddr indices.
	LocAddrMap map[string]int
	// IFAddrMap maps external public address strings to interface IDs.
	IFAddrMap map[string]common.IFIDType
	// LocAddrIFIDMap maps local address strings to (potentially multiple)
	// interface IDs.
	LocAddrIFIDMap map[string][]common.IFIDType
}

// FromTopo creates a NetConf instance from the topology.
func FromTopo(intfs []common.IFIDType, infomap map[common.IFIDType]topology.IFInfo) (
	*NetConf, error) {
	n := &NetConf{}
	locIdxes := make(map[int]*topology.TopoAddr)
	n.IFs = make(map[common.IFIDType]*Interface)
	for _, ifid := range intfs {
		ifinfo := infomap[ifid]
		if v, ok := locIdxes[ifinfo.InternalAddrIdx]; ok && v != ifinfo.InternalAddr {
			return nil, common.NewCError("Duplicate local address index",
				"idx", ifinfo.InternalAddrIdx, "first", v, "second", ifinfo.InternalAddr)
		}
		locIdxes[ifinfo.InternalAddrIdx] = ifinfo.InternalAddr
		v, ok := n.IFs[ifid]
		newIF := intfFromTopoIF(&ifinfo, ifid)
		if ok {
			return nil, common.NewCError("Duplicate ifid",
				"ifid", ifid, "first", v, "second", newIF)
		}
		n.IFs[ifid] = newIF
	}
	n.LocAddr = make([]*topology.TopoAddr, len(locIdxes))
	n.LocAddrMap = make(map[string]int, len(locIdxes))
	n.LocAddrIFIDMap = make(map[string][]common.IFIDType, len(locIdxes))
	// XXX(kormat): deliberately using a counter, and not iterating over the keys of the map,
	// so that non-contiguous indexes will be caught.
	for idx := 0; idx < len(locIdxes); idx++ {
		taddr, ok := locIdxes[idx]
		if !ok {
			return nil, common.NewCError("Non-contiguous local address indexes", "missing", idx)
		}
		n.LocAddr[idx] = taddr
		if taddr.IPv4 != nil {
			n.LocAddrMap[keyFromTopoAddr(taddr, overlay.IPv4)] = idx
		}
		if taddr.IPv6 != nil {
			n.LocAddrMap[keyFromTopoAddr(taddr, overlay.IPv6)] = idx
		}
	}
	n.IFAddrMap = make(map[string]common.IFIDType, len(n.IFs))
	for ifid, intf := range n.IFs {
		var key string
		// Add mapping of interface public address to this interface ID.
		if intf.IFAddr.IPv4 != nil {
			n.IFAddrMap[keyFromTopoAddr(intf.IFAddr, overlay.IPv4)] = ifid
		}
		if intf.IFAddr.IPv6 != nil {
			n.IFAddrMap[keyFromTopoAddr(intf.IFAddr, overlay.IPv6)] = ifid
		}
		if n.LocAddr[intf.LocAddrIdx].IPv4 != nil {
			key = keyFromTopoAddr(n.LocAddr[intf.LocAddrIdx], overlay.IPv4)
			// Add interface ID to local addr -> ifid mapping.
			n.LocAddrIFIDMap[key] = append(n.LocAddrIFIDMap[key], ifid)
		}
		if n.LocAddr[intf.LocAddrIdx].IPv6 != nil {
			key = keyFromTopoAddr(n.LocAddr[intf.LocAddrIdx], overlay.IPv6)
			// Add interface ID to local addr -> ifid mapping.
			n.LocAddrIFIDMap[key] = append(n.LocAddrIFIDMap[key], ifid)
		}
	}
	return n, nil
}

// IntfLocalAddr retrieves the local address for a given interface.
func (n *NetConf) IntfLocalAddr(ifid common.IFIDType) *topology.TopoAddr {
	intf := n.IFs[ifid]
	return n.LocAddr[intf.LocAddrIdx]
}

// Interface describes the configuration of a router interface.
type Interface struct {
	// Id is the interface ID. It is unique per AS.
	Id common.IFIDType
	// LocAddrIdx specifies which local address is associated with this
	// interface.
	LocAddrIdx int
	// IFAddr contains both the bind address and the public address of the
	// interface. Normally these are the same, but for example in the case of
	// NAT, the bind address may differ from the address visible from outside
	// the AS.
	IFAddr *topology.TopoAddr
	// RemoteAddr is the public address of the border router on the other end
	// of the link.
	RemoteAddr *topology.AddrInfo
	// RemoteIA is the ISD-AS of the other end of the link.
	RemoteIA *addr.ISD_AS
	// BW is the bandwidth of the link.
	BW int
	// MTU is the maximum packet size allowed on the link, in bytes.
	MTU int
	// Type describes the type of link, in terms of relationship between this
	// AS and the remote AS.
	// TODO(kormat): switch to a non-string type.
	Type topology.LinkType
}

// intfFromTopoIF is a constructor to create a new Interface instance from a
// TopoIF.
func intfFromTopoIF(t *topology.IFInfo, ifid common.IFIDType) *Interface {
	intf := Interface{}
	intf.Id = ifid
	intf.LocAddrIdx = t.InternalAddrIdx
	intf.IFAddr = t.Local
	intf.RemoteAddr = t.Remote
	intf.RemoteIA = t.ISD_AS
	intf.BW = t.Bandwidth
	intf.MTU = t.MTU
	intf.Type = t.LinkType
	return &intf
}

// This format must be kept in sync with AddrInfo.Key() (from lib/topology/addr.go)
func keyFromTopoAddr(t *topology.TopoAddr, ot overlay.Type) string {
	if ot.IsIPv4() {
		return fmt.Sprintf("%s:%d", t.IPv4.PublicAddr(), t.IPv4.PublicL4Port())
	}
	return fmt.Sprintf("%s:%d", t.IPv6.PublicAddr(), t.IPv6.PublicL4Port())
}
