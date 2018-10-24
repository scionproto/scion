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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

// NetConf contains the local addresses, interface config, and some maps for
// accessing these by different methods.
type NetConf struct {
	// LocAddr is the local data-plane addresses from the topology.
	LocAddr *topology.TopoBRAddr
	// CtrlAddr is the local control-plane addresses from the topology.
	CtrlAddr *topology.TopoAddr
	// IFs maps interface IDs to Interfaces.
	IFs map[common.IFIDType]*Interface
	// IFAddrMap maps external public address strings to interface IDs.
	IFAddrMap map[string]common.IFIDType
}

// FromTopo creates a NetConf instance from the topology.
func FromTopo(intfs []common.IFIDType, infomap map[common.IFIDType]topology.IFInfo) (
	*NetConf, error) {
	n := &NetConf{}
	n.IFs = make(map[common.IFIDType]*Interface)
	for _, ifid := range intfs {
		ifinfo := infomap[ifid]
		if n.LocAddr == nil {
			n.LocAddr = ifinfo.InternalAddrs
		} else if assert.On {
			assert.Must(n.LocAddr == ifinfo.InternalAddrs,
				"Cannot have multiple local data-plane addresses")
		}
		if n.CtrlAddr == nil {
			n.CtrlAddr = ifinfo.CtrlAddrs
		} else if assert.On {
			assert.Must(n.CtrlAddr == ifinfo.CtrlAddrs,
				"Cannot have multiple local control-plane addresses")
		}
		if ifinfo.Local == nil {
			return nil, common.NewBasicError("Local address not initialized", nil, "ifid", ifid)
		}
		if ifinfo.Remote == nil {
			return nil, common.NewBasicError("Remote address not initialized", nil, "ifid", ifid)
		}
		if ifinfo.Overlay == overlay.Invalid {
			return nil, common.NewBasicError("Interface overlay not initialized", nil, "ifid", ifid)
		}
		v, ok := n.IFs[ifid]
		newIF := intfFromTopoIF(&ifinfo, ifid)
		if ok {
			return nil, common.NewBasicError("Duplicate ifid", nil,
				"ifid", ifid, "first", v, "second", newIF)
		}
		n.IFs[ifid] = newIF
	}
	n.IFAddrMap = make(map[string]common.IFIDType, len(n.IFs))
	for ifid, intf := range n.IFs {
		// Add mapping of interface public address to this interface ID.
		if intf.IFAddr.IPv4 != nil {
			n.IFAddrMap[fmt.Sprintf("%s", intf.IFAddr.IPv4.PublicOverlay)] = ifid
		}
		if intf.IFAddr.IPv6 != nil {
			n.IFAddrMap[fmt.Sprintf("%s", intf.IFAddr.IPv6.PublicOverlay)] = ifid
		}
	}
	return n, nil
}

// Interface describes the configuration of a router interface.
type Interface struct {
	// Id is the interface ID. It is unique per AS.
	Id common.IFIDType
	// IFAddr contains both the bind address and the public address of the
	// interface. Normally these are the same, but for example in the case of
	// NAT, the bind address may differ from the address visible from outside
	// the AS.
	IFAddr *topology.TopoBRAddr
	// RemoteAddr is the public address of the border router on the other end
	// of the link.
	RemoteAddr *overlay.OverlayAddr
	// RemoteIA is the ISD-AS of the other end of the link.
	RemoteIA addr.IA
	// BW is the bandwidth of the link.
	BW int
	// MTU is the maximum packet size allowed on the link, in bytes.
	MTU int
	// Type describes the type of link, in terms of relationship between this
	// AS and the remote AS.
	Type proto.LinkType
}

// intfFromTopoIF is a constructor to create a new Interface instance from a
// TopoIF.
func intfFromTopoIF(t *topology.IFInfo, ifid common.IFIDType) *Interface {
	intf := Interface{}
	intf.Id = ifid
	intf.IFAddr = t.Local
	intf.RemoteAddr = t.Remote
	intf.RemoteIA = t.ISD_AS
	intf.BW = t.Bandwidth
	intf.MTU = t.MTU
	intf.Type = t.LinkType
	return &intf
}
