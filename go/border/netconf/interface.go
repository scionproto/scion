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

package netconf

import (
	"net"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/overlay"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/topology"
)

type NetConf struct {
	LocAddr        []*overlay.UDP
	IFs            map[spath.IntfID]*Interface
	LocAddrMap     map[string]int            // Map of local address string to LocAddr index
	IFAddrMap      map[string]spath.IntfID   // Map of external address string to interface ID
	LocAddrIFIDMap map[string][]spath.IntfID // Map of local address string to interface ID(s)
}

func FromTopo(t *topology.TopoBR) *NetConf {
	// TODO(kormat): support multiple internal and external addresses
	n := &NetConf{}
	n.LocAddr = append(n.LocAddr, overlay.NewUDP(t.BasicElem.Addr.IP, t.BasicElem.Port))
	n.IFs = make(map[spath.IntfID]*Interface)
	n.LocAddrMap = make(map[string]int)
	n.IFAddrMap = make(map[string]spath.IntfID)
	n.LocAddrIFIDMap = make(map[string][]spath.IntfID)
	x := intfFromTopoIF(t.IF)
	n.IFs[x.Id] = x
	for i, addr := range n.LocAddr {
		n.LocAddrMap[addr.BindAddr().String()] = i
	}
	for ifid, intf := range n.IFs {
		n.IFAddrMap[intf.IFAddr.BindAddr().String()] = ifid
		key := n.LocAddr[intf.LocAddrIdx].BindAddr().String()
		n.LocAddrIFIDMap[key] = append(n.LocAddrIFIDMap[key], ifid)
	}
	return n
}

func (n *NetConf) IntfLocalAddr(ifid spath.IntfID) *overlay.UDP {
	intf := n.IFs[ifid]
	return n.LocAddr[intf.LocAddrIdx]
}

type Interface struct {
	Id         spath.IntfID
	LocAddrIdx int
	IFAddr     *overlay.UDP
	RemoteAddr *net.UDPAddr
	RemoteIA   *addr.ISD_AS
	BW         int
	MTU        int
	Type       string
}

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
