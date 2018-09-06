// Copyright 2018 ETH Zurich, Anapaya Systems
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

package itopo

import (
	"fmt"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

var (
	topologyMtx     sync.Mutex
	currentTopology Topology = nil
)

type Topology interface {
	IA() addr.IA
	MTU() uint16
	Core() bool
	GetAnyAppAddr(svc proto.ServiceType) *addr.AppAddr
	GetAnyTopoAddr(svc proto.ServiceType) *topology.TopoAddr
	GetTopoAddrById(svc proto.ServiceType, id string) *topology.TopoAddr
	GetAllTopoAddrs(svc proto.ServiceType) []topology.TopoAddr
	GetBROverlayAddrByIfid(ifid common.IFIDType) *overlay.OverlayAddr
	GetBRTopoAddrByIfid(ifid common.IFIDType) *topology.TopoAddr
	GetAllBRTopoAddrs() map[common.IFIDType]*topology.TopoAddr
}

// SetCurrentTopologyFromBase atomically sets the package-wide default topology to
// topo.
func SetCurrentTopologyFromBase(topo *topology.Topo) {
	topologyMtx.Lock()
	currentTopology = NewTopology(topo)
	topologyMtx.Unlock()
}

func SetCurrentTopology(topo Topology) {
	topologyMtx.Lock()
	currentTopology = topo
	topologyMtx.Unlock()
}

// GetCurrentTopology atomically returns a pointer to the package-wide
// default topology.
func GetCurrentTopology() Topology {
	topologyMtx.Lock()
	t := currentTopology
	topologyMtx.Unlock()
	return t
}

type topologyS struct {
	*topology.Topo
}

func NewTopology(topo *topology.Topo) Topology {
	return &topologyS{Topo: topo}
}

func (topo *topologyS) IA() addr.IA {
	return topo.ISD_AS
}

func (topo *topologyS) MTU() uint16 {
	return uint16(topo.Topo.MTU)
}

func (topo *topologyS) Core() bool {
	return topo.Topo.Core
}

func (topo *topologyS) GetAnyAppAddr(svc proto.ServiceType) *addr.AppAddr {
	svcInfo := topo.getSvcInfo(svc)
	if svcInfo == nil {
		return nil
	}
	return svcInfo.getAnyAppAddr()
}

func (topo *topologyS) GetAnyTopoAddr(svc proto.ServiceType) *topology.TopoAddr {
	svcInfo := topo.getSvcInfo(svc)
	if svcInfo == nil {
		return nil
	}
	return svcInfo.getAnyTopoAddr()
}

func (topo *topologyS) GetTopoAddrById(svc proto.ServiceType, id string) *topology.TopoAddr {
	svcInfo := topo.getSvcInfo(svc)
	if svcInfo == nil {
		return nil
	}
	return svcInfo.getTopoAddrById(id)
}

func (topo *topologyS) GetAllTopoAddrs(svc proto.ServiceType) []topology.TopoAddr {
	svcInfo := topo.getSvcInfo(svc)
	if svcInfo == nil {
		return nil
	}
	return svcInfo.getAllTopoAddrs()
}

func (topo *topologyS) getSvcInfo(svc proto.ServiceType) *svcInfo {
	switch svc {
	case proto.ServiceType_unset:
		// FIXME(lukedirtwalker): inform client about this:
		// see https://github.com/scionproto/scion/issues/1673
		return nil
	case proto.ServiceType_bs:
		return &svcInfo{overlay: topo.Overlay, names: topo.BSNames, idTopoAddrMap: topo.BS}
	case proto.ServiceType_ps:
		return &svcInfo{overlay: topo.Overlay, names: topo.PSNames, idTopoAddrMap: topo.PS}
	case proto.ServiceType_cs:
		return &svcInfo{overlay: topo.Overlay, names: topo.CSNames, idTopoAddrMap: topo.CS}
	case proto.ServiceType_sb:
		return &svcInfo{overlay: topo.Overlay, names: topo.SBNames, idTopoAddrMap: topo.SB}
	default:
		panic(fmt.Sprintf("unknown svc type %v", svc))
	}
}

func (topo *topologyS) GetBROverlayAddrByIfid(ifid common.IFIDType) *overlay.OverlayAddr {
	topoAddr := topo.GetBRTopoAddrByIfid(ifid)
	if topoAddr == nil {
		return nil
	}
	return topoAddr.PublicOverlay(topo.Overlay)
}

func (topo *topologyS) GetBRTopoAddrByIfid(ifid common.IFIDType) *topology.TopoAddr {
	if ifInfo, ok := topo.IFInfoMap[ifid]; ok {
		return ifInfo.InternalAddrs
	}
	return nil
}

func (topo *topologyS) GetAllBRTopoAddrs() map[common.IFIDType]*topology.TopoAddr {
	m := make(map[common.IFIDType]*topology.TopoAddr)
	for ifid, ifInfo := range topo.IFInfoMap {
		m[ifid] = ifInfo.InternalAddrs
	}
	return m
}

// svcInfo contains topology information for a single SCION service
type svcInfo struct {
	overlay       overlay.Type
	names         topology.ServiceNames
	idTopoAddrMap topology.IDAddrMap
}

func (svc *svcInfo) getAnyAppAddr() *addr.AppAddr {
	topoAddr := svc.getAnyTopoAddr()
	if topoAddr == nil {
		return nil
	}
	return topoAddr.PublicAddr(svc.overlay)
}

func (svc *svcInfo) getAnyTopoAddr() *topology.TopoAddr {
	id, err := svc.names.GetRandom()
	if err != nil {
		return nil
	}
	return svc.idTopoAddrMap.GetById(id)
}

func (svc *svcInfo) getTopoAddrById(id string) *topology.TopoAddr {
	return svc.idTopoAddrMap.GetById(id)
}

func (svc *svcInfo) getAllTopoAddrs() []topology.TopoAddr {
	var topoAddrs []topology.TopoAddr
	for _, topoAddr := range svc.idTopoAddrMap {
		topoAddrs = append(topoAddrs, topoAddr)
	}
	return topoAddrs
}
