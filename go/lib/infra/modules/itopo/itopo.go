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

// Package itopo implements convenience functions for topology-related operations.
//
// Additionally, it maintains a pointer to the current configuration (once one
// is set). The package level topology setters and getters can be safely called
// from multiple goroutines.
package itopo

import (
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

const (
	ErrAddressNotFound = "Address not found"
)

var (
	topologyMtx     sync.RWMutex
	currentTopology Topology = nil
)

type Topology interface {
	IA() addr.IA
	MTU() uint16
	Core() bool
	// FIXME(scrye): Give apps the possibility to choose the overlay; see
	// https://github.com/scionproto/scion/issues/1855
	GetAnyAppAddr(svc proto.ServiceType) (*addr.AppAddr, *overlay.OverlayAddr, error)
	GetAnyTopoAddr(svc proto.ServiceType) (*topology.TopoAddr, error)
	GetTopoAddrById(svc proto.ServiceType, id string) (*topology.TopoAddr, error)
	GetAllTopoAddrs(svc proto.ServiceType) ([]topology.TopoAddr, error)
	GetBROverlayAddrByIfid(ifid common.IFIDType) *overlay.OverlayAddr
	GetTopoBRAddrByIfid(ifid common.IFIDType) *topology.TopoBRAddr
	GetAllTopoBRAddrs() map[common.IFIDType]*topology.TopoBRAddr
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
	topologyMtx.RLock()
	t := currentTopology
	topologyMtx.RUnlock()
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

func (topo *topologyS) GetAnyAppAddr(
	svc proto.ServiceType) (*addr.AppAddr, *overlay.OverlayAddr, error) {

	svcInfo, err := topo.getSvcInfo(svc)
	if err != nil {
		return nil, nil, err
	}
	topoAddr := svcInfo.getAnyTopoAddr()
	if topoAddr == nil {
		return nil, nil, common.NewBasicError(ErrAddressNotFound, nil)
	}
	return topoAddr.PublicAddr(topo.Overlay), topoAddr.OverlayAddr(topo.Overlay), nil
}

func (topo *topologyS) GetAnyTopoAddr(svc proto.ServiceType) (*topology.TopoAddr, error) {
	svcInfo, err := topo.getSvcInfo(svc)
	if err != nil {
		return nil, err
	}
	topoAddr := svcInfo.getAnyTopoAddr()
	if topoAddr == nil {
		return nil, common.NewBasicError(ErrAddressNotFound, nil)
	}
	return topoAddr, nil
}

func (topo *topologyS) GetTopoAddrById(svc proto.ServiceType,
	id string) (*topology.TopoAddr, error) {

	svcInfo, err := topo.getSvcInfo(svc)
	if err != nil {
		return nil, err
	}
	topoAddr := svcInfo.getTopoAddrById(id)
	if topoAddr == nil {
		return nil, common.NewBasicError(ErrAddressNotFound, nil)
	}
	return topoAddr, nil
}

func (topo *topologyS) GetAllTopoAddrs(svc proto.ServiceType) ([]topology.TopoAddr, error) {
	svcInfo, err := topo.getSvcInfo(svc)
	if err != nil {
		return nil, err
	}
	topoAddrs := svcInfo.getAllTopoAddrs()
	if topoAddrs == nil {
		return nil, common.NewBasicError(ErrAddressNotFound, nil)
	}
	return topoAddrs, nil
}

func (topo *topologyS) getSvcInfo(svc proto.ServiceType) (*svcInfo, error) {
	switch svc {
	case proto.ServiceType_unset:
		return nil, common.NewBasicError("Service type unset", nil)
	case proto.ServiceType_bs:
		return &svcInfo{overlay: topo.Overlay, names: topo.BSNames, idTopoAddrMap: topo.BS}, nil
	case proto.ServiceType_ps:
		return &svcInfo{overlay: topo.Overlay, names: topo.PSNames, idTopoAddrMap: topo.PS}, nil
	case proto.ServiceType_cs:
		return &svcInfo{overlay: topo.Overlay, names: topo.CSNames, idTopoAddrMap: topo.CS}, nil
	case proto.ServiceType_sb:
		return &svcInfo{overlay: topo.Overlay, names: topo.SBNames, idTopoAddrMap: topo.SB}, nil
	default:
		return nil, common.NewBasicError("Unsupported service type", nil, "type", svc)
	}
}

func (topo *topologyS) GetBROverlayAddrByIfid(ifid common.IFIDType) *overlay.OverlayAddr {
	topoBRAddr := topo.GetTopoBRAddrByIfid(ifid)
	if topoBRAddr == nil {
		return nil
	}
	return topoBRAddr.PublicOverlay(topo.Overlay)
}

func (topo *topologyS) GetTopoBRAddrByIfid(ifid common.IFIDType) *topology.TopoBRAddr {
	if ifInfo, ok := topo.IFInfoMap[ifid]; ok {
		return ifInfo.InternalAddrs
	}
	return nil
}

func (topo *topologyS) GetAllTopoBRAddrs() map[common.IFIDType]*topology.TopoBRAddr {
	m := make(map[common.IFIDType]*topology.TopoBRAddr)
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
