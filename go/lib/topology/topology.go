// Copyright 2016 ETH Zurich
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

package topology

import (
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/proto"
)

type IDAddrMap map[string]TopoAddr

// GetById returns the TopoAddr for the given ID, or nil if there is none.
func (m IDAddrMap) GetById(id string) *TopoAddr {
	if _, ok := m[id]; ok {
		cp := m[id]
		return &cp
	}
	return nil
}

type ServiceNames []string

// GetRandom returns a random entry, or an error if the slice is empty.
func (s ServiceNames) GetRandom() (string, error) {
	numServers := len(s)
	if numServers == 0 {
		return "", common.NewBasicError("No names present", nil)
	}
	return s[rand.Intn(numServers)], nil
}

// Topo is the main struct encompassing topology information for use in Go code.
// The first section contains metadata about the topology. All of these fields
// should be self-explanatory.
// The second section concerns the Border routers. BRNames is just a sorted slice
// of the names of the BRs in this topolgy. Its contents is exactly the same as
// the keys in the BR map.
//
// The BR map points from border router names to BRInfo structs, which in turn
// are lists of IFID type slices, thus defines the IFIDs that belong to a
// particular border router. The IFInfoMap points from interface IDs to IFInfo structs.
//
// The third section in Topo concerns the SCION-specific services in the topology.
// The structure is identical between the various elements. For each service,
// there is again a sorted slice of names of the servers that provide the service.
// Additionally, there is a map from those names to TopoAddr structs.
type Topo struct {
	Timestamp      time.Time
	TimestampHuman string // This can vary wildly in format and is only for informational purposes.
	ISD_AS         addr.IA
	Overlay        overlay.Type
	MTU            int
	Core           bool

	BR      map[string]BRInfo
	BRNames []string
	// This maps Interface IDs to internal addresses. Clients use this to
	// figure out which internal BR address they have to send their traffic to
	// if they want to use a given interface.
	IFInfoMap map[common.IFIDType]IFInfo

	BS       IDAddrMap
	BSNames  ServiceNames
	CS       IDAddrMap
	CSNames  ServiceNames
	PS       IDAddrMap
	PSNames  ServiceNames
	SB       IDAddrMap
	SBNames  ServiceNames
	RS       IDAddrMap
	RSNames  ServiceNames
	DS       IDAddrMap
	DSNames  ServiceNames
	SIG      IDAddrMap
	SIGNames ServiceNames

	ZK map[int]*addr.AppAddr
}

// Create new empty Topo object, including all possible service maps etc.
func NewTopo() *Topo {
	return &Topo{
		BR:        make(map[string]BRInfo),
		BS:        make(IDAddrMap),
		CS:        make(IDAddrMap),
		PS:        make(IDAddrMap),
		SB:        make(IDAddrMap),
		RS:        make(IDAddrMap),
		SIG:       make(IDAddrMap),
		DS:        make(IDAddrMap),
		ZK:        make(map[int]*addr.AppAddr),
		IFInfoMap: make(map[common.IFIDType]IFInfo),
	}
}

// Convert a JSON-filled RawTopo to a Topo usabled by Go code.
func TopoFromRaw(raw *RawTopo) (*Topo, error) {
	t := NewTopo()

	if err := t.populateMeta(raw); err != nil {
		return nil, err
	}
	if err := t.populateBR(raw); err != nil {
		return nil, err
	}
	if err := t.populateServices(raw); err != nil {
		return nil, err
	}
	if err := t.zkSvcFromRaw(raw.ZookeeperService); err != nil {
		return nil, err
	}

	return t, nil
}

func (t *Topo) populateMeta(raw *RawTopo) error {
	// These fields can be simply copied
	var err error
	t.Timestamp = time.Unix(raw.Timestamp, 0)
	t.TimestampHuman = raw.TimestampHuman

	if t.ISD_AS, err = addr.IAFromString(raw.ISD_AS); err != nil {
		return err
	}
	if t.ISD_AS.I == 0 || t.ISD_AS.A == 0 {
		return common.NewBasicError("IA contains wildcard", nil, "ia", t.ISD_AS)
	}
	if t.Overlay, err = overlay.TypeFromString(raw.Overlay); err != nil {
		return err
	}
	t.MTU = raw.MTU
	t.Core = raw.Core
	return nil
}

func (t *Topo) populateBR(raw *RawTopo) error {
	for name, rawBr := range raw.BorderRouters {
		if rawBr.CtrlAddr == nil {
			return common.NewBasicError("Missing Control Address", nil, "br", name)
		}
		if rawBr.InternalAddrs == nil {
			return common.NewBasicError("Missing Internal Address", nil, "br", name)
		}
		ctrlAddr, err := topoAddrFromRAM(rawBr.CtrlAddr, t.Overlay)
		if err != nil {
			return err
		}
		intAddr, err := topoBRAddrFromRBRAM(rawBr.InternalAddrs, t.Overlay)
		if err != nil {
			return err
		}
		brInfo := BRInfo{}
		for ifid, rawIntf := range rawBr.Interfaces {
			var err error
			brInfo.IFIDs = append(brInfo.IFIDs, ifid)
			ifinfo := IFInfo{
				BRName:        name,
				InternalAddrs: intAddr,
				CtrlAddrs:     ctrlAddr,
				Bandwidth:     rawIntf.Bandwidth,
				MTU:           rawIntf.MTU,
			}
			if ifinfo.ISD_AS, err = addr.IAFromString(rawIntf.ISD_AS); err != nil {
				return err
			}
			if ifinfo.LinkType, err = LinkTypeFromString(rawIntf.LinkTo); err != nil {
				return err
			}
			if err = ifinfo.Verify(t.Core, name); err != nil {
				return err
			}
			// These fields are only necessary for the border router.
			// Parsing should not fail if they are missing.
			if rawIntf.Overlay == "" && rawIntf.BindOverlay == nil && rawIntf.RemoteOverlay == nil {
				t.IFInfoMap[ifid] = ifinfo
				continue
			}
			if ifinfo.Overlay, err = overlay.TypeFromString(rawIntf.Overlay); err != nil {
				return err
			}
			if ifinfo.Local, err = rawIntf.localTopoBRAddr(ifinfo.Overlay); err != nil {
				return err
			}
			if ifinfo.Remote, err = rawIntf.remoteBRAddr(ifinfo.Overlay); err != nil {
				return err
			}
			t.IFInfoMap[ifid] = ifinfo
		}
		t.BR[name] = brInfo
		t.BRNames = append(t.BRNames, name)
	}
	sort.Strings(t.BRNames)
	return nil
}

func (t *Topo) populateServices(raw *RawTopo) error {
	// Populate BS, CS, PS, SB, RS, SIG and DS maps
	var err error
	t.BSNames, err = svcMapFromRaw(raw.BeaconService, common.BS, t.BS, t.Overlay)
	if err != nil {
		return err
	}
	t.CSNames, err = svcMapFromRaw(raw.CertificateService, common.CS, t.CS, t.Overlay)
	if err != nil {
		return err
	}
	t.PSNames, err = svcMapFromRaw(raw.PathService, common.PS, t.PS, t.Overlay)
	if err != nil {
		return err
	}
	t.SBNames, err = svcMapFromRaw(raw.SibraService, common.SB, t.SB, t.Overlay)
	if err != nil {
		return err
	}
	t.RSNames, err = svcMapFromRaw(raw.RainsService, common.RS, t.RS, t.Overlay)
	if err != nil {
		return err
	}
	t.SIGNames, err = svcMapFromRaw(raw.SIG, common.SIG, t.SIG, t.Overlay)
	if err != nil {
		return err
	}
	t.DSNames, err = svcMapFromRaw(raw.DiscoveryService, common.DS, t.DS, t.Overlay)
	if err != nil {
		return err
	}
	return nil
}

func (t *Topo) GetAllTopoAddrs(svc proto.ServiceType) ([]TopoAddr, error) {
	svcInfo, err := t.GetSvcInfo(svc)
	if err != nil {
		return nil, err
	}
	topoAddrs := svcInfo.GetAllTopoAddrs()
	if topoAddrs == nil {
		return nil, common.NewBasicError("Address not found", nil)
	}
	return topoAddrs, nil
}

func (t *Topo) GetSvcInfo(svc proto.ServiceType) (*SVCInfo, error) {
	switch svc {
	case proto.ServiceType_unset:
		return nil, common.NewBasicError("Service type unset", nil)
	case proto.ServiceType_bs:
		return &SVCInfo{overlay: t.Overlay, names: t.BSNames, idTopoAddrMap: t.BS}, nil
	case proto.ServiceType_ps:
		return &SVCInfo{overlay: t.Overlay, names: t.PSNames, idTopoAddrMap: t.PS}, nil
	case proto.ServiceType_cs:
		return &SVCInfo{overlay: t.Overlay, names: t.CSNames, idTopoAddrMap: t.CS}, nil
	case proto.ServiceType_sb:
		return &SVCInfo{overlay: t.Overlay, names: t.SBNames, idTopoAddrMap: t.SB}, nil
	case proto.ServiceType_sig:
		return &SVCInfo{overlay: t.Overlay, names: t.SIGNames, idTopoAddrMap: t.SIG}, nil
	case proto.ServiceType_ds:
		return &SVCInfo{overlay: t.Overlay, names: t.DSNames, idTopoAddrMap: t.DS}, nil
	default:
		return nil, common.NewBasicError("Unsupported service type", nil, "type", svc)
	}
}

// SVCInfo contains topology information for a single SCION service
type SVCInfo struct {
	overlay       overlay.Type
	names         ServiceNames
	idTopoAddrMap IDAddrMap
}

func (svc *SVCInfo) GetAnyTopoAddr() *TopoAddr {
	id, err := svc.names.GetRandom()
	if err != nil {
		return nil
	}
	return svc.idTopoAddrMap.GetById(id)
}

func (svc *SVCInfo) GetAllTopoAddrs() []TopoAddr {
	var topoAddrs []TopoAddr
	for _, topoAddr := range svc.idTopoAddrMap {
		topoAddrs = append(topoAddrs, topoAddr)
	}
	return topoAddrs
}

// Convert map of Name->RawSrvInfo into map of Name->TopoAddr and sorted slice of Names
// stype is only used for error reporting
func svcMapFromRaw(ras map[string]*RawSrvInfo, stype string, smap IDAddrMap,
	ot overlay.Type) ([]string, error) {

	var snames []string
	for name, svc := range ras {
		svcTopoAddr, err := svc.Addrs.ToTopoAddr(ot)
		if err != nil {
			return nil, common.NewBasicError(
				"Could not convert RawAddrMap to TopoAddr", err,
				"servicetype", stype, "RawAddrMap", svc.Addrs, "name", name)
		}
		smap[name] = *svcTopoAddr
		snames = append(snames, name)
	}
	sort.Strings(snames)
	return snames, nil
}

func (t *Topo) zkSvcFromRaw(zksvc map[int]*RawAddrPort) error {
	for id, ap := range zksvc {
		l3 := addr.HostFromIPStr(ap.Addr)
		if l3 == nil {
			return common.NewBasicError("Parsing ZooKeeper address", nil, "addr", ap.Addr)
		}
		t.ZK[id] = &addr.AppAddr{
			L3: l3,
			L4: addr.NewL4TCPInfo(uint16(ap.L4Port)),
		}
	}
	return nil
}

// A list of AS-wide unique interface IDs for a router. These IDs are also used
// to point to the specific internal address clients should send their traffic
// to in order to use that interface, via the IFInfoMap member of the Topo
// struct.
type BRInfo struct {
	IFIDs []common.IFIDType
}

// IFInfo describes a border router link to another AS, including the internal address
// applications should send traffic for the link to (InternalAddrs) and information about
// the link itself and the remote side of it.
type IFInfo struct {
	BRName        string
	CtrlAddrs     *TopoAddr
	Overlay       overlay.Type
	InternalAddrs *TopoBRAddr
	Local         *TopoBRAddr
	Remote        *overlay.OverlayAddr
	RemoteIFID    common.IFIDType
	Bandwidth     int
	ISD_AS        addr.IA
	LinkType      proto.LinkType
	MTU           int
}

func (i IFInfo) Verify(isCore bool, brName string) error {
	if isCore {
		switch i.LinkType {
		case proto.LinkType_core, proto.LinkType_child:
		default:
			return common.NewBasicError("Illegal link type for core AS", nil,
				"type", i.LinkType, "br", brName)
		}
	} else {
		switch i.LinkType {
		case proto.LinkType_parent, proto.LinkType_child, proto.LinkType_peer:
		default:
			return common.NewBasicError("Illegal link type for non-core AS", nil,
				"type", i.LinkType, "br", brName)
		}
	}
	return nil
}

func (i IFInfo) String() string {
	return fmt.Sprintf("IFinfo: Name[%s] IntAddr[%+v] CtrlAddr[%+v] Overlay:%s Local:%+v "+
		"Remote:+%v Bw:%d IA:%s Type:%s MTU:%d", i.BRName, i.InternalAddrs, i.CtrlAddrs, i.Overlay,
		i.Local, i.Remote, i.Bandwidth, i.ISD_AS, i.LinkType, i.MTU)
}
