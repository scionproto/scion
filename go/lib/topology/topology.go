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

// Structures used by Go code, filled in by populate()

// Topo is the main struct encompassing topology information for use in Go code.
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

	BS      map[string]TopoAddr
	BSNames []string
	CS      map[string]TopoAddr
	CSNames []string
	PS      map[string]TopoAddr
	PSNames []string
	SB      map[string]TopoAddr
	SBNames []string
	RS      map[string]TopoAddr
	RSNames []string
	DS      map[string]TopoAddr
	DSNames []string

	ZK map[int]TopoAddr
}

// Create new empty Topo object, including all possible service maps etc.
func NewTopo() *Topo {
	return &Topo{
		BR:        make(map[string]BRInfo),
		BS:        make(map[string]TopoAddr),
		CS:        make(map[string]TopoAddr),
		PS:        make(map[string]TopoAddr),
		SB:        make(map[string]TopoAddr),
		RS:        make(map[string]TopoAddr),
		DS:        make(map[string]TopoAddr),
		ZK:        make(map[int]TopoAddr),
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
	if t.Overlay, err = overlay.TypeFromString(raw.Overlay); err != nil {
		return err
	}
	t.MTU = raw.MTU
	t.Core = raw.Core
	return nil
}

func (t *Topo) populateBR(raw *RawTopo) error {
	for name, rawBr := range raw.BorderRouters {
		if rawBr.InternalAddr == nil {
			return common.NewBasicError("Missing Internal Address", nil, "br", name)
		}
		for i := range rawBr.InternalAddr.Public {
			iAddr := &rawBr.InternalAddr.Public[i]
			if iAddr.OverlayPort != 0 {
				return common.NewBasicError("BR internal address may not have overlay port set",
					nil, "br", name, "intAddr", iAddr)
			}
			if t.Overlay.IsUDP() {
				// Set the overlay port to the L4 port as the BR does not run
				// on top of the dispatcher.
				iAddr.OverlayPort = iAddr.L4Port
			}
		}
		intAddr, err := rawBr.InternalAddr.ToTopoAddr(t.Overlay)
		if err != nil {
			return err
		}
		brInfo := BRInfo{}
		for ifid, rawIntf := range rawBr.Interfaces {
			var err error
			brInfo.IFIDs = append(brInfo.IFIDs, ifid)
			ifinfo := IFInfo{BRName: name, InternalAddr: intAddr}
			if ifinfo.Overlay, err = overlay.TypeFromString(rawIntf.Overlay); err != nil {
				return err
			}
			if ifinfo.Local, err = rawIntf.localTopoAddr(ifinfo.Overlay); err != nil {
				return err
			}
			if ifinfo.Remote, err = rawIntf.remoteAddr(ifinfo.Overlay); err != nil {
				return err
			}
			ifinfo.Bandwidth = rawIntf.Bandwidth
			if ifinfo.ISD_AS, err = addr.IAFromString(rawIntf.ISD_AS); err != nil {
				return err
			}
			if ifinfo.LinkType, err = LinkTypeFromString(rawIntf.LinkTo); err != nil {
				return err
			}
			ifinfo.MTU = rawIntf.MTU
			t.IFInfoMap[ifid] = ifinfo

		}
		t.BR[name] = brInfo
		t.BRNames = append(t.BRNames, name)
	}
	sort.Strings(t.BRNames)
	return nil
}

func (t *Topo) populateServices(raw *RawTopo) error {
	// Populate BS, CS, PS, SB, RS and DS maps
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
	t.DSNames, err = svcMapFromRaw(raw.DiscoveryService, common.DS, t.DS, t.Overlay)
	if err != nil {
		return err
	}
	return nil
}

// GetTopoAddr is a helper method that returns the TopoAddress for a specific
// element ID of type t. nodeType must be one of BS, CS or PS. If the ID is not
// found, nil is returned.
func (t *Topo) GetTopoAddr(serviceType proto.ServiceType, id string) *TopoAddr {
	var addressMap map[string]TopoAddr
	switch serviceType {
	case proto.ServiceType_bs:
		addressMap = t.BS
	case proto.ServiceType_cs:
		addressMap = t.CS
	case proto.ServiceType_ps:
		addressMap = t.PS
	}
	if _, ok := addressMap[id]; ok {
		cp := addressMap[id]
		return &cp
	}
	return nil
}

// GetRandomServer returns the application address for a random service of type
// t; BS, PS, and CS are currently supported. Randomness is taken from the
// default source. If no server is found, an error is returned.
func (t *Topo) GetRandomServer(serviceType proto.ServiceType) (*addr.AppAddr, error) {
	names, err := t.extractServerNames(serviceType)
	if err != nil {
		return nil, err
	}
	numServers := len(names)
	if numServers == 0 {
		return nil, common.NewBasicError("Found no servers of requested type", nil,
			"type", serviceType)
	}
	topoAddr := t.GetTopoAddr(serviceType, names[rand.Intn(numServers)])
	return topoAddr.PublicAddr(t.Overlay), nil

}

func (t *Topo) extractServerNames(serviceType proto.ServiceType) ([]string, error) {
	switch serviceType {
	case proto.ServiceType_bs:
		return t.BSNames, nil
	case proto.ServiceType_cs:
		return t.CSNames, nil
	case proto.ServiceType_ps:
		return t.PSNames, nil
	default:
		return nil, common.NewBasicError("Unknown service type", nil, "type", serviceType)
	}
}

// Convert map of Name->RawAddrInfo into map of Name->TopoAddr and sorted slice of Names
// stype is only used for error reporting
func svcMapFromRaw(rais map[string]RawAddrInfo, stype string, smap map[string]TopoAddr,
	ot overlay.Type) ([]string, error) {
	var snames []string
	for name, svc := range rais {
		svcTopoAddr, err := svc.ToTopoAddr(ot)
		if err != nil {
			return nil, common.NewBasicError(
				"Could not convert RawAddrInfo to TopoAddr", err,
				"servicetype", stype, "RawAddrInfo", svc, "name", name)
		}
		smap[name] = *svcTopoAddr
		snames = append(snames, name)
	}
	sort.Strings(snames)
	return snames, nil
}

func (t *Topo) zkSvcFromRaw(zksvc map[int]RawAddrPort) error {
	for id, ap := range zksvc {
		rai := RawAddrInfo{Public: []RawAddrPortOverlay{{ap, 0}}}
		tai, err := rai.ToTopoAddr(t.Overlay)
		if err != nil {
			return err
		}
		t.ZK[id] = *tai
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

type IFInfo struct {
	BRName       string
	InternalAddr *TopoAddr
	Overlay      overlay.Type
	Local        *TopoAddr
	Remote       *overlay.OverlayAddr
	RemoteIFID   common.IFIDType
	Bandwidth    int
	ISD_AS       addr.IA
	LinkType     proto.LinkType
	MTU          int
}

func (i IFInfo) String() string {
	return fmt.Sprintf(
		"IFinfo: Name[%s] IntAddr[%+v] Overlay:%s Local:%+v Remote:+%v Bw:%d IA:%s Type:%s MTU:%d",
		i.BRName, i.InternalAddr, i.Overlay, i.Local, i.Remote, i.Bandwidth, i.ISD_AS, i.LinkType,
		i.MTU)
}
