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

// TODO(klausman): there is a lot of stuff in here now, some parts should be
// split out to separate files

import (
	"fmt"
	"sort"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/overlay"
)

/*   Structures used by Go code, filled in by populate()   */
type Topo struct {
	Timestamp      int64
	TimestampHuman string
	ISD_AS         *addr.ISD_AS
	Overlay        overlay.Type
	MTU            int
	BR             map[string]BRInfo
	BRNames        []string

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
	// This maps Interface IDs to internal addresses. Clients use this to
	// figure out which internal BR address they have to send their traffic to
	// if they want to use a given (external) interface.
	IFInfoMap map[common.IFIDType]IFInfo
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
func TopoFromRaw(i *RawTopo) (*Topo, *common.Error) {
	n := NewTopo()
	var err *common.Error

	if err = populateMeta(i, n); err != nil {
		return nil, err
	}
	if err = populateBR(i, n); err != nil {
		return nil, err
	}
	if err = populateServices(i, n); err != nil {
		return nil, err
	}
	if err = zkSvcFromRaw(i.ZookeeperService, n); err != nil {
		return nil, err
	}

	return n, nil
}

func populateMeta(i *RawTopo, n *Topo) *common.Error {
	// These fields can be simply copied
	var err *common.Error
	n.Timestamp = i.Timestamp
	n.TimestampHuman = i.TimestampHuman

	if n.ISD_AS, err = addr.IAFromString(i.ISD_AS); err != nil {
		return err
	}
	if n.Overlay, err = overlay.TypeFromString(i.Overlay); err != nil {
		return err
	}
	n.MTU = i.MTU
	return nil
}

func populateBR(i *RawTopo, n *Topo) *common.Error {
	var err *common.Error
	for name, br := range i.BorderRouters {
		info := BRInfo{}
		for ifid, brInt := range br.Interfaces {
			info.IFIDs = append(info.IFIDs, ifid)
			ifinfo := IFInfo{
				BRName: name,
			}
			intAddr := br.InternalAddrs[brInt.InternalAddrIdx]
			if ifinfo.InternalAddr, err = TopoAddrFromRawAddrInfo(intAddr, n.Overlay); err != nil {
				return err
			}
			if ifinfo.Overlay, err = overlay.TypeFromString(brInt.Overlay); err != nil {
				return err
			}
			if ifinfo.Local, err = localTopoAddrFromBrInt(brInt, ifinfo.Overlay); err != nil {
				return err
			}
			if ifinfo.Remote, err = remoteAddrInfoFromBrInt(brInt, ifinfo.Overlay); err != nil {
				return err
			}
			fmt.Printf("Set Remote to %+v\n", ifinfo.Remote)
			ifinfo.Bandwidth = brInt.Bandwidth
			if ifinfo.ISD_AS, err = addr.IAFromString(brInt.ISD_AS); err != nil {
				return err
			}
			if ifinfo.LinkType, err = LinkTypeFromString(brInt.LinkType); err != nil {
				return err
			}
			ifinfo.MTU = brInt.MTU
			n.IFInfoMap[ifid] = ifinfo

		}
		n.BR[name] = info
		n.BRNames = append(n.BRNames, name)
	}
	sort.Strings(n.BRNames)
	return nil
}

func populateServices(i *RawTopo, n *Topo) *common.Error {
	// Populate BS, CS, PS, SB, RS and DS maps
	var err *common.Error
	if n.BSNames, err = svcMapFromRaw(i.BeaconService, "BS", n.BS, n.Overlay); err != nil {
		return err
	}
	if n.CSNames, err = svcMapFromRaw(i.CertificateService, "CS", n.CS, n.Overlay); err != nil {
		return err
	}
	if n.PSNames, err = svcMapFromRaw(i.PathService, "PS", n.PS, n.Overlay); err != nil {
		return err
	}
	if n.SBNames, err = svcMapFromRaw(i.SibraService, "SB", n.SB, n.Overlay); err != nil {
		return err
	}
	if n.RSNames, err = svcMapFromRaw(i.RainsService, "RS", n.RS, n.Overlay); err != nil {
		return err
	}
	if n.DSNames, err = svcMapFromRaw(i.DiscoveryService, "DS", n.DS, n.Overlay); err != nil {
		return err
	}
	return nil
}

// Convert map of Name->RawAddrInfo into map of Name->TopoAddr and sorted slice of Names
// stype is only used for logging
func svcMapFromRaw(rais map[string]RawAddrInfo, stype string, smap map[string]TopoAddr,
	ot overlay.Type) ([]string, *common.Error) {
	var snames []string
	for name, svc := range rais {
		svcTopoAddr, err := TopoAddrFromRawAddrInfo(&svc, ot)
		if err != nil {
			return nil, common.NewError("Could not convert RawAddrInfo to TopoAddr", "servicetype", stype, "RawAddrInfo", svc, "err", err)
		}
		smap[name] = *svcTopoAddr
		snames = append(snames, name)
	}
	sort.Strings(snames)
	return snames, nil
}

func zkSvcFromRaw(zksvc map[int]RawAddrPort, n *Topo) *common.Error {
	for id, ap := range zksvc {
		rai := RawAddrInfo{Public: []RawAddrPortOverlay{RawAddrPortOverlay{ap, 0}}}
		tai, err := TopoAddrFromRawAddrInfo(&rai, n.Overlay)
		if err != nil {
			return err
		}
		n.ZK[id] = *tai
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
	BRName          string
	InternalAddr    *TopoAddr
	InternalAddrIdx int
	Overlay         overlay.Type
	Local           *TopoAddr
	Remote          *AddrInfo
	RemoteIFID      common.IFIDType
	Bandwidth       int
	ISD_AS          *addr.ISD_AS
	LinkType        LinkType
	MTU             int
}
