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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"sort"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	jsontopo "github.com/scionproto/scion/go/lib/topology/json"
	"github.com/scionproto/scion/go/lib/topology/underlay"
)

// EndhostPort is the underlay port that the dispatcher binds to on non-routers.
const EndhostPort = underlay.EndhostPort

// ErrAddressNotFound indicates the address was not found.
var ErrAddressNotFound = serrors.New("address not found")

type (
	// RWTopology is the topology type for applications and libraries that need write
	// access to AS topology information (e.g., discovery, topology reloaders).
	//
	// The first section contains metadata about the topology. All of these fields
	// should be self-explanatory. The unit of TTL is seconds, with the zero value
	// indicating an infinite TTL.
	//
	// The second section concerns the Border routers. BRNames is just a sorted slice
	// of the names of the BRs in this topology. Its contents is exactly the same as
	// the keys in the BR map.
	//
	// The BR map points from border router names to BRInfo structs, which in turn
	// are lists of IFID type slices, thus defines the IFIDs that belong to a
	// particular border router. The IFInfoMap points from interface IDs to IFInfo structs.
	//
	// The third section in RWTopology concerns the SCION-specific services in the topology.
	// The structure is identical between the various elements. For each service,
	// there is again a sorted slice of names of the servers that provide the service.
	// Additionally, there is a map from those names to TopoAddr structs.
	RWTopology struct {
		Timestamp  time.Time
		IA         addr.IA
		Attributes []jsontopo.Attribute
		MTU        int

		BR        map[string]BRInfo
		BRNames   []string
		IFInfoMap IfInfoMap

		CS                        IDAddrMap
		DS                        IDAddrMap
		HiddenSegmentLookup       IDAddrMap
		HiddenSegmentRegistration IDAddrMap
		SIG                       map[string]GatewayInfo
	}

	// GatewayInfo describes a scion gateway.
	GatewayInfo struct {
		CtrlAddr        *TopoAddr
		DataAddr        *net.UDPAddr
		AllowInterfaces []uint64
	}

	// BRInfo is a list of AS-wide unique interface IDs for a router. These IDs are also used
	// to point to the specific internal address clients should send their traffic
	// to in order to use that interface, via the IFInfoMap member of the Topo
	// struct.
	BRInfo struct {
		Name string
		// CtrlAddrs are the local control-plane addresses.
		CtrlAddrs *TopoAddr
		// InternalAddr is the local data-plane address.
		InternalAddr *net.UDPAddr
		// IFIDs is a sorted list of the interface IDs.
		IFIDs []common.IFIDType
		// IFs is a map of interface IDs.
		IFs map[common.IFIDType]*IFInfo
	}

	// IfInfoMap maps interface ids to the interface information.
	IfInfoMap map[common.IFIDType]IFInfo

	// IFInfo describes a border router link to another AS, including the internal data-plane
	// address applications should send traffic to and information about the link itself and the
	// remote side of it.
	IFInfo struct {
		// ID is the interface ID. It is unique per AS.
		ID           common.IFIDType
		BRName       string
		CtrlAddrs    *TopoAddr
		Underlay     underlay.Type
		InternalAddr *net.UDPAddr
		Local        *net.UDPAddr
		Remote       *net.UDPAddr
		RemoteIFID   common.IFIDType
		Bandwidth    int
		IA           addr.IA
		LinkType     LinkType
		MTU          int
		BFD          BFD
	}

	// IDAddrMap maps process IDs to their topology addresses.
	IDAddrMap map[string]TopoAddr

	// TopoAddr wraps the possible addresses of a SCION service and describes
	// the underlay to be used for contacting said service.
	TopoAddr struct {
		SCIONAddress    *net.UDPAddr
		UnderlayAddress *net.UDPAddr
	}

	// BFD is the configuration for a BFD session
	BFD struct {
		Disable               bool
		DetectMult            uint8
		DesiredMinTxInterval  time.Duration
		RequiredMinRxInterval time.Duration
	}
)

// NewRWTopology creates new empty Topo object, including all possible service maps etc.
func NewRWTopology() *RWTopology {
	return &RWTopology{
		BR:                        make(map[string]BRInfo),
		CS:                        make(IDAddrMap),
		DS:                        make(IDAddrMap),
		HiddenSegmentLookup:       make(IDAddrMap),
		HiddenSegmentRegistration: make(IDAddrMap),
		SIG:                       make(map[string]GatewayInfo),
		IFInfoMap:                 make(IfInfoMap),
	}
}

// RWTopologyFromJSONTopology converts a parsed JSON struct topology to a topology usable by Go
// code.
func RWTopologyFromJSONTopology(raw *jsontopo.Topology) (*RWTopology, error) {
	t := NewRWTopology()
	if err := t.populateMeta(raw); err != nil {
		return nil, err
	}
	if err := t.populateBR(raw); err != nil {
		return nil, err
	}
	if err := t.populateServices(raw); err != nil {
		return nil, err
	}
	return t, nil
}

// RWTopologyFromJSONBytes extracts the topology from a JSON representation in raw byte format.
func RWTopologyFromJSONBytes(b []byte) (*RWTopology, error) {
	rt := &jsontopo.Topology{}
	if err := json.Unmarshal(b, rt); err != nil {
		return nil, err
	}
	ct, err := RWTopologyFromJSONTopology(rt)
	if err != nil {
		return nil, serrors.WrapStr("unable to convert raw topology to topology", err)
	}
	return ct, nil
}

// RWTopologyFromJSONFile extracts the topology from a file containing the JSON representation
// of the topology.
func RWTopologyFromJSONFile(path string) (*RWTopology, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return RWTopologyFromJSONBytes(b)
}

func (t *RWTopology) populateMeta(raw *jsontopo.Topology) error {
	// These fields can be simply copied
	var err error
	t.Timestamp = time.Unix(raw.Timestamp, 0)

	if t.IA, err = addr.IAFromString(raw.IA); err != nil {
		return err
	}
	if t.IA.IsWildcard() {
		return serrors.New("ISD-AS contains wildcard", "isd_as", t.IA)
	}
	t.MTU = raw.MTU
	t.Attributes = raw.Attributes
	return nil
}

func (t *RWTopology) populateBR(raw *jsontopo.Topology) error {
	for name, rawBr := range raw.BorderRouters {
		if rawBr.CtrlAddr == "" {
			return serrors.New("Missing Control Address", "br", name)
		}
		if rawBr.InternalAddr == "" {
			return serrors.New("Missing Internal Address", "br", name)
		}
		ctrlAddr, err := rawAddrToTopoAddr(rawBr.CtrlAddr)
		if err != nil {
			return serrors.WrapStr("unable to extract SCION control-plane address", err)
		}
		intAddr, err := rawAddrToUDPAddr(rawBr.InternalAddr)
		if err != nil {
			return serrors.WrapStr("unable to extract underlay internal data-plane address", err)
		}
		brInfo := BRInfo{
			Name:         name,
			CtrlAddrs:    ctrlAddr,
			InternalAddr: intAddr,
			IFs:          make(map[common.IFIDType]*IFInfo),
		}
		for ifid, rawIntf := range rawBr.Interfaces {
			var err error
			// Check that ifid is unique
			if _, ok := t.IFInfoMap[ifid]; ok {
				return serrors.New("IFID already exists", "ID", ifid)
			}
			brInfo.IFIDs = append(brInfo.IFIDs, ifid)
			ifinfo := IFInfo{
				ID:           ifid,
				BRName:       name,
				InternalAddr: intAddr,
				CtrlAddrs:    ctrlAddr,
				Bandwidth:    rawIntf.Bandwidth,
				MTU:          rawIntf.MTU,
			}
			if ifinfo.IA, err = addr.IAFromString(rawIntf.IA); err != nil {
				return err
			}
			ifinfo.LinkType = LinkTypeFromString(rawIntf.LinkTo)
			isCore := false
			for _, attr := range t.Attributes {
				if attr == jsontopo.AttrCore {
					isCore = true
					break
				}
			}
			if err = ifinfo.CheckLinks(isCore, name); err != nil {
				return err
			}
			if bfd := rawIntf.BFD; bfd != nil {
				ifinfo.BFD = BFD{
					Disable:               bfd.Disable,
					DetectMult:            bfd.DetectMult,
					DesiredMinTxInterval:  bfd.DesiredMinTxInterval.Duration,
					RequiredMinRxInterval: bfd.RequiredMinRxInterval.Duration,
				}
			}

			// These fields are only necessary for the border router.
			// Parsing should not fail if they are missing.
			if rawIntf.Underlay.Bind == "" && rawIntf.Underlay.Remote == "" {
				brInfo.IFs[ifid] = &ifinfo
				t.IFInfoMap[ifid] = ifinfo
				continue
			}
			if ifinfo.Local, err = rawBRIntfTopoBRAddr(rawIntf); err != nil {
				return serrors.WrapStr("unable to extract "+
					"underlay external data-plane local address", err)
			}
			if ifinfo.Remote, err = rawAddrToUDPAddr(rawIntf.Underlay.Remote); err != nil {
				return serrors.WrapStr("unable to extract "+
					"underlay external data-plane remote address", err)
			}
			ifinfo.Underlay = underlay.UDPIPv6
			if ifinfo.Local.IP.To4() != nil && ifinfo.Remote.IP.To4() != nil {
				ifinfo.Underlay = underlay.UDPIPv4
			}
			brInfo.IFs[ifid] = &ifinfo
			t.IFInfoMap[ifid] = ifinfo
		}
		sort.Slice(brInfo.IFIDs, func(i, j int) bool {
			return brInfo.IFIDs[i] < brInfo.IFIDs[j]
		})
		t.BR[name] = brInfo
		t.BRNames = append(t.BRNames, name)
	}
	sort.Strings(t.BRNames)
	return nil
}

func (t *RWTopology) populateServices(raw *jsontopo.Topology) error {
	var err error
	t.CS, err = svcMapFromRaw(raw.ControlService)
	if err != nil {
		return serrors.WrapStr("unable to extract CS address", err)
	}
	t.SIG, err = gatewayMapFromRaw(raw.SIG)
	if err != nil {
		return serrors.WrapStr("unable to extract SIG address", err)
	}
	t.DS, err = svcMapFromRaw(raw.DiscoveryService)
	if err != nil {
		return serrors.WrapStr("unable to extract DS address", err)
	}
	t.HiddenSegmentLookup, err = svcMapFromRaw(raw.HiddenSegmentLookup)
	if err != nil {
		return serrors.WrapStr("unable to extract hidden segment lookup address", err)
	}
	t.HiddenSegmentRegistration, err = svcMapFromRaw(raw.HiddenSegmentReg)
	if err != nil {
		return serrors.WrapStr("unable to extract hidden segment registration address", err)
	}
	return nil
}

// Active returns whether the topology is active at the point in time specified by the argument.
// A topology is active if now is after the timestamp.
func (t *RWTopology) Active(now time.Time) bool {
	return !now.Before(t.Timestamp)
}

// GetTopoAddr returns the address information for the process of the requested type with the
// requested ID.
func (t *RWTopology) GetTopoAddr(id string, svc ServiceType) (*TopoAddr, error) {
	svcInfo, err := t.getSvcInfo(svc)
	if err != nil {
		return nil, err
	}
	topoAddr := svcInfo.idTopoAddrMap.GetByID(id)
	if topoAddr == nil {
		return nil, serrors.New("Element not found", "id", id)
	}
	return topoAddr, nil
}

// getAllTopoAddrs returns the address information of all processes of the requested type.
func (t *RWTopology) getAllTopoAddrs(svc ServiceType) ([]TopoAddr, error) {
	svcInfo, err := t.getSvcInfo(svc)
	if err != nil {
		return nil, err
	}
	topoAddrs := svcInfo.getAllTopoAddrs()
	if topoAddrs == nil {
		return nil, ErrAddressNotFound
	}
	return topoAddrs, nil
}

func (t *RWTopology) getSvcInfo(svc ServiceType) (*svcInfo, error) {
	switch svc {
	case Unknown:
		return nil, serrors.New("service type unknown")
	case Discovery:
		return &svcInfo{idTopoAddrMap: t.DS}, nil
	case Control:
		return &svcInfo{idTopoAddrMap: t.CS}, nil
	case HiddenSegmentLookup:
		return &svcInfo{idTopoAddrMap: t.HiddenSegmentLookup}, nil
	case HiddenSegmentRegistration:
		return &svcInfo{idTopoAddrMap: t.HiddenSegmentRegistration}, nil
	case Gateway:
		m := make(IDAddrMap)
		for k, v := range t.SIG {
			m[k] = *v.CtrlAddr
		}
		return &svcInfo{idTopoAddrMap: m}, nil
	default:
		return nil, serrors.New("unsupported service type", "type", svc)
	}
}

// Copy creates a deep copy of the object.
func (t *RWTopology) Copy() *RWTopology {
	if t == nil {
		return nil
	}
	return &RWTopology{
		Timestamp:  t.Timestamp,
		IA:         t.IA,
		MTU:        t.MTU,
		Attributes: append(t.Attributes[:0:0], t.Attributes...),

		BR:        copyBRMap(t.BR),
		BRNames:   append(t.BRNames[:0:0], t.BRNames...),
		IFInfoMap: t.IFInfoMap.copy(),

		CS:                        t.CS.copy(),
		DS:                        t.DS.copy(),
		SIG:                       copySIGMap(t.SIG),
		HiddenSegmentLookup:       t.HiddenSegmentLookup.copy(),
		HiddenSegmentRegistration: t.HiddenSegmentRegistration.copy(),
	}
}

func copySIGMap(m map[string]GatewayInfo) map[string]GatewayInfo {
	if m == nil {
		return nil
	}
	ret := make(map[string]GatewayInfo)
	for k, v := range m {
		e := GatewayInfo{
			CtrlAddr: v.CtrlAddr.copy(),
			DataAddr: copyUDPAddr(v.DataAddr),
		}
		ret[k] = e
	}
	return ret
}

func copyBRMap(m map[string]BRInfo) map[string]BRInfo {
	if m == nil {
		return nil
	}
	newM := make(map[string]BRInfo)
	for k, v := range m {
		newM[k] = *v.copy()
	}
	return newM
}

func (i *BRInfo) copy() *BRInfo {
	if i == nil {
		return nil
	}
	return &BRInfo{
		Name:         i.Name,
		CtrlAddrs:    i.CtrlAddrs.copy(),
		InternalAddr: copyUDPAddr(i.InternalAddr),
		IFIDs:        append(i.IFIDs[:0:0], i.IFIDs...),
		IFs:          copyIFsMap(i.IFs),
	}
}

func copyIFsMap(m map[common.IFIDType]*IFInfo) map[common.IFIDType]*IFInfo {
	if m == nil {
		return nil
	}
	newM := make(map[common.IFIDType]*IFInfo)
	for k, v := range m {
		newM[k] = v.copy()
	}
	return newM
}

func (m IfInfoMap) copy() IfInfoMap {
	if m == nil {
		return nil
	}
	newM := make(IfInfoMap)
	for k, v := range m {
		newM[k] = *v.copy()
	}
	return newM
}

// svcInfo contains topology information for a single SCION service
type svcInfo struct {
	idTopoAddrMap IDAddrMap
}

func (svc *svcInfo) getAllTopoAddrs() []TopoAddr {
	var topoAddrs []TopoAddr
	for _, topoAddr := range svc.idTopoAddrMap {
		topoAddrs = append(topoAddrs, topoAddr)
	}
	return topoAddrs
}

func svcMapFromRaw(ras map[string]*jsontopo.ServerInfo) (IDAddrMap, error) {
	svcMap := make(IDAddrMap)
	for name, svc := range ras {
		svcTopoAddr, err := rawAddrToTopoAddr(svc.Addr)
		if err != nil {
			return nil, serrors.WrapStr("could not parse address", err,
				"address", svc.Addr, "process_name", name)
		}
		svcMap[name] = *svcTopoAddr
	}
	return svcMap, nil
}

func gatewayMapFromRaw(ras map[string]*jsontopo.GatewayInfo) (map[string]GatewayInfo, error) {
	ret := make(map[string]GatewayInfo)
	for name, svc := range ras {
		c, err := rawAddrToTopoAddr(svc.CtrlAddr)
		if err != nil {
			return nil, serrors.WrapStr("could not parse control address", err,
				"address", svc.CtrlAddr, "process_name", name)
		}
		d, err := rawAddrToUDPAddr(svc.DataAddr)
		if err != nil {
			return nil, serrors.WrapStr("could not parse data address", err,
				"address", svc.DataAddr, "process_name", name)
		}

		ret[name] = GatewayInfo{
			CtrlAddr:        c,
			DataAddr:        d,
			AllowInterfaces: svc.Interfaces,
		}
	}
	return ret, nil
}

// GetByID returns the TopoAddr for the given ID, or nil if there is none.
func (m IDAddrMap) GetByID(id string) *TopoAddr {
	if _, ok := m[id]; ok {
		cp := m[id]
		return &cp
	}
	return nil
}

func (m IDAddrMap) copy() IDAddrMap {
	if m == nil {
		return nil
	}
	newM := make(IDAddrMap)
	for k, v := range m {
		// This has the potential of making a _lot_ of shallow copies, but we can't really avoid it
		// due to the value type in the map.
		newM[k] = *v.copy()
	}
	return newM
}

// CheckLinks checks whether the link types are compatible with whether the AS is core or not.
func (i IFInfo) CheckLinks(isCore bool, brName string) error {
	if isCore {
		switch i.LinkType {
		case Core, Child:
		default:
			return serrors.New("Illegal link type for core AS",
				"type", i.LinkType, "br", brName)
		}
	} else {
		switch i.LinkType {
		case Parent, Child, Peer:
		default:
			return serrors.New("Illegal link type for non-core AS",
				"type", i.LinkType, "br", brName)
		}
	}
	return nil
}

func (i IFInfo) String() string {
	return fmt.Sprintf("IFinfo: Name[%s] IntAddr[%+v] CtrlAddr[%+v] Underlay:%s Local:%+v "+
		"Remote:%+v Bw:%d IA:%s Type:%v MTU:%d", i.BRName, i.InternalAddr, i.CtrlAddrs, i.Underlay,
		i.Local, i.Remote, i.Bandwidth, i.IA, i.LinkType, i.MTU)
}

func (i *IFInfo) copy() *IFInfo {
	if i == nil {
		return nil
	}
	return &IFInfo{
		ID:           i.ID,
		BRName:       i.BRName,
		CtrlAddrs:    i.CtrlAddrs.copy(),
		Underlay:     i.Underlay,
		InternalAddr: copyUDPAddr(i.InternalAddr),
		Local:        copyUDPAddr(i.Local),
		Remote:       copyUDPAddr(i.Remote),
		RemoteIFID:   i.RemoteIFID,
		Bandwidth:    i.Bandwidth,
		IA:           i.IA,
		LinkType:     i.LinkType,
		MTU:          i.MTU,
	}
}

// UnderlayAddr returns the underlay address interpreted as a net.UDPAddr.
//
// FIXME(scrye): This should be removed; applications should not need to look into the underlay
// concrete type.
func (a *TopoAddr) UnderlayAddr() *net.UDPAddr {
	return a.UnderlayAddress
}

func (a *TopoAddr) String() string {
	return fmt.Sprintf("TopoAddr{SCION: %v, Underlay: %v}", a.SCIONAddress, a.UnderlayAddress)
}

func (a *TopoAddr) copy() *TopoAddr {
	// TODO(scrye): Investigate how this can be removed.
	if a == nil {
		return nil
	}
	return &TopoAddr{
		SCIONAddress:    copyUDPAddr(a.SCIONAddress),
		UnderlayAddress: toUDPAddr(a.UnderlayAddress),
	}
}

func toUDPAddr(a net.Addr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	udpAddr, ok := a.(*net.UDPAddr)
	if !ok {
		return nil
	}
	return copyUDPAddr(udpAddr)
}

// ServiceNames is a slice of process names (e.g., "bs-1", "bs-2").
type ServiceNames []string

// GetRandom returns a random entry, or an error if the slice is empty.
func (s ServiceNames) GetRandom() (string, error) {
	numServers := len(s)
	if numServers == 0 {
		return "", serrors.New("No names present")
	}
	return s[rand.Intn(numServers)], nil
}

func copyUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(a.IP[:0:0], a.IP...),
		Port: a.Port,
		Zone: a.Zone,
	}
}
