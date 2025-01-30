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
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/iface"
	jsontopo "github.com/scionproto/scion/private/topology/json"
	"github.com/scionproto/scion/private/topology/underlay"
)

const (
	// EndhostPort is the underlay port that SCION binds to on non-routers.
	EndhostPort = underlay.EndhostPort
)

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
	// The second section concerns the Border routers.
	// The BR map points from border router names to BRInfo structs, which in turn
	// are lists of IfID type slices, thus defines the IfIDs that belong to a
	// particular border router. The IFInfoMap points from interface IDs to IFInfo structs.
	//
	// The third section in RWTopology concerns the SCION-specific services in the topology.
	// The structure is identical between the various elements. For each service,
	// there is again a sorted slice of names of the servers that provide the service.
	// Additionally, there is a map from those names to TopoAddr structs.
	RWTopology struct {
		Timestamp           time.Time
		IA                  addr.IA
		IsCore              bool
		MTU                 int
		DispatchedPortStart uint16
		DispatchedPortEnd   uint16

		BR        map[string]BRInfo
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
		ProbeAddr       *net.UDPAddr
		AllowInterfaces []uint64
	}

	// BRInfo is a list of AS-wide unique interface IDs for a router. These IDs are also used
	// to point to the specific internal address clients should send their traffic
	// to in order to use that interface, via the IFInfoMap member of the Topo
	// struct.
	BRInfo struct {
		Name string
		// InternalAddr is the local data-plane address.
		InternalAddr netip.AddrPort
		// IfIDs is a sorted list of the interface IDs.
		IfIDs []iface.ID
		// IFs is a map of interface IDs.
		IFs map[iface.ID]*IFInfo
	}

	// IfInfoMap maps interface ids to the interface information.
	IfInfoMap map[iface.ID]IFInfo

	// IFInfo describes a border router link to another AS, including the internal data-plane
	// address applications should send traffic to and information about the link itself and the
	// remote side of it.
	IFInfo struct {
		// ID is the interface ID. It is unique per AS.
		ID           iface.ID
		BRName       string
		InternalAddr netip.AddrPort
		Local        netip.AddrPort
		Remote       netip.AddrPort
		RemoteIfID   iface.ID
		IA           addr.IA
		LinkType     LinkType
		MTU          int
		BFD          BFD
	}

	// IDAddrMap maps process IDs to their topology addresses.
	IDAddrMap map[string]TopoAddr

	// TopoAddr wraps the possible addresses of a SCION service and describes
	// the underlay to be used for contacting said service.
	// XXX: this has become redundant. Replace with single address (and netip.AddrPort)
	TopoAddr struct {
		SCIONAddress    *net.UDPAddr
		UnderlayAddress *net.UDPAddr
	}

	// BFD is the configuration for a BFD session
	// Disable can be set from two sources: the topology configuration for the link (here), and
	// the dataplane's bfd global configuration. This is actually a pointer to boolean. nil
	// means unspecified.
	BFD struct {
		Disable               *bool
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
		return nil, serrors.Wrap("unable to convert raw topology to topology", err)
	}
	return ct, nil
}

// RWTopologyFromJSONFile extracts the topology from a file containing the JSON representation
// of the topology.
func RWTopologyFromJSONFile(path string) (*RWTopology, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return RWTopologyFromJSONBytes(b)
}

func (t *RWTopology) populateMeta(raw *jsontopo.Topology) error {
	// These fields can be simply copied
	var err error
	t.Timestamp = time.Unix(raw.Timestamp, 0)

	if t.IA, err = addr.ParseIA(raw.IA); err != nil {
		return err
	}
	if t.IA.IsWildcard() {
		return serrors.New("ISD-AS contains wildcard", "isd_as", t.IA)
	}
	t.MTU = raw.MTU

	t.DispatchedPortStart, t.DispatchedPortEnd, err = validatePortRange(raw.EndhostPortRange)
	if err != nil {
		return err
	}

	isCore := false
	for _, attr := range raw.Attributes {
		if attr == jsontopo.AttrCore {
			isCore = true
			break
		}
	}
	t.IsCore = isCore
	return nil
}

func validatePortRange(portRange string) (uint16, uint16, error) {
	if portRange == "" || portRange == "-" {
		log.Debug("Empty port range defined")
		return 0, 0, nil
	}
	if portRange == "all" || portRange == "ALL" {
		log.Debug("\"all\" port range defined")
		return uint16(1), uint16(65535), nil
	}
	ports := strings.Split(portRange, "-")
	if len(ports) != 2 {
		return 0, 0, serrors.New("invalid format: expected startPort-endPort", "got", portRange)
	}
	startPort, errStart := strconv.ParseUint(ports[0], 10, 16)
	endPort, errEnd := strconv.ParseUint(ports[1], 10, 16)
	if errStart != nil || errEnd != nil {
		return 0, 0, serrors.New("invalid port numbers", "got", portRange)
	}
	if startPort < 1 {
		return 0, 0, serrors.New("invalid value for start port", "start port", startPort)
	}
	if endPort < 1 {
		return 0, 0, serrors.New("invalid value for end port", "end port", endPort)
	}
	if startPort > endPort {
		return 0, 0, serrors.New("start port is bigger than end port for the SCION port range",
			"start port", startPort, "end port", endPort)
	}
	return uint16(startPort), uint16(endPort), nil
}

func (t *RWTopology) populateBR(raw *jsontopo.Topology) error {
	for name, rawBr := range raw.BorderRouters {
		if rawBr.InternalAddr == "" {
			return serrors.New("Missing Internal Address", "br", name)
		}
		intAddr, err := resolveAddrPort(rawBr.InternalAddr)
		if err != nil {
			return serrors.Wrap("unable to extract underlay internal data-plane address", err)
		}
		brInfo := BRInfo{
			Name:         name,
			InternalAddr: intAddr,
			IFs:          make(map[iface.ID]*IFInfo),
		}
		for ifID, rawIntf := range rawBr.Interfaces {
			var err error
			// Check that ifID is unique
			if _, ok := t.IFInfoMap[ifID]; ok {
				return serrors.New("IfID already exists", "ID", ifID)
			}
			brInfo.IfIDs = append(brInfo.IfIDs, ifID)
			ifinfo := IFInfo{
				ID:           ifID,
				BRName:       name,
				InternalAddr: intAddr,
				MTU:          rawIntf.MTU,
			}
			if ifinfo.IA, err = addr.ParseIA(rawIntf.IA); err != nil {
				return err
			}
			ifinfo.LinkType = LinkTypeFromString(rawIntf.LinkTo)
			if ifinfo.LinkType == Peer {
				ifinfo.RemoteIfID = rawIntf.RemoteIfID
			}

			if err = ifinfo.CheckLinks(t.IsCore, name); err != nil {
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
			// Parsing should not fail if all fields are empty.
			if rawIntf.Underlay == (jsontopo.Underlay{}) {
				brInfo.IFs[ifID] = &ifinfo
				t.IFInfoMap[ifID] = ifinfo
				continue
			}
			if ifinfo.Local, err = rawBRIntfLocalAddr(&rawIntf.Underlay); err != nil {
				return serrors.Wrap("unable to extract "+
					"underlay external data-plane local address", err)

			}
			if ifinfo.Remote, err = resolveAddrPort(rawIntf.Underlay.Remote); err != nil {
				return serrors.Wrap("unable to extract "+
					"underlay external data-plane remote address", err)

			}
			brInfo.IFs[ifID] = &ifinfo
			t.IFInfoMap[ifID] = ifinfo
		}
		sort.Slice(brInfo.IfIDs, func(i, j int) bool {
			return brInfo.IfIDs[i] < brInfo.IfIDs[j]
		})
		t.BR[name] = brInfo
	}
	return nil
}

func (t *RWTopology) populateServices(raw *jsontopo.Topology) error {
	var err error
	t.CS, err = svcMapFromRaw(raw.ControlService)
	if err != nil {
		return serrors.Wrap("unable to extract CS address", err)
	}
	t.SIG, err = gatewayMapFromRaw(raw.SIG)
	if err != nil {
		return serrors.Wrap("unable to extract SIG address", err)
	}
	t.DS, err = svcMapFromRaw(raw.DiscoveryService)
	if err != nil {
		return serrors.Wrap("unable to extract DS address", err)
	}
	t.HiddenSegmentLookup, err = svcMapFromRaw(raw.HiddenSegmentLookup)
	if err != nil {
		return serrors.Wrap("unable to extract hidden segment lookup address", err)
	}
	t.HiddenSegmentRegistration, err = svcMapFromRaw(raw.HiddenSegmentReg)
	if err != nil {
		return serrors.Wrap("unable to extract hidden segment registration address", err)
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
		Timestamp:           t.Timestamp,
		IA:                  t.IA,
		MTU:                 t.MTU,
		IsCore:              t.IsCore,
		DispatchedPortStart: t.DispatchedPortStart,
		DispatchedPortEnd:   t.DispatchedPortEnd,

		BR:        copyBRMap(t.BR),
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
			CtrlAddr:  v.CtrlAddr.copy(),
			DataAddr:  copyUDPAddr(v.DataAddr),
			ProbeAddr: copyUDPAddr(v.ProbeAddr),
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
		InternalAddr: i.InternalAddr,
		IfIDs:        append(i.IfIDs[:0:0], i.IfIDs...),
		IFs:          copyIFsMap(i.IFs),
	}
}

func copyIFsMap(m map[iface.ID]*IFInfo) map[iface.ID]*IFInfo {
	if m == nil {
		return nil
	}
	newM := make(map[iface.ID]*IFInfo)
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
		a, err := resolveAddrPort(svc.Addr)
		if err != nil {
			return nil, serrors.Wrap("could not parse address", err,
				"address", svc.Addr, "process_name", name)

		}
		svcTopoAddr := &TopoAddr{
			SCIONAddress:    net.UDPAddrFromAddrPort(a),
			UnderlayAddress: net.UDPAddrFromAddrPort(netip.AddrPortFrom(a.Addr(), EndhostPort)),
		}
		svcMap[name] = *svcTopoAddr
	}
	return svcMap, nil
}

func gatewayMapFromRaw(ras map[string]*jsontopo.GatewayInfo) (map[string]GatewayInfo, error) {
	ret := make(map[string]GatewayInfo)
	for name, svc := range ras {
		c, err := resolveAddrPort(svc.CtrlAddr)
		if err != nil {
			return nil, serrors.Wrap("could not parse control address", err,
				"address", svc.CtrlAddr, "process_name", name)

		}
		d, err := resolveAddrPort(svc.DataAddr)
		if err != nil {
			return nil, serrors.Wrap("could not parse data address", err,
				"address", svc.DataAddr, "process_name", name)

		}
		// backward compatibility: if no probe address is specified just use the
		// default (ctrl address & port 30856):
		probeAddr := netip.AddrPortFrom(c.Addr(), 30856)
		if svc.ProbeAddr != "" {
			probeAddr, err = resolveAddrPort(svc.ProbeAddr)
			if err != nil {
				return nil, serrors.Wrap("could not parse probe address", err,
					"address", svc.ProbeAddr, "process_name", name)

			}
		}

		ret[name] = GatewayInfo{
			CtrlAddr: &TopoAddr{
				SCIONAddress:    net.UDPAddrFromAddrPort(c),
				UnderlayAddress: net.UDPAddrFromAddrPort(netip.AddrPortFrom(c.Addr(), EndhostPort)),
			},
			DataAddr:        net.UDPAddrFromAddrPort(d),
			ProbeAddr:       net.UDPAddrFromAddrPort(probeAddr),
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
		case Core, Child, Peer:
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
	return fmt.Sprintf("IFinfo: Name[%s] IntAddr[%+v] Local:%+v "+
		"Remote:%+v IA:%s Type:%v MTU:%d", i.BRName, i.InternalAddr,
		i.Local, i.Remote, i.IA, i.LinkType, i.MTU)
}

func (i *IFInfo) copy() *IFInfo {
	if i == nil {
		return nil
	}
	cpy := *i
	return &cpy
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
	return s[rand.IntN(numServers)], nil
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
