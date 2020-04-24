// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"math/rand"
	"net"
	"sort"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

// Provider provides a topology snapshot. The snapshot is guaranteed to not change.
type Provider interface {
	// Get returns a topology. The returned topology is guaranteed to not be
	// nil.
	Get() Topology
}

// Topology is the topology type for applications and libraries that only need read access to AS
// topology information. This is the case of most applications and libraries that use the topology
// file to discover information about the local AS. Libraries that need to edit the topology (e.g.,
// a topology reloading library that computes a new topology file based on information found on
// disk) should instead use the writable topology type present in this package.
type Topology interface {
	// IA returns the local ISD-AS number.
	IA() addr.IA
	// MTU returns the MTU of the local AS.
	MTU() uint16
	// Core returns whether the local AS is core.
	Core() bool
	// InterfaceIDs returns all interface IDS from the local AS.
	InterfaceIDs() []common.IFIDType

	// PublicAddress gets the public address of a server with the requested type and name, and nil
	// if no such server exists.
	PublicAddress(svc addr.HostSVC, name string) *net.UDPAddr

	// Exists returns true if the service and name are present in the topology file.
	Exists(svc addr.HostSVC, name string) bool

	// SBRAddress returns the internal public address of the BR with the specified name.
	SBRAddress(name string) *snet.UDPAddr

	// Anycast returns the address for an arbitrary server of the requested type.
	Anycast(svc addr.HostSVC) (*net.UDPAddr, error)
	// Multicast returns all addresses for the requested type.
	Multicast(svc addr.HostSVC) ([]*net.UDPAddr, error)

	// UnderlayAnycast returns the underlay address for an arbitrary server of the requested type.
	UnderlayAnycast(svc addr.HostSVC) (*net.UDPAddr, error)
	// UnderlayMulticast returns all underlay addresses for the requested type.
	UnderlayMulticast(svc addr.HostSVC) ([]*net.UDPAddr, error)
	// UnderlayByName returns the underlay address of the server name of the requested type.
	//
	// FIXME(scrye): This isn't really needed. We should also get rid of it.
	UnderlayByName(svc addr.HostSVC, name string) (*net.UDPAddr, error)
	// UnderlayNextHop2 returns the internal underlay address of the router containing the ID. The
	// return value is encoded as an underlay address.
	//
	// FIXME(scrye): Remove either this or the other method. A single return type should be
	// supported.
	UnderlayNextHop2(ifID common.IFIDType) (*net.UDPAddr, bool)

	// UnderlayNextHop returns the internal underlay address of the router
	// containing the interface ID.
	//
	// XXX(scrye): Return value is a shallow copy.
	UnderlayNextHop(ifID common.IFIDType) (*net.UDPAddr, bool)

	// MakeHostInfos returns the underlay addresses of all services for the specified service type.
	MakeHostInfos(st proto.ServiceType) []net.UDPAddr

	// BR returns information for a specific border router
	//
	// FIXME(scrye): Simplify return type and make it topology format agnostic.
	//
	// XXX(scrye): Return value is a shallow copy.
	BR(name string) (BRInfo, bool)
	// IFInfoMap returns the mapping between interface IDs an internal addresses.
	//
	// FIXME(scrye): Simplify return type and make it topology format agnostic.
	//
	// XXX(scrye): Return value is a shallow copy.
	IFInfoMap() IfInfoMap

	// BRNames returns the names of all BRs in the topology.
	//
	// FIXME(scrye): Remove this, callers shouldn't care about names.
	//
	// XXX(scrye): Return value is a shallow copy.
	BRNames() []string

	// SVCNames returns the names of all servers in the topology for the specified service.
	//
	// FIXME(scrye): Remove this, callers shouldn't care about names.
	//
	// XXX(scrye): Return value is a shallow copy.
	SVCNames(svc addr.HostSVC) ServiceNames

	// Writable returns a pointer to the underlying topology object. This is included for legacy
	// reasons and should never be used.
	//
	// FIXME(scrye): Remove this.
	//
	// XXX(scrye): Return value is a shallow copy.
	Writable() *RWTopology
}

// NewTopology creates a new empty topology.
func NewTopology() Topology {
	return &topologyS{
		Topology: &RWTopology{},
	}
}

// FromRWTopology wraps the high level topology interface API around a raw topology object.
func FromRWTopology(topo *RWTopology) Topology {
	return &topologyS{
		Topology: topo,
	}
}

// FromJSONFile extracts the topology from a file containing the JSON representation of the
// topology.
func FromJSONFile(path string) (Topology, error) {
	t, err := RWTopologyFromJSONFile(path)
	if err != nil {
		return nil, err
	}
	return &topologyS{
		Topology: t,
	}, nil
}

type topologyS struct {
	Topology *RWTopology
}

func (t *topologyS) IA() addr.IA {
	return t.Topology.IA
}

func (t *topologyS) MTU() uint16 {
	return uint16(t.Topology.MTU)
}

func (t *topologyS) InterfaceIDs() []common.IFIDType {
	intfs := make([]common.IFIDType, 0, len(t.Topology.IFInfoMap))
	for ifid := range t.Topology.IFInfoMap {
		intfs = append(intfs, ifid)
	}
	return intfs
}

func (t *topologyS) UnderlayNextHop(ifid common.IFIDType) (*net.UDPAddr, bool) {
	ifInfo, ok := t.Topology.IFInfoMap[ifid]
	if !ok {
		return nil, false
	}
	return copyUDPAddr(ifInfo.InternalAddr), true
}

func (t *topologyS) UnderlayNextHop2(ifid common.IFIDType) (*net.UDPAddr, bool) {
	ifInfo, ok := t.Topology.IFInfoMap[ifid]
	if !ok {
		return nil, false
	}
	return copyUDPAddr(ifInfo.InternalAddr), true
}

func (t *topologyS) MakeHostInfos(st proto.ServiceType) []net.UDPAddr {
	var hostInfos []net.UDPAddr
	addresses, err := t.Topology.GetAllTopoAddrs(st)
	if err != nil {
		// FIXME(lukedirtwalker): inform client about this:
		// see https://github.com/scionproto/scion/issues/1673
		return hostInfos
	}
	for _, a := range addresses {
		if tmp := a.SCIONAddress; tmp != nil {
			hostInfos = append(hostInfos, *tmp)
		}
	}
	return hostInfos
}

func (t *topologyS) Core() bool {
	return t.Topology.Attributes.Contains(trc.Core)
}

func (t *topologyS) BR(name string) (BRInfo, bool) {
	br, ok := t.Topology.BR[name]
	return br, ok
}

func (t *topologyS) PublicAddress(svc addr.HostSVC, name string) *net.UDPAddr {
	topoAddr := t.topoAddress(svc, name)
	if topoAddr == nil {
		return nil
	}
	return topoAddr.SCIONAddress
}

func (t *topologyS) Exists(svc addr.HostSVC, name string) bool {
	return t.PublicAddress(svc, name) != nil
}

func (t *topologyS) topoAddress(svc addr.HostSVC, name string) *TopoAddr {
	var addresses IDAddrMap
	switch svc.Base() {
	case addr.SvcBS, addr.SvcCS, addr.SvcPS:
		addresses = t.Topology.CS
	case addr.SvcSIG:
		addresses = t.Topology.SIG
	}
	if addresses == nil {
		return nil
	}
	return addresses.GetByID(name)
}

func (t *topologyS) Anycast(svc addr.HostSVC) (*net.UDPAddr, error) {
	addrs, err := t.Multicast(svc)
	if err != nil {
		return nil, err
	}
	return addrs[rand.Intn(len(addrs))], nil
}

func (t *topologyS) Multicast(svc addr.HostSVC) ([]*net.UDPAddr, error) {
	names := t.SVCNames(svc)
	st, err := toProtoServiceType(svc)
	if err != nil {
		return nil, err
	}
	addrs := make([]*net.UDPAddr, 0, len(names))
	for _, name := range names {
		topoAddr, err := t.Topology.GetTopoAddr(name, st)
		if err != nil {
			return nil, serrors.Wrap(addr.ErrUnsupportedSVCAddress, err, "svc", svc)
		}
		addrs = append(addrs, &net.UDPAddr{
			IP:   topoAddr.SCIONAddress.IP,
			Port: topoAddr.SCIONAddress.Port,
			Zone: topoAddr.SCIONAddress.Zone,
		})
	}
	return addrs, nil
}

func (t *topologyS) UnderlayAnycast(svc addr.HostSVC) (*net.UDPAddr, error) {
	names := t.SVCNames(svc)
	name, err := names.GetRandom()
	if err != nil {
		if supportedSVC(svc) {
			// FIXME(scrye): Return this error because some calling code in the BR searches for it.
			// Ideally, the error should be communicated in a more explicit way.
			return nil, serrors.WrapStr("No instances found for SVC address",
				scmp.NewError(scmp.C_Routing, scmp.T_R_UnreachHost, nil, nil), "svc", svc)
		}
		// FIXME(scrye): Return this error because some calling code in the BR searches for it.
		// Ideally, the error should be communicated in a more explicit way.
		return nil, serrors.Wrap(addr.ErrUnsupportedSVCAddress,
			scmp.NewError(scmp.C_Routing, scmp.T_R_BadHost, nil, nil), "svc", svc)
	}
	underlay, err := t.UnderlayByName(svc, name)
	if err != nil {
		return nil, serrors.WrapStr("BUG! Selected random service name, but service info not found",
			err, "service_names", names, "selected_name", name)
	}
	// FIXME(scrye): This should return net.Addr
	return underlay, nil
}

func supportedSVC(svc addr.HostSVC) bool {
	b := svc.Base()
	return b == addr.SvcBS || b == addr.SvcCS || b == addr.SvcPS || b == addr.SvcSIG
}

func (t *topologyS) UnderlayMulticast(svc addr.HostSVC) ([]*net.UDPAddr, error) {
	st, err := toProtoServiceType(svc)
	if err != nil {
		return nil, err
	}
	topoAddrs, err := t.Topology.GetAllTopoAddrs(st)
	if err != nil {
		return nil, serrors.Wrap(addr.ErrUnsupportedSVCAddress, err, "svc", svc)
	}

	if len(topoAddrs) == 0 {
		// FIXME(scrye): Return this error because some calling code in the BR searches for it.
		// Ideally, the error should be communicated in a more explicit way.
		return nil, common.NewBasicError("No instances found for SVC address",
			scmp.NewError(scmp.C_Routing, scmp.T_R_UnreachHost, nil, nil), "svc", svc)
	}

	// Only select each IP:UnderlayPort combination once, s.t. the same message isn't multicasted
	// multiple times by the remote dispatcher.
	uniqueUnderlayAddrs := make(map[string]*net.UDPAddr)
	for _, topoAddr := range topoAddrs {
		underlayAddr := topoAddr.UnderlayAddr()
		if underlayAddr == nil {
			continue
		}
		uniqueUnderlayAddrs[underlayAddr.String()] = underlayAddr
	}

	var underlayAddrs []*net.UDPAddr
	for _, underlayAddr := range uniqueUnderlayAddrs {
		underlayAddrs = append(underlayAddrs, underlayAddr)
	}
	return underlayAddrs, nil
}

func (t *topologyS) UnderlayByName(svc addr.HostSVC, name string) (*net.UDPAddr, error) {
	st, err := toProtoServiceType(svc)
	if err != nil {
		return nil, err
	}
	topoAddr, err := t.Topology.GetTopoAddr(name, st)
	if err != nil {
		return nil, serrors.Wrap(addr.ErrUnsupportedSVCAddress, err, "svc", svc)
	}
	underlayAddr := topoAddr.UnderlayAddr()
	if underlayAddr == nil {
		return nil, serrors.New("underlay address not found", "svc", svc)
	}
	return copyUDPAddr(underlayAddr), nil
}

func toProtoServiceType(svc addr.HostSVC) (proto.ServiceType, error) {
	switch svc.Base() {
	case addr.SvcBS, addr.SvcCS, addr.SvcPS:
		return proto.ServiceType_cs, nil
	case addr.SvcSIG:
		return proto.ServiceType_sig, nil
	default:
		// FIXME(scrye): Return this error because some calling code in the BR searches for it.
		// Ideally, the error should be communicated in a more explicit way.
		return 0, serrors.Wrap(addr.ErrUnsupportedSVCAddress,
			scmp.NewError(scmp.C_Routing, scmp.T_R_BadHost, nil, nil), "svc", svc)
	}
}

func (t *topologyS) IFInfoMap() IfInfoMap {
	return t.Topology.IFInfoMap
}

func (t *topologyS) BRNames() []string {
	return t.Topology.BRNames
}

func (t *topologyS) SBRAddress(name string) *snet.UDPAddr {
	br, ok := t.Topology.BR[name]
	if !ok {
		return nil
	}
	return &snet.UDPAddr{
		IA:      t.IA(),
		NextHop: br.CtrlAddrs.UnderlayAddr(),
		Host:    br.CtrlAddrs.SCIONAddress,
	}
}

func (t *topologyS) SVCNames(svc addr.HostSVC) ServiceNames {
	var m IDAddrMap
	switch svc.Base() {
	case addr.SvcBS, addr.SvcCS, addr.SvcPS:
		m = t.Topology.CS
	case addr.SvcSIG:
		m = t.Topology.SIG
	}

	var names ServiceNames
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func (t *topologyS) Writable() *RWTopology {
	return t.Topology
}
