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
	"crypto/sha256"
	"encoding/json"
	"math/rand"
	"net"
	"sort"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
)

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

	// Anycast returns the address for an arbitrary server of the requested type.
	Anycast(svc addr.HostSVC) (*net.UDPAddr, error)
	// Multicast returns all addresses for the requested type.
	Multicast(svc addr.HostSVC) ([]*net.UDPAddr, error)

	// UnderlayAnycast returns the underlay address for an arbitrary server of the requested type.
	UnderlayAnycast(svc addr.HostSVC) (*net.UDPAddr, error)
	// UnderlayMulticast returns all underlay addresses for the requested type.
	UnderlayMulticast(svc addr.HostSVC) ([]*net.UDPAddr, error)
	// UnderlayNextHop returns the internal underlay address of the router
	// containing the interface ID.
	UnderlayNextHop(ifID common.IFIDType) (*net.UDPAddr, bool)

	// MakeHostInfos returns the underlay addresses of all services for the specified service type.
	MakeHostInfos(st ServiceType) ([]*net.UDPAddr, error)

	// Gateways returns an array of all gateways.
	Gateways() ([]GatewayInfo, error)

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

func FromJSONBytes(raw []byte) (Topology, error) {
	t, err := RWTopologyFromJSONBytes(raw)
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

func (t *topologyS) MakeHostInfos(st ServiceType) ([]*net.UDPAddr, error) {
	var hostInfos []*net.UDPAddr
	addresses, err := t.Topology.getAllTopoAddrs(st)
	if err != nil {
		return nil, err
	}
	for _, a := range addresses {
		if tmp := a.SCIONAddress; tmp != nil {
			hostInfos = append(hostInfos, copyUDPAddr(tmp))
		}
	}
	return hostInfos, nil
}

func (t *topologyS) Core() bool {
	return t.Topology.IsCore
}

func (t *topologyS) Gateways() ([]GatewayInfo, error) {
	ret := []GatewayInfo{}
	keys := []string{}
	for k := range t.Topology.SIG {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := t.Topology.SIG[k]
		ret = append(ret, v)
	}

	return ret, nil
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

func (t *topologyS) topoAddress(svc addr.HostSVC, name string) *TopoAddr {
	var addresses IDAddrMap
	switch svc.Base() {
	case addr.SvcDS:
		addresses = t.Topology.DS
	case addr.SvcCS:
		addresses = t.Topology.CS
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
	st, err := toServiceType(svc)
	if err != nil {
		return nil, err
	}
	names := t.SVCNames(svc)
	if len(names) == 0 {
		return nil, serrors.New("no address found")
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
			return nil, serrors.New("no instances found for service", "svc", svc)
		}
		return nil, serrors.WithCtx(addr.ErrUnsupportedSVCAddress, "svc", svc)
	}
	underlay, err := t.underlayByName(svc, name)
	if err != nil {
		return nil, serrors.WrapStr("BUG! Selected random service name, but service info not found",
			err, "service_names", names, "selected_name", name)
	}
	// FIXME(scrye): This should return net.Addr
	return underlay, nil
}

func supportedSVC(svc addr.HostSVC) bool {
	b := svc.Base()
	return b == addr.SvcDS || b == addr.SvcCS
}

func (t *topologyS) UnderlayMulticast(svc addr.HostSVC) ([]*net.UDPAddr, error) {
	st, err := toServiceType(svc)
	if err != nil {
		return nil, err
	}
	topoAddrs, err := t.Topology.getAllTopoAddrs(st)
	if err != nil {
		return nil, serrors.Wrap(addr.ErrUnsupportedSVCAddress, err, "svc", svc)
	}

	if len(topoAddrs) == 0 {
		return nil, serrors.New("no instances found for service", "svc", svc)
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

func (t *topologyS) underlayByName(svc addr.HostSVC, name string) (*net.UDPAddr, error) {
	st, err := toServiceType(svc)
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

func toServiceType(svc addr.HostSVC) (ServiceType, error) {
	switch svc.Base() {
	case addr.SvcDS:
		return Discovery, nil
	case addr.SvcCS:
		return Control, nil
	default:
		return 0, serrors.WithCtx(addr.ErrUnsupportedSVCAddress, "svc", svc)
	}
}

func (t *topologyS) IFInfoMap() IfInfoMap {
	return t.Topology.IFInfoMap
}

func (t *topologyS) BRNames() []string {
	return t.Topology.BRNames
}

func (t *topologyS) SVCNames(svc addr.HostSVC) ServiceNames {
	var m IDAddrMap
	switch svc.Base() {
	case addr.SvcDS:
		m = t.Topology.DS
	case addr.SvcCS:
		m = t.Topology.CS
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

func Digest(t interface{}) ([]byte, error) {
	h := sha256.New()
	enc := json.NewEncoder(h)
	if err := enc.Encode(t); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
