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

package itopo

import (
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

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
	//
	// FIXME(scrye): See whether this or its snet variant below can be removed.
	PublicAddress(svc addr.HostSVC, name string) *addr.AppAddr
	// SPublicAddress gets the public address of a server with the requested type and name, and nil
	// if no such server exists.
	//
	// FIXME(scrye): See whether this or its app variant above can be removed.
	SPublicAddress(svc addr.HostSVC, name string) *snet.Addr

	// Exists returns true if the service and name are present in the topology file.
	Exists(svc addr.HostSVC, name string) bool

	// BindAddress gets the bind address of a server with the requested type and name, and nil
	// if no such server exists.
	//
	// FIXME(scrye): See whether this or its snet variant below can be removed.
	BindAddress(svc addr.HostSVC, name string) *addr.AppAddr
	// BindAddress gets the bind address of a server with the requested type and name, and nil
	// if no such server exists.
	//
	// FIXME(scrye): See whether this or its app variant above can be removed.
	SBindAddress(svc addr.HostSVC, name string) *snet.Addr

	// SBRAddress returns the internal public address of the BR with the specified name.
	SBRAddress(name string) *snet.Addr

	// OverlayAnycast returns the overlay address for an arbitrary server of the requested type.
	OverlayAnycast(svc addr.HostSVC) (*overlay.OverlayAddr, error)
	// OverlayMulticast returns all overlay addresses for the requested type.
	OverlayMulticast(svc addr.HostSVC) ([]*overlay.OverlayAddr, error)
	// OverlayByName returns the overlay address of the server name of the requested type.
	//
	// FIXME(scrye): This isn't really needed. We should also get rid of it.
	OverlayByName(svc addr.HostSVC, name string) (*overlay.OverlayAddr, error)
	// OverlayNextHop2 returns the internal overlay address of the router containing the ID. The
	// return value is encoded as an overlay address.
	//
	// FIXME(scrye): Remove either this or the other method. A single return type should be
	// supported.
	OverlayNextHop2(ifID common.IFIDType) (*overlay.OverlayAddr, bool)

	// OverlayNextHop returns the internal overlay address of the router
	// containing the interface ID.
	//
	// XXX(scrye): Return value is a shallow copy.
	OverlayNextHop(ifID common.IFIDType) (*net.UDPAddr, bool)

	// MakeHostInfos returns the overlay addresses of all services for the specified service type.
	MakeHostInfos(st proto.ServiceType) []net.UDPAddr

	// BR returns information for a specific border router
	//
	// FIXME(scrye): Simplify return type and make it topology format agnostic.
	//
	// XXX(scrye): Return value is a shallow copy.
	BR(name string) (topology.BRInfo, bool)
	// IFInfoMap returns the mapping between interface IDs an internal addresses.
	//
	// FIXME(scrye): Simplify return type and make it topology format agnostic.
	//
	// XXX(scrye): Return value is a shallow copy.
	IFInfoMap() topology.IfInfoMap

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
	SVCNames(svc addr.HostSVC) []string

	// Raw returns a pointer to the underlying topology object. This is included for legacy
	// reasons and should never be used.
	//
	// FIXME(scrye): Remove this.
	//
	// XXX(scrye): Return value is a shallow copy.
	Raw() *topology.Topo
	// Overlay returns the overlay running in the current AS.
	//
	// FIXME(scrye): Remove this.
	Overlay() overlay.Type

	// DS returns the discovery servers in the topology.
	//
	// FIXME(scrye): Simplify return type and make it topology format agnostic.
	//
	// XXX(scrye): Return value is a shallow copy.
	DS() topology.IDAddrMap
}

// NewTopology creates a new empty topology.
func NewTopology() Topology {
	return &topologyS{
		Topology: &topology.Topo{},
	}
}

// NewTopologyFromRaw wraps the high level topology interface API around a raw topology object.
func NewTopologyFromRaw(topo *topology.Topo) Topology {
	return &topologyS{
		Topology: topo,
	}
}

type ServiceType string

func LoadFromFile(path string) (Topology, error) {
	t, err := topology.LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	return &topologyS{
		Topology: t,
	}, nil
}

type topologyS struct {
	Topology *topology.Topo
}

func (t *topologyS) DS() topology.IDAddrMap {
	return t.Topology.DS
}

func (t *topologyS) IA() addr.IA {
	return t.Topology.ISD_AS
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

func (t *topologyS) OverlayNextHop(ifid common.IFIDType) (*net.UDPAddr, bool) {
	ifInfo, ok := t.Topology.IFInfoMap[ifid]
	if !ok {
		return nil, false
	}
	if ifInfo.InternalAddrs.IPv4 != nil {
		if v4Addr := ifInfo.InternalAddrs.IPv4.PublicOverlay; v4Addr != nil {
			return &net.UDPAddr{IP: copyIP(v4Addr.L3().IP()), Port: int(v4Addr.L4())}, true
		}
	}
	if ifInfo.InternalAddrs.IPv6 != nil {
		if v6Addr := ifInfo.InternalAddrs.IPv6.PublicOverlay; v6Addr != nil {
			return &net.UDPAddr{IP: copyIP(v6Addr.L3().IP()), Port: int(v6Addr.L4())}, true
		}
	}
	return nil, false
}

func (t *topologyS) OverlayNextHop2(ifid common.IFIDType) (*overlay.OverlayAddr, bool) {
	ifInfo, ok := t.Topology.IFInfoMap[ifid]
	if !ok {
		return nil, false
	}
	return ifInfo.InternalAddrs.PublicOverlay(t.Topology.Overlay).Copy(), true
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
		if v4Addr := a.PublicAddr(overlay.IPv4); v4Addr != nil {
			hostInfos = append(hostInfos, net.UDPAddr{
				IP:   copyIP(v4Addr.L3.IP()),
				Port: int(v4Addr.L4),
			})
		}
		if v6Addr := a.PublicAddr(overlay.IPv6); v6Addr != nil {
			hostInfos = append(hostInfos, net.UDPAddr{
				IP:   copyIP(v6Addr.L3.IP()),
				Port: int(v6Addr.L4),
			})
		}
	}
	return hostInfos
}

func (t *topologyS) Core() bool {
	return t.Topology.Core
}

func (t *topologyS) BR(name string) (topology.BRInfo, bool) {
	br, ok := t.Topology.BR[name]
	return br, ok
}

func (t *topologyS) SPublicAddress(svc addr.HostSVC, name string) *snet.Addr {
	address := t.PublicAddress(svc, name)
	if address == nil {
		return nil
	}
	return &snet.Addr{
		IA:   t.IA(),
		Host: address.Copy(),
	}
}

func (t *topologyS) PublicAddress(svc addr.HostSVC, name string) *addr.AppAddr {
	topoAddr := t.topoAddress(svc, name)
	if topoAddr == nil {
		return nil
	}
	publicAddr := topoAddr.PublicAddr(topoAddr.Overlay)
	if publicAddr == nil {
		return nil
	}
	return publicAddr.Copy()
}

func (t *topologyS) Exists(svc addr.HostSVC, name string) bool {
	return t.PublicAddress(svc, name) != nil
}

func (t *topologyS) SBindAddress(svc addr.HostSVC, name string) *snet.Addr {
	address := t.BindAddress(svc, name)
	if address == nil {
		return nil
	}
	return &snet.Addr{
		IA:   t.IA(),
		Host: address.Copy(),
	}
}

func (t *topologyS) BindAddress(svc addr.HostSVC, name string) *addr.AppAddr {
	topoAddr := t.topoAddress(svc, name)
	if topoAddr == nil {
		return nil
	}
	bindAddr := topoAddr.BindAddr(topoAddr.Overlay)
	if bindAddr == nil {
		return nil
	}
	return bindAddr.Copy()
}

func (t *topologyS) topoAddress(svc addr.HostSVC, name string) *topology.TopoAddr {
	var addresses topology.IDAddrMap
	switch svc.Base() {
	case addr.SvcBS:
		addresses = t.Topology.BS
	case addr.SvcCS:
		addresses = t.Topology.CS
	case addr.SvcPS:
		addresses = t.Topology.PS
	case addr.SvcSIG:
		addresses = t.Topology.SIG
	}
	if addresses == nil {
		return nil
	}
	return addresses.GetById(name)
}

func (t *topologyS) OverlayAnycast(svc addr.HostSVC) (*overlay.OverlayAddr, error) {
	st, err := toProtoServiceType(svc)
	if err != nil {
		return nil, err
	}
	topoAddr, err := t.Topology.GetAnyTopoAddr(st)
	if err != nil {
		// FIXME(scrye): Return this error because some calling code in the BR searches for it.
		// Ideally, the error should be communicated in a more explicit way.
		return nil, common.NewBasicError("No instances found for SVC address",
			scmp.NewError(scmp.C_Routing, scmp.T_R_UnreachHost, nil, nil), "svc", svc)
	}
	overlayAddr := topoAddr.OverlayAddr(t.Topology.Overlay)
	if overlayAddr == nil {
		return nil, serrors.New("overlay address not found", "svc", svc)
	}
	return overlayAddr.Copy(), nil
}

func (t *topologyS) OverlayMulticast(svc addr.HostSVC) ([]*overlay.OverlayAddr, error) {
	st, err := toProtoServiceType(svc)
	if err != nil {
		return nil, err
	}
	topoAddrs, err := t.Topology.GetAllTopoAddrs(st)
	if err != nil {
		return nil, serrors.WrapStr("SVC not supported", err, "svc", svc)
	}

	if len(topoAddrs) == 0 {
		// FIXME(scrye): Return this error because some calling code in the BR searches for it.
		// Ideally, the error should be communicated in a more explicit way.
		return nil, common.NewBasicError("No instances found for SVC address",
			scmp.NewError(scmp.C_Routing, scmp.T_R_UnreachHost, nil, nil), "svc", svc)
	}

	// Only select each IP:OverlayPort combination once, s.t. the same message isn't multicasted
	// multiple times by the remote dispatcher.
	uniqueOverlayAddrs := make(map[string]*overlay.OverlayAddr)
	for _, topoAddr := range topoAddrs {
		overlayAddr := topoAddr.OverlayAddr(t.Topology.Overlay)
		if overlayAddr == nil {
			continue
		}
		uniqueOverlayAddrs[overlayAddr.String()] = overlayAddr
	}

	var overlayAddrs []*overlay.OverlayAddr
	for _, overlayAddr := range uniqueOverlayAddrs {
		overlayAddrs = append(overlayAddrs, overlayAddr.Copy())
	}
	return overlayAddrs, nil
}

func (t *topologyS) OverlayByName(svc addr.HostSVC, name string) (*overlay.OverlayAddr, error) {
	st, err := toProtoServiceType(svc)
	if err != nil {
		return nil, err
	}
	topoAddr, err := t.Topology.GetTopoAddr(name, st)
	if err != nil {
		return nil, serrors.WrapStr("SVC not supported", err, "svc", svc)
	}
	overlayAddr := topoAddr.OverlayAddr(t.Topology.Overlay)
	if overlayAddr == nil {
		return nil, serrors.New("overlay address not found", "svc", svc)
	}
	return overlayAddr.Copy(), nil
}

func toProtoServiceType(svc addr.HostSVC) (proto.ServiceType, error) {
	switch svc.Base() {
	case addr.SvcBS:
		return proto.ServiceType_bs, nil
	case addr.SvcCS:
		return proto.ServiceType_cs, nil
	case addr.SvcPS:
		return proto.ServiceType_ps, nil
	case addr.SvcSIG:
		return proto.ServiceType_sig, nil
	default:
		// FIXME(scrye): Return this error because some calling code in the BR searches for it.
		// Ideally, the error should be communicated in a more explicit way.
		return 0, common.NewBasicError("Unsupported SVC address",
			scmp.NewError(scmp.C_Routing, scmp.T_R_BadHost, nil, nil), "svc", svc)
	}
}

func (t *topologyS) IFInfoMap() topology.IfInfoMap {
	return t.Topology.IFInfoMap
}

func (t *topologyS) BRNames() []string {
	return t.Topology.BRNames
}

func (t *topologyS) SBRAddress(name string) *snet.Addr {
	br, ok := t.Topology.BR[name]
	if !ok {
		return nil
	}
	return &snet.Addr{
		IA:      t.IA(),
		Host:    br.CtrlAddrs.PublicAddr(br.CtrlAddrs.Overlay),
		NextHop: br.CtrlAddrs.OverlayAddr(br.CtrlAddrs.Overlay),
	}
}

func (t *topologyS) SVCNames(svc addr.HostSVC) []string {
	switch svc.Base() {
	case addr.SvcBS:
		return t.Topology.BSNames
	case addr.SvcCS:
		return t.Topology.CSNames
	case addr.SvcPS:
		return t.Topology.PSNames
	case addr.SvcSIG:
		return t.Topology.SIGNames
	default:
		return nil
	}
}

func (t *topologyS) Overlay() overlay.Type {
	return t.Topology.Overlay
}

func (t *topologyS) Raw() *topology.Topo {
	return t.Topology
}

func copyIP(ip net.IP) net.IP {
	return append(ip[:0:0], ip...)
}
