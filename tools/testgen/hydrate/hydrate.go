// Copyright 2026 Anapaya Systems
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

// Package hydrate resolves the implicit addressing of a parsed topology. It
// groups interfaces onto border routers, lays out one containerlab host per
// border router (co-locating the control service and daemon on the first
// host), and allocates subnets, addresses and ports via an [Allocator]. The
// result is a [Network] consumed by the config and clab phases.
package hydrate

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/tools/testgen/topo"
)

// Well-known service ports. Each host has a unique address, so reusing ports
// across hosts is fine.
const (
	routerInternalPort = 30042
	routerExternalPort = 50000 // BR external underlay UDP port
	controlPort        = 30252
	controlAPIPort     = 30452
	daemonPort         = 30255
	daemonAPIPort      = 30455
	routerAPIPort      = 30442
)

// Network is the fully resolved topology with all addressing assigned.
type Network struct {
	ASes []*AS // sorted by ISD-AS
}

// AS is a resolved autonomous system.
type AS struct {
	IA       addr.IA
	Attrs    topo.ASEntry
	MTU      int
	Underlay topo.UnderlayType
	Subnet   netip.Prefix

	Hosts         []*Host
	BorderRouters []*BorderRouter
	Control       Service
	Daemon        Service
}

// Host is one containerlab host (container) of an AS.
type Host struct {
	Name         string        // host-1, host-2, …
	Addr         netip.Addr    // this host's address within the AS subnet
	BorderRouter *BorderRouter // border router on this host, if any
	Control      bool          // host runs the control service (host-1)
	Daemon       bool          // host runs the daemon (host-1)
}

// Service is a control/daemon service endpoint.
type Service struct {
	ID   string
	Addr netip.AddrPort
	API  netip.AddrPort
}

// BorderRouter is a resolved border router.
type BorderRouter struct {
	ID           string
	Host         string
	Label        string // the link suffix tag (e.g. "A"); empty for the default group
	InternalAddr netip.AddrPort
	APIAddr      netip.AddrPort
	Interfaces   []*Interface
}

// Interface is a resolved external (inter-AS) interface.
type Interface struct {
	IfID       iface.ID
	LinkType   topo.LinkType // relationship of the neighbor as seen from this AS
	Underlay   topo.UnderlayType
	Net        netip.Prefix // the link's underlay network
	Local      netip.AddrPort
	Remote     netip.AddrPort
	RemoteIA   addr.IA
	RemoteIfID iface.ID
	MTU        int
}

// Hydrate resolves the topology into a fully addressed [Network].
func Hydrate(t *topo.Topo, alloc Allocator) (*Network, error) {
	ias := sortedIAs(t)

	ases := make(map[addr.IA]*AS, len(ias))
	net := &Network{}
	for _, ia := range ias {
		entry := t.ASes[ia]
		asAlloc, err := alloc.AS(ia, entry.Underlay.OrDefault())
		if err != nil {
			return nil, err
		}
		mtu := entry.MTU
		if mtu == 0 {
			mtu = topo.DefaultMTU
		}
		a := &AS{
			IA:       ia,
			Attrs:    entry,
			MTU:      mtu,
			Underlay: entry.Underlay.OrDefault(),
			Subnet:   asAlloc.Subnet,
		}
		ases[ia] = a
		net.ASes = append(net.ASes, a)
	}

	if err := assignBorderRouters(t, ases, alloc); err != nil {
		return nil, err
	}
	for _, a := range net.ASes {
		layoutHosts(a)
	}
	return net, nil
}

// assignBorderRouters walks the links in file order, grouping interfaces onto
// border routers and assigning underlay addresses. By default all of an AS's
// interfaces share a single border router; an explicit link suffix (e.g.
// "1-ff00:0:110-A#1") groups the tagged interfaces onto their own border
// router. Border router IDs are assigned later, in layoutHosts.
func assignBorderRouters(t *topo.Topo, ases map[addr.IA]*AS, alloc Allocator) error {
	// Per-AS state: the border router for each group key (tag, or "" default).
	brByKey := map[addr.IA]map[string]*BorderRouter{}

	getBR := func(ep topo.Endpoint) *BorderRouter {
		a := ases[ep.IA]
		keys := brByKey[ep.IA]
		if keys == nil {
			keys = map[string]*BorderRouter{}
			brByKey[ep.IA] = keys
		}
		if br, ok := keys[ep.BR]; ok {
			return br
		}
		br := &BorderRouter{Label: ep.BR}
		keys[ep.BR] = br
		a.BorderRouters = append(a.BorderRouters, br)
		return br
	}

	for i, l := range t.Links {
		la, err := alloc.Link(i, l)
		if err != nil {
			return serrors.Wrap("allocating link", err, "index", i)
		}
		port := uint16(routerExternalPort)
		brA := getBR(l.A)
		brB := getBR(l.B)
		brA.Interfaces = append(brA.Interfaces, &Interface{
			IfID:       l.A.IfID,
			LinkType:   l.LinkAtoB,
			Underlay:   l.Underlay.OrDefault(),
			Net:        la.Subnet,
			Local:      netip.AddrPortFrom(la.A, port),
			Remote:     netip.AddrPortFrom(la.B, port),
			RemoteIA:   l.B.IA,
			RemoteIfID: l.B.IfID,
			MTU:        linkMTU(l, ases[l.A.IA], ases[l.B.IA]),
		})
		brB.Interfaces = append(brB.Interfaces, &Interface{
			IfID:       l.B.IfID,
			LinkType:   invert(l.LinkAtoB),
			Underlay:   l.Underlay.OrDefault(),
			Net:        la.Subnet,
			Local:      netip.AddrPortFrom(la.B, port),
			Remote:     netip.AddrPortFrom(la.A, port),
			RemoteIA:   l.A.IA,
			RemoteIfID: l.A.IfID,
			MTU:        linkMTU(l, ases[l.A.IA], ases[l.B.IA]),
		})
	}
	return nil
}

// layoutHosts assigns one host per border router and co-locates the control
// service and daemon on the first host. The default (untagged) border router is
// ordered first; tagged border routers follow in first-encounter order. Hosts
// are named after their suffix tag ("host-A", "host-B"); the default host is
// "host-1".
func layoutHosts(a *AS) {
	iaFile := addr.FormatIA(a.IA, addr.WithFileSeparator())
	hostAddr := func(n int) netip.Addr { return offset(a.Subnet.Addr(), uint64(n)) }

	// Stable-sort the default (empty label) border router to the front while
	// preserving the encounter order of the tagged ones.
	sort.SliceStable(a.BorderRouters, func(i, j int) bool {
		return a.BorderRouters[i].Label == "" && a.BorderRouters[j].Label != ""
	})

	for i, br := range a.BorderRouters {
		name := "host-1"
		if br.Label != "" {
			name = "host-" + br.Label
		}
		ha := hostAddr(i + 1)
		br.ID = fmt.Sprintf("br%s-%d", iaFile, i+1)
		br.Host = name
		br.InternalAddr = netip.AddrPortFrom(ha, routerInternalPort)
		br.APIAddr = netip.AddrPortFrom(ha, routerAPIPort)
		a.Hosts = append(a.Hosts, &Host{Name: name, Addr: ha, BorderRouter: br})
	}
	// Control service and daemon live on host-1. If the AS has no border
	// router, create a dedicated host-1 for them.
	if len(a.Hosts) == 0 {
		ha := hostAddr(1)
		a.Hosts = append(a.Hosts, &Host{Name: "host-1", Addr: ha})
	}
	h1 := a.Hosts[0]
	h1.Control = true
	h1.Daemon = true
	a.Control = Service{
		ID:   fmt.Sprintf("cs%s-1", iaFile),
		Addr: netip.AddrPortFrom(h1.Addr, controlPort),
		API:  netip.AddrPortFrom(h1.Addr, controlAPIPort),
	}
	a.Daemon = Service{
		ID:   fmt.Sprintf("sd%s", iaFile),
		Addr: netip.AddrPortFrom(h1.Addr, daemonPort),
		API:  netip.AddrPortFrom(h1.Addr, daemonAPIPort),
	}
}

func linkMTU(l topo.Link, a, b *AS) int {
	if l.MTU != 0 {
		return l.MTU
	}
	mtu := a.MTU
	if b.MTU < mtu {
		mtu = b.MTU
	}
	return mtu
}

func invert(lt topo.LinkType) topo.LinkType {
	switch lt {
	case topo.Child:
		return topo.Parent
	case topo.Parent:
		return topo.Child
	default:
		return lt
	}
}

func sortedIAs(t *topo.Topo) []addr.IA {
	ias := make([]addr.IA, 0, len(t.ASes))
	for ia := range t.ASes {
		ias = append(ias, ia)
	}
	sort.Slice(ias, func(i, j int) bool { return ias[i].String() < ias[j].String() })
	return ias
}
