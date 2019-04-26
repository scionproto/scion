// Copyright 2019 ETH Zurich
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

package snet

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath"
)

// Router performs path resolution for SCION-speaking applications.
//
// Most applications backed by SCIOND can use the default router implementation
// in this package. Applications that run SCIOND-less (PS, SD, BS) might be
// interested in spinning their own implementations.
type Router interface {
	// Route returns a path from the local AS to dst. If dst matches the local
	// AS, an empty path is returned.
	Route(ctx context.Context, dst addr.IA) (Path, error)
	// LocalIA returns the IA from which this router routes.
	LocalIA() addr.IA
}

var _ Router = (*BaseRouter)(nil)

// BaseRouter is a path router implementation that uses a path resolver to
// query SCIOND for paths, or returns empty paths if a path resolver is not
// specified.
type BaseRouter struct {
	// IA is the source AS for paths, usually the local AS.
	IA addr.IA
	// PathResolver to solve path requests. If nil, all path requests yield
	// empty paths.
	PathResolver pathmgr.Resolver
}

// Route uses the specified path resolver (if one exists) to obtain a path from
// the local AS to dst.
func (r *BaseRouter) Route(ctx context.Context, dst addr.IA) (Path, error) {
	if r.PathResolver == nil || dst.Equal(r.IA) {
		return &path{}, nil
	}
	aps := r.PathResolver.Query(ctx, r.IA, dst, sciond.PathReqFlags{})
	if len(aps) == 0 {
		return nil, common.NewBasicError("unable to find paths", nil)
	}

	pathEntry := aps.GetAppPath("").Entry
	p := spath.New(pathEntry.Path.FwdPath)
	// Preinitialize offsets, we don't want to propagate unusable paths
	if err := p.InitOffsets(); err != nil {
		return nil, common.NewBasicError("path error", err)
	}
	overlayAddr, err := pathEntry.HostInfo.Overlay()
	if err != nil {
		return nil, common.NewBasicError("path error", err)
	}
	return &path{
		sciondPath: pathEntry,
		spath:      p,
		overlay:    overlayAddr,
		source:     r.IA,
	}, nil
}

func (r *BaseRouter) LocalIA() addr.IA {
	return r.IA
}

// Path is an abstract representation of a path. Most applications do not need
// access to the raw internals.
//
// An empty path is a special kind of path that can be used for intra-AS
// traffic. Empty paths are valid return values for certain route calls (e.g.,
// if the source and destination ASes match, or if a router was configured
// without a source of paths).
type Path interface {
	// OverlayNextHop returns the address:port pair of a local-AS overlay
	// speaker. Usually, this is a border router that will forward the traffic.
	OverlayNextHop() *overlay.OverlayAddr
	// Path returns a raw (data-plane compatible) representation of the path.
	// The returned path is initialized and ready for use in snet calls that
	// deal with raw paths.
	Path() *spath.Path
	// Destination is the AS the path points to. Empty paths return the local
	// AS of the router that created them.
	Destination() addr.IA
}

var _ Path = (*path)(nil)

type path struct {
	// sciondPath contains SCIOND-related path metadata.
	sciondPath *sciond.PathReplyEntry
	// spath is the raw SCION forwarding path.
	spath *spath.Path
	// overlay is the intra-AS next-hop to use for this path.
	overlay *overlay.OverlayAddr
	// source is the AS where the path starts.
	source addr.IA
}

func (p *path) OverlayNextHop() *overlay.OverlayAddr {
	return p.overlay
}

func (p *path) Path() *spath.Path {
	if p.spath == nil {
		return nil
	}
	return p.spath.Copy()
}

func (p *path) Destination() addr.IA {
	if p.sciondPath == nil {
		return p.source
	}
	return p.sciondPath.Path.DstIA()
}

// partialPath is a path object with incomplete metadata. It is used as a
// temporary solution where a full path cannot be reconstituted from other
// objects, notably snet.Addr.
type partialPath struct {
	spath       *spath.Path
	overlay     *overlay.OverlayAddr
	destination addr.IA
}

func (p *partialPath) OverlayNextHop() *overlay.OverlayAddr {
	return p.overlay
}

func (p *partialPath) Path() *spath.Path {
	if p.spath == nil {
		return nil
	}
	return p.spath.Copy()
}

func (p *partialPath) Destination() addr.IA {
	return p.destination
}

// LocalMachine describes aspects of the host system and its network.
type LocalMachine struct {
	// InterfaceIP is the default L3 address for connections originating from
	// this machine. It should be an address configured on a host interface
	// that is reachable from the network.
	InterfaceIP net.IP
	// If this machine is behind a NAT, PublicIP should be set to the public IP
	// of the NAT. If the local IP is already public, PublicIP should be set to
	// nil.
	PublicIP net.IP
}

// AppAddress returns a public address for the local machine. The port is
// set to 0.
func (m *LocalMachine) AppAddress() *addr.AppAddr {
	ip := m.InterfaceIP
	if m.PublicIP != nil {
		ip = m.PublicIP
	}
	return &addr.AppAddr{
		L3: addr.HostFromIP(ip),
		L4: addr.NewL4UDPInfo(0),
	}
}

// BindAddress returns a bind address for the local machine. The port is
// set to 0.
func (m *LocalMachine) BindAddress() *overlay.OverlayAddr {
	ov, err := overlay.NewOverlayAddr(
		addr.HostFromIP(m.InterfaceIP),
		addr.NewL4UDPInfo(0),
	)
	if err != nil {
		// XXX(scrye): due to the hardcoded types in this function, this should
		// never panic
		panic(err)
	}
	return ov
}
