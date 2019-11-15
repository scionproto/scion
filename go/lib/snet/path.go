// Copyright 2019 Anapaya Systems
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
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/spath"
)

// Path is an abstract representation of a path. Most applications do not need
// access to the raw internals.
//
// An empty path is a special kind of path that can be used for intra-AS
// traffic. Empty paths are valid return values for certain route calls (e.g.,
// if the source and destination ASes match, or if a router was configured
// without a source of paths).
type Path interface {
	// Fingerprint uniquely identifies the path based on the sequence of
	// ASes and BRs. Other metadata, such as MTU or NextHop have no effect
	// on the fingerprint. Empty string means unknown fingerprint.
	Fingerprint() string
	// OverlayNextHop returns the address:port pair of a local-AS overlay
	// speaker. Usually, this is a border router that will forward the traffic.
	OverlayNextHop() *overlay.OverlayAddr
	// Path returns a raw (data-plane compatible) representation of the path.
	// The returned path is initialized and ready for use in snet calls that
	// deal with raw paths.
	Path() *spath.Path
	// Interfaces returns a list of interfaces on the path. If the list is not
	// available the result is nil.
	Interfaces() []PathInterface
	// Destination is the AS the path points to. Empty paths return the local
	// AS of the router that created them.
	Destination() addr.IA
	// MTU returns the MTU of the path. If the result is zero, MTU is unknown.
	MTU() uint16
	// Expiry returns the expiration time of the path. If the result is a zero
	// value expiration time is unknown.
	Expiry() time.Time
	// Copy create a copy of the path.
	Copy() Path
}

// PathInterface is an interface of the path. This is currently an interface so
// that packages which can not depend on snet can still implement the snet.Path
// interface.
type PathInterface interface {
	ID() common.IFIDType
	IA() addr.IA
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

func newPathFromSDReply(srcIA addr.IA, replyEntry *sciond.PathReplyEntry) (Path, error) {
	sp := spath.New(replyEntry.Path.FwdPath)
	// Preinitialize offsets, we don't want to propagate unusable paths
	if err := sp.InitOffsets(); err != nil {
		return nil, serrors.WrapStr("path error", err)
	}
	overlayAddr, err := replyEntry.HostInfo.Overlay()
	if err != nil {
		return nil, serrors.WrapStr("path error", err)
	}
	return &path{
		sciondPath: replyEntry,
		spath:      sp,
		overlay:    overlayAddr,
		source:     srcIA,
	}, nil
}

func (p *path) Fingerprint() string {
	if p.sciondPath == nil {
		return ""
	}
	h := sha256.New()
	for _, iface := range p.sciondPath.Path.Interfaces {
		binary.Write(h, common.Order, iface.RawIsdas)
		binary.Write(h, common.Order, iface.IfID)
	}
	return string(h.Sum(nil))
}

func (p *path) OverlayNextHop() *overlay.OverlayAddr {
	return p.overlay.Copy()
}

func (p *path) Path() *spath.Path {
	if p.spath == nil {
		return nil
	}
	return p.spath.Copy()
}

func (p *path) Interfaces() []PathInterface {
	if p.spath == nil {
		return nil
	}
	res := make([]PathInterface, 0, len(p.sciondPath.Path.Interfaces))
	for _, intf := range p.sciondPath.Path.Interfaces {
		res = append(res, intf)
	}
	return res
}

func (p *path) Destination() addr.IA {
	if p.sciondPath == nil {
		return p.source
	}
	return p.sciondPath.Path.DstIA()
}

func (p *path) MTU() uint16 {
	if p.sciondPath == nil {
		return 0
	}
	return p.sciondPath.Path.Mtu
}

func (p *path) Expiry() time.Time {
	if p.sciondPath == nil {
		return time.Time{}
	}
	return p.sciondPath.Path.Expiry()
}

func (p *path) Copy() Path {
	return &path{
		sciondPath: p.sciondPath.Copy(),
		spath:      p.spath.Copy(),
		overlay:    p.overlay.Copy(),
		source:     p.source,
	}
}

func (p *path) String() string {
	if p.sciondPath == nil {
		return ""
	}
	return p.sciondPath.String()
}

// partialPath is a path object with incomplete metadata. It is used as a
// temporary solution where a full path cannot be reconstituted from other
// objects, notably snet.Addr.
type partialPath struct {
	spath       *spath.Path
	overlay     *overlay.OverlayAddr
	destination addr.IA
}

func (p *partialPath) Fingerprint() string {
	return ""
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

func (p *partialPath) Interfaces() []PathInterface {
	return nil
}

func (p *partialPath) Destination() addr.IA {
	return p.destination
}

func (p *partialPath) MTU() uint16 {
	return 0
}

func (p *partialPath) Expiry() time.Time {
	return time.Time{}
}

func (p *partialPath) Copy() Path {
	return &partialPath{
		spath:       p.spath.Copy(),
		overlay:     p.overlay.Copy(),
		destination: p.destination,
	}
}
