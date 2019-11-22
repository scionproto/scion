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

package snetmigrate

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
)

type path struct {
	// sciondPath contains SCIOND-related path metadata.
	sciondPath *sciond.PathReplyEntry
	// spath is the raw SCION forwarding path.
	spath *spath.Path
	// overlay is the intra-AS next-hop to use for this path.
	overlay *net.UDPAddr
	// source is the AS where the path starts.
	source addr.IA
}

// NewPathFromSDReply creates a snet.Path from a sciond.PathReplyEntry. It
// should only be used to refactor code depending on SCIOND into code depending
// on snet.
func NewPathFromSDReply(srcIA addr.IA, replyEntry *sciond.PathReplyEntry) (snet.Path, error) {
	if replyEntry == nil {
		return &path{source: srcIA}, nil
	}
	sp := spath.New(replyEntry.Path.FwdPath)
	// Preinitialize offsets, we don't want to propagate unusable paths
	if err := sp.InitOffsets(); err != nil {
		return nil, serrors.WrapStr("path error", err)
	}
	overlayAddr := replyEntry.HostInfo.Overlay()
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

func (p *path) OverlayNextHop() *net.UDPAddr {
	return copyUDP(p.overlay)
}

func (p *path) Path() *spath.Path {
	if p.spath == nil {
		return nil
	}
	return p.spath.Copy()
}

func (p *path) Interfaces() []snet.PathInterface {
	if p.spath == nil {
		return nil
	}
	res := make([]snet.PathInterface, 0, len(p.sciondPath.Path.Interfaces))
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

func (p *path) Copy() snet.Path {
	return &path{
		sciondPath: p.sciondPath.Copy(),
		spath:      p.spath.Copy(),
		overlay:    copyUDP(p.overlay),
		source:     p.source,
	}
}

func (p *path) String() string {
	if p.sciondPath == nil {
		return ""
	}
	return p.sciondPath.String()
}

func copyUDP(udp *net.UDPAddr) *net.UDPAddr {
	if udp == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(udp.IP[:0:0], udp.IP...),
		Port: udp.Port,
	}
}
