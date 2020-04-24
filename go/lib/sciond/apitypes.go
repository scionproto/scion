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

package sciond

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/proto"
)

type Querier struct {
	Connector Connector
	IA        addr.IA
	MaxPaths  uint16
}

func (q Querier) Query(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	return q.Connector.Paths(ctx, dst, q.IA, PathReqFlags{PathCount: q.MaxPaths})
}

// RevHandler is an adapter for sciond connector to implement snet.RevocationHandler.
type RevHandler struct {
	Connector Connector
}

func (h RevHandler) RevokeRaw(ctx context.Context, rawSRevInfo common.RawBytes) {
	_, err := h.Connector.RevNotificationFromRaw(ctx, rawSRevInfo)
	if err != nil {
		log.FromCtx(ctx).Error("Revocation notification to sciond failed", "err", err)
	}
}

// TopoQuerier can be used to get topology information from sciond.
type TopoQuerier struct {
	Connector Connector
}

// UnderlayAnycast provides any address for the given svc type.
func (h TopoQuerier) UnderlayAnycast(ctx context.Context, svc addr.HostSVC) (*net.UDPAddr, error) {
	psvc := svcAddrToProto(svc)
	if psvc == proto.ServiceType_unset {
		return nil, serrors.New("invalid svc type", "svc", svc)
	}
	r, err := h.Connector.SVCInfo(ctx, []proto.ServiceType{psvc})
	if err != nil {
		return nil, err
	}
	return r.Entries[0].HostInfos[0].UDP(), nil
}

func svcAddrToProto(svc addr.HostSVC) proto.ServiceType {
	switch svc {
	case addr.SvcBS:
		return proto.ServiceType_bs
	case addr.SvcPS:
		return proto.ServiceType_ps
	case addr.SvcCS:
		return proto.ServiceType_cs
	case addr.SvcSIG:
		return proto.ServiceType_sig
	default:
		return proto.ServiceType_unset
	}
}

func ifinfoReplyToMap(ifinfoReply *IFInfoReply) map[common.IFIDType]*net.UDPAddr {
	m := make(map[common.IFIDType]*net.UDPAddr)

	for _, entry := range ifinfoReply.RawEntries {
		m[entry.IfID] = entry.HostInfo.UDP()
	}

	return m
}

type Path struct {
	interfaces []pathInterface
	underlay   *net.UDPAddr
	spath      *spath.Path
	mtu        uint16
	expiry     time.Time
	dst        addr.IA
}

func pathReplyToPaths(pathReply *PathReply, dst addr.IA) ([]snet.Path, error) {
	if pathReply.ErrorCode != ErrorOk {
		return nil, serrors.New("Path lookup had an error", "err_code", pathReply.ErrorCode)
	}
	paths := make([]snet.Path, 0, len(pathReply.Entries))
	for _, pe := range pathReply.Entries {
		p, err := pathReplyEntryToPath(pe, dst)
		if err != nil {
			return nil, serrors.WrapStr("invalid path received", err)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func pathReplyEntryToPath(pe PathReplyEntry, dst addr.IA) (Path, error) {
	if len(pe.Path.Interfaces) == 0 {
		return Path{
			dst: dst,
		}, nil
	}
	sp := spath.New(pe.Path.FwdPath)
	if err := sp.InitOffsets(); err != nil {
		return Path{}, serrors.WrapStr("path error", err)
	}
	underlayAddr := pe.HostInfo.Underlay()
	p := Path{
		interfaces: make([]pathInterface, 0, len(pe.Path.Interfaces)),
		underlay:   underlayAddr,
		spath:      sp,
		mtu:        pe.Path.Mtu,
		expiry:     pe.Path.Expiry(),
	}
	for _, intf := range pe.Path.Interfaces {
		p.interfaces = append(p.interfaces, pathInterface{ia: intf.IA(), id: intf.ID()})
	}
	return p, nil
}

func (p Path) Fingerprint() snet.PathFingerprint {
	if len(p.interfaces) == 0 {
		return ""
	}
	h := sha256.New()
	for _, intf := range p.interfaces {
		binary.Write(h, common.Order, intf.IA().IAInt())
		binary.Write(h, common.Order, intf.ID())
	}
	return snet.PathFingerprint(h.Sum(nil))
}

func (p Path) UnderlayNextHop() *net.UDPAddr {
	if p.underlay == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(p.underlay.IP[:0:0], p.underlay.IP...),
		Port: p.underlay.Port,
		Zone: p.underlay.Zone,
	}
}

func (p Path) Path() *spath.Path {
	if p.spath == nil {
		return nil
	}
	return p.spath.Copy()
}

func (p Path) Interfaces() []snet.PathInterface {
	if p.interfaces == nil {
		return nil
	}
	intfs := make([]snet.PathInterface, 0, len(p.interfaces))
	for _, intf := range p.interfaces {
		intfs = append(intfs, intf)
	}
	return intfs
}

func (p Path) Destination() addr.IA {
	if len(p.interfaces) == 0 {
		return p.dst
	}
	return p.interfaces[len(p.interfaces)-1].IA()
}

func (p Path) MTU() uint16 {
	return p.mtu
}

func (p Path) Expiry() time.Time {
	return p.expiry
}

func (p Path) Copy() snet.Path {
	return Path{
		interfaces: append(p.interfaces[:0:0], p.interfaces...),
		underlay:   p.UnderlayNextHop(), // creates copy
		spath:      p.Path(),            // creates copy
		mtu:        p.mtu,
		expiry:     p.expiry,
	}
}

func (p Path) String() string {
	hops := p.fmtInterfaces()
	return fmt.Sprintf("Hops: [%s] MTU: %d, NextHop: %s",
		strings.Join(hops, ">"), p.mtu, p.underlay)
}

func (p Path) fmtInterfaces() []string {
	var hops []string
	if len(p.interfaces) == 0 {
		return hops
	}
	intf := p.interfaces[0]
	hops = append(hops, fmt.Sprintf("%s %d", intf.IA(), intf.ID()))
	for i := 1; i < len(p.interfaces)-1; i += 2 {
		inIntf := p.interfaces[i]
		outIntf := p.interfaces[i+1]
		hops = append(hops, fmt.Sprintf("%d %s %d", inIntf.ID(), inIntf.IA(), outIntf.ID()))
	}
	intf = p.interfaces[len(p.interfaces)-1]
	hops = append(hops, fmt.Sprintf("%d %s", intf.ID(), intf.IA()))
	return hops
}

type pathInterface struct {
	id common.IFIDType
	ia addr.IA
}

func (i pathInterface) ID() common.IFIDType { return i.id }
func (i pathInterface) IA() addr.IA         { return i.ia }
