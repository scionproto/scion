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
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

// ASInfo provides information about the local AS.
type ASInfo struct {
	IA  addr.IA
	MTU uint16
}

type Querier struct {
	Connector Connector
	IA        addr.IA
}

func (q Querier) Query(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	return q.Connector.Paths(ctx, dst, q.IA, PathReqFlags{})
}

// RevHandler is an adapter for sciond connector to implement snet.RevocationHandler.
type RevHandler struct {
	Connector Connector
}

func (h RevHandler) RevokeRaw(ctx context.Context, rawSRevInfo common.RawBytes) {
	err := h.Connector.RevNotificationFromRaw(ctx, rawSRevInfo)
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
	r, err := h.Connector.SVCInfo(ctx, []addr.HostSVC{svc})
	if err != nil {
		return nil, err
	}
	entry, ok := r[svc]
	if !ok {
		return nil, serrors.New("no entry found", "svc", svc, "services", r)
	}
	a, err := net.ResolveUDPAddr("udp", entry)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: a.IP, Port: topology.EndhostPort, Zone: a.Zone}, nil
}

func svcAddrToProto(svc addr.HostSVC) proto.ServiceType {
	switch svc {
	case addr.SvcCS:
		return proto.ServiceType_cs
	case addr.SvcSIG:
		return proto.ServiceType_sig
	default:
		return proto.ServiceType_unset
	}
}

func protoSVCToAddr(svc proto.ServiceType) addr.HostSVC {
	switch svc {
	case proto.ServiceType_bs, proto.ServiceType_cs, proto.ServiceType_ps:
		return addr.SvcCS
	case proto.ServiceType_sig:
		return addr.SvcSIG
	default:
		return addr.SvcNone
	}
}

type Path struct {
	interfaces []snet.PathInterface
	underlay   *net.UDPAddr
	spath      *spath.Path
	mtu        uint16
	expiry     time.Time
	dst        addr.IA
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
	return p.interfaces[len(p.interfaces)-1].IA
}

func (p Path) Metadata() snet.PathMetadata {
	return p
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
	return fmt.Sprintf("Hops: [%s] MTU: %d NextHop: %s",
		strings.Join(hops, ">"), p.mtu, p.underlay)
}

func (p Path) fmtInterfaces() []string {
	var hops []string
	if len(p.interfaces) == 0 {
		return hops
	}
	intf := p.interfaces[0]
	hops = append(hops, fmt.Sprintf("%s %d", intf.IA, intf.ID))
	for i := 1; i < len(p.interfaces)-1; i += 2 {
		inIntf := p.interfaces[i]
		outIntf := p.interfaces[i+1]
		hops = append(hops, fmt.Sprintf("%d %s %d", inIntf.ID, inIntf.IA, outIntf.ID))
	}
	intf = p.interfaces[len(p.interfaces)-1]
	hops = append(hops, fmt.Sprintf("%d %s", intf.ID, intf.IA))
	return hops
}
