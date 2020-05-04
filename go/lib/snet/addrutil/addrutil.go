// Copyright 2018 Anapaya Systems
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

package addrutil

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/topology"
)

// Pather computes the remote address with a path based on the provided segment.
type Pather interface {
	GetPath(svc addr.HostSVC, ps *seg.PathSegment) (*snet.SVCAddr, error)
}

// NewPather is a temporary helper until header v2 is complete.
func NewPather(provider topology.Provider, headerV2 bool) Pather {
	var pather Pather = LegacyPather{TopoProvider: provider}
	if headerV2 {
		pather = PatherV2{
			UnderlayNextHop: func(ifID uint16) (*net.UDPAddr, bool) {
				return provider.Get().UnderlayNextHop2(common.IFIDType(ifID))
			},
		}
	}
	return pather
}

// PatherV2 creates paths in the V2 header format
type PatherV2 struct {
	// UnderlayNextHop determines the next hop underlay address for the
	// specified interface id.
	UnderlayNextHop func(ifID uint16) (*net.UDPAddr, bool)
}

func (p PatherV2) GetPath(svc addr.HostSVC, ps *seg.PathSegment) (*snet.SVCAddr, error) {
	if len(ps.ASEntries) == 0 {
		return nil, serrors.New("empty path")
	}

	beta := ps.SData.SegID
	// The hop fields need to be in reversed order.
	hopFields := make([]*path.HopField, len(ps.ASEntries))
	for i, entry := range ps.ASEntries {
		if len(entry.HopEntries) == 0 {
			return nil, serrors.New("hop with no entry", "index", i)
		}
		hopFields[len(hopFields)-1-i] = &path.HopField{
			ConsIngress: entry.HopEntries[0].HopField.ConsIngress,
			ConsEgress:  entry.HopEntries[0].HopField.ConsEgress,
			ExpTime:     entry.HopEntries[0].HopField.ExpTime,
			Mac:         entry.HopEntries[0].HopField.MAC,
		}
		beta = beta ^ binary.BigEndian.Uint16(entry.HopEntries[0].HopField.MAC[:2])
	}

	hops := len(hopFields)
	dec := scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF:  0,
				CurrINF: 0,
				SegLen:  [3]uint8{uint8(hops), 0, 0},
			},
			NumHops: hops,
			NumINF:  1,
		},
		InfoFields: []*path.InfoField{{
			Timestamp: ps.SData.RawTimestamp,
			ConsDir:   false,
			SegID:     beta,
		}},
		HopFields: hopFields,
	}
	raw := make([]byte, dec.Len())
	if err := dec.SerializeTo(raw); err != nil {
		return nil, serrors.WrapStr("serializing path", err)
	}
	ifID := dec.HopFields[0].ConsIngress
	nextHop, ok := p.UnderlayNextHop(ifID)
	if !ok {
		return nil, serrors.New("first-hop border router not found", "intf_id", ifID)
	}
	return &snet.SVCAddr{
		IA:      ps.FirstIA(),
		Path:    spath.NewV2(raw, false),
		NextHop: nextHop,
		SVC:     svc,
	}, nil

}

// LegacyPather creates paths in the legacy V1 header format
type LegacyPather struct {
	TopoProvider topology.Provider
}

func (p LegacyPather) GetPath(svc addr.HostSVC, ps *seg.PathSegment) (*snet.SVCAddr, error) {
	return getPath(svc, ps, p.TopoProvider)
}

// getPath creates a path from the given segment and then creates a snet.SVCAddr.
func getPath(svc addr.HostSVC, ps *seg.PathSegment,
	topoProv topology.Provider) (*snet.SVCAddr, error) {

	p, err := legacyPath(ps)
	if err != nil {
		return nil, serrors.WrapStr("constructing path from segment", err)
	}
	if err := p.Reverse(); err != nil {
		return nil, serrors.WrapStr("reversing path", err)
	}
	if err := p.InitOffsets(); err != nil {
		return nil, serrors.WrapStr("initializing offsets", err)
	}
	hopF, err := p.GetHopField(p.HopOff)
	if err != nil {
		return nil, serrors.WrapStr("extracting first hop field", err)
	}
	topo := topoProv.Get()
	ifID := hopF.ConsIngress
	UnderlayNextHop, ok := topo.UnderlayNextHop2(ifID)
	if !ok {
		return nil, serrors.New("first-hop border router not found", "intf_id", ifID)
	}
	return &snet.SVCAddr{IA: ps.FirstIA(), Path: p, NextHop: UnderlayNextHop, SVC: svc}, nil
}

// ResolveLocal returns the local IP address used for traffic destined to dst.
func ResolveLocal(dst net.IP) (net.IP, error) {
	udpAddr := net.UDPAddr{IP: dst, Port: 1}
	udpConn, err := net.DialUDP(udpAddr.Network(), nil, &udpAddr)
	if err != nil {
		return nil, err
	}
	defer udpConn.Close()
	srcIP := udpConn.LocalAddr().(*net.UDPAddr).IP
	return srcIP, nil
}

// legacyPath constructs a spath.Path from the path segment in construction direction.
func legacyPath(ps *seg.PathSegment) (*spath.Path, error) {
	info, err := spath.InfoFFromRaw(ps.SData.RawInfo)
	if err != nil {
		return nil, err
	}
	inf := spath.InfoField{
		ConsDir: true,
		Hops:    uint8(len(ps.ASEntries)),
		TsInt:   info.TsInt,
		ISD:     info.ISD,
	}

	buf := bytes.Buffer{}
	if _, err = inf.WriteTo(&buf); err != nil {
		return nil, err
	}
	for _, asEntry := range ps.ASEntries {
		if len(asEntry.HopEntries) == 0 {
			return nil, serrors.New("ASEntry has no HopEntry", "asEntry", asEntry)
		}
		hf := spath.HopField{
			ExpTime:     spath.ExpTimeType(asEntry.HopEntries[0].HopField.ExpTime),
			ConsIngress: common.IFIDType(asEntry.HopEntries[0].HopField.ConsIngress),
			ConsEgress:  common.IFIDType(asEntry.HopEntries[0].HopField.ConsEgress),
			Mac:         asEntry.HopEntries[0].HopField.MAC,
		}
		if _, err = hf.WriteTo(&buf); err != nil {
			return nil, err
		}
	}
	return &spath.Path{Raw: buf.Bytes()}, nil
}
