// Copyright 2018 ETH Zurich
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

package tpkt

import (
	"fmt"
	"hash"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
)

// ScnPath contains the scion path (which is raw) and the path definition.
// It is used to define hand-crafted paths.
type ScnPath struct {
	spath.Path
	Segs Segments
}

// GenPath converts info and hop field indexes to their proper offsets.
// Both infoF and hopF are relative indexes, where infoF index indicates the references segment
// position and hopF index indicates the hop fields position within the segment.
// Note that this function writes the raw path then parses it to calculate the expected
// hop field macs.
func GenPath(infoF, hopF int, segs Segments) *ScnPath {
	p := &ScnPath{}
	for i := 0; i < infoF; i++ {
		// Each segments consists of one InfoField and N HopFields
		p.InfOff += spath.InfoFieldLength + int(segs[i].Inf.Hops*spath.HopFieldLength)
	}
	p.HopOff = p.InfOff + spath.InfoFieldLength + hopF*spath.HopFieldLength
	// Write SCION path
	p.Raw = make(common.RawBytes, segs.Len())
	segs.initMacs()
	if _, err := segs.WriteTo(p.Raw); err != nil {
		return nil
	}
	// Parse the raw packet to retrieve hop fields mac
	p.Parse(p.Raw)
	return p
}

func (p *ScnPath) Parse(b []byte) error {
	if len(b) == 0 || len(b)%common.LineLen != 0 {
		return fmt.Errorf("Bad path length, actual=%d", len(b))
	}
	offset := 0
	for offset < len(b) {
		seg := &SegDef{}
		l, err := seg.Parse(b[offset:])
		if err != nil {
			return err
		}
		p.Segs = append(p.Segs, seg)
		offset += l
	}
	p.Raw = b
	return nil
}

func (p *ScnPath) String() string {
	if p == nil {
		return ""
	}
	return p.Segs.String()
}

func (p *ScnPath) Check(o *ScnPath) error {
	if len(o.Segs) != len(p.Segs) {
		return fmt.Errorf("Number of segments mismatch, expected=%d, actual=%d",
			len(p.Segs), len(o.Segs))
	}
	for i := range p.Segs {
		if err := p.Segs[i].Equal(o.Segs[i]); err != nil {
			return err
		}
	}
	return nil
}

func (p *ScnPath) Len() int {
	if p == nil {
		return 0
	}
	return p.Segs.Len()
}

type Segments []*SegDef

func (segs Segments) Len() int {
	l := 0
	for i := range segs {
		l += segs[i].segLen()
	}
	return l
}

func (segs Segments) WriteTo(b []byte) (int, error) {
	offset := 0
	for i := range segs {
		n, err := segs[i].WriteTo(b[offset:])
		if err != nil {
			return offset, nil
		}
		offset += n
	}
	return offset, nil
}

func (segs Segments) String() string {
	return PrintSegments(segs, "", " ")
}

func (segs Segments) initMacs() {
	for i := range segs {
		segs[i].initMacs()
	}
}

func (segs Segments) SetMac(infoF, hopF int, hashMac hash.Hash) Segments {
	segs[infoF].initMacs()
	segs[infoF].macs[hopF] = hashMac
	return segs
}

func PrintSegments(segs Segments, indent, sep string) string {
	var str []string
	for _, s := range segs {
		str = append(str, fmt.Sprintf("%s%s", indent, s))
	}
	return strings.Join(str, sep)
}

var defaultMac = common.RawBytes{0xef, 0xef, 0xef}

// SegDef defines a path segment
type SegDef struct {
	Inf  *spath.InfoField
	Hops []*spath.HopField
	macs []hash.Hash
}

func (s *SegDef) initMacs() {
	if s.macs == nil {
		s.macs = make([]hash.Hash, len(s.Hops))
	}
}

func (s *SegDef) Parse(b []byte) (int, error) {
	inf, err := spath.InfoFFromRaw(b)
	if err != nil {
		return 0, err
	}
	s.Inf = inf
	segLen := int(spath.InfoFieldLength + inf.Hops*common.LineLen)
	if segLen > len(b) {
		return 0, fmt.Errorf("Buffer is too short, expected=%d, actual=%d", segLen, len(b))
	}
	for offset := spath.InfoFieldLength; offset < segLen; offset += common.LineLen {
		hop, err := spath.HopFFromRaw(b[offset:])
		if err != nil {
			return 0, err
		}
		s.Hops = append(s.Hops, hop)
	}
	return segLen, nil
}

func (seg *SegDef) WriteTo(b []byte) (int, error) {
	var err error
	// Write Info Field
	seg.Inf.Write(b)
	// Write Hop Fields
	prevHop := []byte{}
	nHops := len(seg.Hops)
	for j := range seg.Hops {
		hopIdx := j
		if !seg.Inf.ConsDir {
			// For reverse ConsDir, start from last hop
			hopIdx = nHops - 1 - j
		}
		hop := seg.Hops[hopIdx]
		mac := seg.macs[hopIdx]
		if hop.Mac == nil {
			if mac != nil {
				mac.Reset()
				// TODO(sgmonroy) peer interface support
				hop.Mac, err = hop.CalcMac(mac, seg.Inf.TsInt, prevHop)
				if err != nil {
					return 0, err
				}
			} else {
				hop.Mac = defaultMac
			}
		}
		curOff := spath.InfoFieldLength + hopIdx*spath.HopFieldLength
		hop.Write(b[curOff:])
		prevHop = b[curOff+1 : curOff+spath.HopFieldLength]
	}
	return spath.InfoFieldLength + nHops*spath.HopFieldLength, nil
}

func (s *SegDef) String() string {
	var str []string
	var cons, short, peer string
	if s.Inf.ConsDir {
		cons = "C"
	}
	if s.Inf.Shortcut {
		short = "S"
	}
	if s.Inf.Peer {
		peer = "P"
	}
	for i := range s.Hops {
		var xover, ver string
		if s.Hops[i].Xover {
			xover = "X"
		}
		if s.Hops[i].VerifyOnly {
			ver = "V"
		}
		str = append(str, fmt.Sprintf("%1s%1s %04d:%04d %s", xover, ver,
			s.Hops[i].ConsIngress, s.Hops[i].ConsEgress, s.Hops[i].Mac))
	}
	return fmt.Sprintf("[%1s%1s%1s] %s", cons, short, peer, strings.Join(str, " <-> "))
}

func (s *SegDef) segLen() int {
	return spath.InfoFieldLength + spath.HopFieldLength*len(s.Hops)
}

func (s *SegDef) Equal(o *SegDef) error {
	if !s.Inf.Eq(o.Inf) {
		return fmt.Errorf("Info Field mismatch\n  Expected: %s\n  Actual:   %s\n", s.Inf, o.Inf)
	}
	if len(s.Hops) != len(o.Hops) {
		return fmt.Errorf("Different number of Hop Fields\n  Expected: %s\n  Actual:   %s\n", s, o)
	}
	for i := range s.Hops {
		if !s.Hops[i].Eq(o.Hops[i]) {
			return fmt.Errorf("Hop Field mismatch\n  Expected: %s\n  Actual:   %s\n",
				s.Hops[i], o.Hops[i])
		}
	}
	return nil
}
