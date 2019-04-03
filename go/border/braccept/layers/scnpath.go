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

package layers

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
)

type ScnPath struct {
	Segs Segments
	raw  common.RawBytes
}

func (p ScnPath) Parse(b common.RawBytes) error {
	p.raw = b
	_, err := p.Segs.Parse(b)
	return err
}

func (p ScnPath) WriteTo(b common.RawBytes) error {
	p.raw = b[:p.Len()]
	_, err := p.Segs.WriteTo(b)
	return err
}

func (p ScnPath) Len() int {
	return p.Segs.Len()
}

func (p *ScnPath) String() string {
	return p.Segs.String()
}

type Segments []*Segment

func (segs Segments) Len() int {
	l := 0
	for i := range segs {
		l += segs[i].Len()
	}
	return l
}

func (segs Segments) Parse(b common.RawBytes) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	offset := 0
	for offset < len(b) {
		seg := &Segment{}
		l, err := seg.Parse(b[offset:])
		if err != nil {
			return 0, err
		}
		segs = append(segs, seg)
		offset += l
	}
	return offset, nil
}

func (segs Segments) WriteTo(b common.RawBytes) (int, error) {
	if segs == nil || len(segs) == 0 {
		return 0, nil
	}
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

func PrintSegments(segs Segments, indent, sep string) string {
	var str []string
	for _, s := range segs {
		str = append(str, fmt.Sprintf("%s%s", indent, s))
	}
	return strings.Join(str, sep)
}

// Segment defines a path segment
type Segment struct {
	Inf  *spath.InfoField
	Hops []*spath.HopField
}

func (s *Segment) Parse(b common.RawBytes) (int, error) {
	minSegLen := spath.InfoFieldLength + 2*spath.HopFieldLength
	if minSegLen > len(b) {
		return 0, fmt.Errorf("Buffer is too short, minimum=%d, actual=%d", minSegLen, len(b))
	}
	inf, err := spath.InfoFFromRaw(b)
	if err != nil {
		return 0, err
	}
	s.Inf = inf
	// XXX we have to rely on info field number of hops to determined length of segment
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

func (s *Segment) WriteTo(b common.RawBytes) (int, error) {
	if s.Len() > len(b) {
		return 0, fmt.Errorf("Buffer is too short, expected=%d, actual=%d", s.Len(), len(b))
	}
	// Write Info Field
	s.Inf.Write(b)
	offset := spath.InfoFieldLength
	// Write Hop Fields
	for i := range s.Hops {
		hop := s.Hops[i]
		hop.Write(b[offset:])
		offset += spath.HopFieldLength
	}
	return offset, nil
}

func (s *Segment) String() string {
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

func (s *Segment) Len() int {
	return spath.InfoFieldLength + spath.HopFieldLength*len(s.Hops)
}
