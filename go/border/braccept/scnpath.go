package main

import (
	"fmt"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/spath"
)

//
// ScnPath
//
type ScnPath struct {
	spath.Path
	Segs Segments
}

// gPath converts info and hop field indexes to their proper offsets
func gPath(infoF, hopF int, segs []*SegDef) *ScnPath {
	p := &ScnPath{}
	for i := 0; i < infoF-1; i++ {
		// Each segments consists of one InfoField and N HopFields
		p.InfOff += spath.InfoFieldLength + int(segs[i].inf.Hops*spath.HopFieldLength)
	}
	p.HopOff = p.InfOff + (hopF * spath.HopFieldLength)
	p.Segs = segs
	return p
}

func (p *ScnPath) Parse(b []byte) error {
	if len(b) == 0 || len(b)%common.LineLen != 0 {
		return fmt.Errorf("Bad path length, actual=%d", len(b))
	}
	//p.Raw = b
	offset := 0
	for offset < len(b) {
		seg := &SegDef{}
		len, err := seg.Parse(b[offset:])
		if err != nil {
			return err
		}
		p.Segs = append(p.Segs, seg)
		offset += len
	}
	return nil
}

func (p *ScnPath) String() string {
	if p == nil {
		return ""
	}
	if len(p.Segs) > 0 {
		return p.Segs.String()
	}

	return fmt.Sprintf("%x", p.Raw)
}

//
// Segments
//
type Segments []*SegDef

func (segs Segments) Len() int {
	len := 0
	for i, _ := range segs {
		len += segs[i].segLen()
	}
	return len
}

func (segs Segments) String() string {
	return printSegments(segs, "", " ")
}

func printSegments(segs Segments, indent, sep string) string {
	var str []string
	for _, s := range segs {
		str = append(str, fmt.Sprintf("%s%s", indent, s))
	}
	return strings.Join(str, sep)
}

//
// SegDef
//
type SegDef struct {
	inf  spath.InfoField
	hops []spath.HopField
}

func (s *SegDef) Parse(b []byte) (int, error) {
	inf, err := spath.InfoFFromRaw(b)
	if err != nil {
		return 0, err
	}
	s.inf = *inf
	segLen := int(spath.InfoFieldLength + inf.Hops*common.LineLen)
	if segLen > len(b) {
		return 0, fmt.Errorf("Buffer is too short, expected=%d, actual=%d", segLen, len(b))
	}
	for offset := spath.InfoFieldLength; offset < segLen; offset += common.LineLen {
		hop, err := spath.HopFFromRaw(b[offset:])
		if err != nil {
			return 0, err
		}
		s.hops = append(s.hops, *hop)
	}
	return segLen, nil
}

func (s *SegDef) String() string {
	var str []string
	var cons, short, peer string
	if s.inf.ConsDir {
		cons = "C"
	}
	if s.inf.Shortcut {
		short = "S"
	}
	if s.inf.Peer {
		peer = "P"
	}
	for i, _ := range s.hops {
		var xover, ver string
		if s.hops[i].Xover {
			xover = "X"
		}
		if s.hops[i].VerifyOnly {
			ver = "V"
		}
		str = append(str, fmt.Sprintf("%1s%1s %04d:%04d", xover, ver,
			s.hops[i].ConsIngress, s.hops[i].ConsEgress))
	}
	return fmt.Sprintf("[%1s%1s%1s] %s", cons, short, peer, strings.Join(str, " <-> "))
}

func (s *SegDef) segLen() int {
	return spath.InfoFieldLength + spath.HopFieldLength*len(s.hops)
}
