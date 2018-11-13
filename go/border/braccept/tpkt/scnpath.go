package tpkt

import (
	"bytes"
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
	Mac  hash.Hash
}

// GenPath converts info and hop field indexes to their proper offsets
func GenPath(infoF, hopF int, segs Segments, hashMac hash.Hash) *ScnPath {
	p := &ScnPath{}
	for i := 0; i < infoF-1; i++ {
		// Each segments consists of one InfoField and N HopFields
		p.InfOff += spath.InfoFieldLength + int(segs[i].Inf.Hops*spath.HopFieldLength)
	}
	p.HopOff = p.InfOff + (hopF * spath.HopFieldLength)
	// Write SCION path
	p.Raw = make(common.RawBytes, segs.Len())
	p.Mac = hashMac
	if _, err := segs.WriteTo(p.Raw, p.Mac); err != nil {
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
		len, err := seg.Parse(b[offset:])
		if err != nil {
			return err
		}
		p.Segs = append(p.Segs, seg)
		offset += len
	}
	return nil
}

func (p *ScnPath) WriteRaw() (int, error) {
	if p.Mac == nil {
		return 0, fmt.Errorf("Mac is required to write raw path\n")
	}
	return p.Segs.WriteTo(p.Raw, p.Mac)
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

func (p *ScnPath) Check(o *ScnPath) error {
	o.Parse(o.Raw)
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

type Segments []*SegDef

func (segs Segments) Len() int {
	len := 0
	for i := range segs {
		len += segs[i].segLen()
	}
	return len
}

func (segs Segments) WriteTo(b []byte, mac hash.Hash) (int, error) {
	offset := 0
	for i := range segs {
		n, err := segs[i].WriteTo(b[offset:], mac)
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

// SegDef defines a path segment
type SegDef struct {
	Inf  spath.InfoField
	Hops []spath.HopField
}

func (s *SegDef) Parse(b []byte) (int, error) {
	Inf, err := spath.InfoFFromRaw(b)
	if err != nil {
		return 0, err
	}
	s.Inf = *Inf
	segLen := int(spath.InfoFieldLength + Inf.Hops*common.LineLen)
	if segLen > len(b) {
		return 0, fmt.Errorf("Buffer is too short, expected=%d, actual=%d", segLen, len(b))
	}
	for offset := spath.InfoFieldLength; offset < segLen; offset += common.LineLen {
		hop, err := spath.HopFFromRaw(b[offset:])
		if err != nil {
			return 0, err
		}
		s.Hops = append(s.Hops, *hop)
	}
	return segLen, nil
}

func (seg *SegDef) WriteTo(b []byte, mac hash.Hash) (int, error) {
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
		if hop.Mac == nil {
			mac.Reset()
			hop.Mac, err = hop.CalcMac(mac, seg.Inf.TsInt, prevHop)
			if err != nil {
				return 0, err
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
		str = append(str, fmt.Sprintf("%1s%1s %04d:%04d", xover, ver,
			s.Hops[i].ConsIngress, s.Hops[i].ConsEgress))
	}
	return fmt.Sprintf("[%1s%1s%1s] %s", cons, short, peer, strings.Join(str, " <-> "))
}

func (s *SegDef) segLen() int {
	return spath.InfoFieldLength + spath.HopFieldLength*len(s.Hops)
}

func (s *SegDef) Equal(o *SegDef) error {
	if s.Inf != o.Inf {
		return fmt.Errorf("Info Field mismatch\n  Expected: %s\n  Actual:   %s\n", &s.Inf, &o.Inf)
	}
	if len(s.Hops) != len(o.Hops) {
		return fmt.Errorf("Different number of Hop Fields\n  Expected: %s\n  Actual:   %s\n", s, o)
	}
	for i := range s.Hops {
		if !compareHopF(s.Hops[i], o.Hops[i]) {
			return fmt.Errorf("Hop Field mismatch\n  Expected: %s\n  Actual:   %s\n",
				&s.Hops[i], &o.Hops[i])
		}
	}
	return nil
}

func compareHopF(a, o spath.HopField) bool {
	return a.Xover == o.Xover && a.VerifyOnly == o.VerifyOnly && a.ExpTime == o.ExpTime &&
		a.ConsIngress == o.ConsIngress && a.ConsEgress == o.ConsEgress && bytes.Equal(a.Mac, o.Mac)
}
