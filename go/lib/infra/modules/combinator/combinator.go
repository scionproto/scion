// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package combinator contains methods for constructing SCION forwarding paths.
//
// Call Combine to grab all the metadata associated with the constructed paths,
// followed by WriteTo to obtain the wire format of a path:
//  for path := range Combine(src, dst, ups, cores, downs) {
//    path.WriteTo(w)
//  }
//
// Returned paths are sorted by weight in descending order. The weight is
// defined as the number of transited AS hops in the path.
package combinator

import (
	"fmt"
	"io"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

// CombineV2 constructs paths between src and dst using the supplied
// segments. All possible paths are first computed, and then filtered according
// to FilterLongPaths. The remaining paths are returned sorted according to
// weight (on equal weight, see pathSolutionList.Less for the tie-breaking
// algorithm).
//
// If Combine cannot extract a hop field or info field from the segments, it
// panics.
//
// This method is specifically for header v2.
func CombineV2(src, dst addr.IA, ups, cores, downs []*seg.PathSegment) []*Path {
	paths := NewDMG(ups, cores, downs).GetPaths(VertexFromIA(src), VertexFromIA(dst))

	var pathSlice []*Path
	for _, path := range paths {
		pathSlice = append(pathSlice, path.getFwdPathMetadata())
	}
	return FilterLongPaths(pathSlice)
}

// InputSegment is a local representation of a path segment that includes the
// segment's type.
type InputSegment struct {
	*seg.PathSegment
	Type proto.PathSegType
}

// IsDownSeg returns true if the segment is a DownSegment.
func (s *InputSegment) IsDownSeg() bool {
	return s.Type == proto.PathSegType_down
}

type Path struct {
	Segments   []*Segment
	Weight     int
	Mtu        uint16
	Interfaces []snet.PathInterface
	StaticInfo *PathMetadata
}

func (p *Path) writeTestString(w io.Writer) {
	fmt.Fprintf(w, "  Weight: %d\n", p.Weight)
	fmt.Fprintln(w, "  Fields:")
	for _, segment := range p.Segments {
		fmt.Fprintf(w, "    %v\n", segment.InfoField)
		for _, hopField := range segment.HopFields {
			fmt.Fprintf(w, "      %v\n", hopField)
		}
	}
	fmt.Fprintln(w, "  Interfaces:")
	for _, pi := range p.Interfaces {
		fmt.Fprintf(w, "    %v\n", pi)
	}
}

func (p *Path) reverseDownSegment() {
	segment := p.Segments[len(p.Segments)-1]
	if segment.Type == proto.PathSegType_down {
		segment.reverse()
	}
}

func (p *Path) aggregateInterfaces() {
	p.Interfaces = []snet.PathInterface{}
	for _, segment := range p.Segments {
		p.Interfaces = append(p.Interfaces, segment.Interfaces...)
	}
}

func (p *Path) ComputeExpTime() time.Time {
	minTimestamp := spath.MaxExpirationTime
	for _, segment := range p.Segments {
		expTime := segment.ComputeExpTime()
		if minTimestamp.After(expTime) {
			minTimestamp = expTime
		}
	}
	return minTimestamp
}

func (p *Path) WriteTo(w io.Writer) (int64, error) {
	var meta scion.MetaHdr
	var infos []*path.InfoField
	var hops []*path.HopField

	for i, segment := range p.Segments {
		meta.SegLen[i] = uint8(len(segment.HopFields))
		infos = append(infos, &path.InfoField{
			ConsDir:   segment.InfoField.ConsDir,
			Peer:      segment.InfoField.Peer,
			SegID:     segment.InfoField.SegID,
			Timestamp: util.TimeToSecs(segment.InfoField.Timestamp),
		})
		for _, hop := range segment.HopFields {
			hops = append(hops, &path.HopField{
				ExpTime:     hop.ExpTime,
				ConsIngress: hop.ConsIngress,
				ConsEgress:  hop.ConsEgress,
				Mac:         hop.MAC,
			})
		}
	}
	sp := scion.Decoded{
		Base: scion.Base{
			PathMeta: meta,
			NumHops:  len(hops),
			NumINF:   len(p.Segments),
		},
		InfoFields: infos,
		HopFields:  hops,
	}
	raw := make([]byte, sp.Len())
	if err := sp.SerializeTo(raw); err != nil {
		return 0, err
	}
	n, err := w.Write(raw)
	if err != nil {
		return int64(n), err
	}
	if n != len(raw) {
		return int64(n), serrors.New("incomplete path written", "expected", len(raw), "actual", n)
	}
	return int64(n), nil
}

type Segment struct {
	InfoField  *InfoField
	HopFields  []*HopField
	Type       proto.PathSegType
	Interfaces []snet.PathInterface
}

func (segment *Segment) reverse() {
	for i, j := 0, len(segment.HopFields)-1; i < j; i, j = i+1, j-1 {
		segment.HopFields[i], segment.HopFields[j] = segment.HopFields[j], segment.HopFields[i]
	}
	for i, j := 0, len(segment.Interfaces)-1; i < j; i, j = i+1, j-1 {
		segment.Interfaces[i], segment.Interfaces[j] = segment.Interfaces[j], segment.Interfaces[i]
	}
}

func (segment *Segment) ComputeExpTime() time.Time {
	return segment.InfoField.Timestamp.Add(segment.computeHopFieldsTTL())
}

func (segment *Segment) computeHopFieldsTTL() time.Duration {
	minTTL := time.Duration(spath.MaxTTL) * time.Second
	for _, hf := range segment.HopFields {
		offset := spath.ExpTimeType(hf.ExpTime).ToDuration()
		if minTTL > offset {
			minTTL = offset
		}
	}
	return minTTL
}

type InfoField struct {
	SegID     uint16
	Timestamp time.Time
	Peer      bool
	ConsDir   bool
}

func (field *InfoField) String() string {
	return fmt.Sprintf("IF %s%s",
		flagPrint("C", field.ConsDir),
		flagPrint("P", field.Peer))
}

type HopField struct {
	ExpTime     uint8
	ConsIngress uint16
	ConsEgress  uint16
	MAC         []byte
}

func (field *HopField) String() string {
	return fmt.Sprintf("HF InIF=%d OutIF=%d",
		field.ConsIngress,
		field.ConsEgress)
}

func flagPrint(name string, b bool) string {
	if b == false {
		return "."
	}
	return name
}

// FilterLongPaths returns a new slice containing only those paths that do not
// go more than twice through interfaces belonging to the same AS (thus
// filtering paths containing useless loops).
func FilterLongPaths(paths []*Path) []*Path {
	var newPaths []*Path
	for _, path := range paths {
		long := false
		iaCounts := make(map[addr.IA]int)
		for _, iface := range path.Interfaces {
			iaCounts[iface.IA]++
			if iaCounts[iface.IA] > 2 {
				long = true
				break
			}
		}
		if !long {
			newPaths = append(newPaths, path)
		}
	}
	return newPaths
}
