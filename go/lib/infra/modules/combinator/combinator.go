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
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/proto"
)

// Combine constructs paths between src and dst using the supplied
// segments. All possible paths are returned, sorted according to weight (on
// equal weight, see pathSolutionList.Less for the tie-breaking algorithm).
//
// If Combine cannot extract a hop field or info field from the segments, it
// panics.
func Combine(src, dst addr.IA, ups, cores, downs []*seg.PathSegment) []*Path {
	paths := NewDAMG(ups, cores, downs).GetPaths(VertexFromIA(src), VertexFromIA(dst))

	var pathSlice []*Path
	for _, path := range paths {
		pathSlice = append(pathSlice, path.GetFwdPathMetadata())
	}
	return pathSlice
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
	Interfaces []sciond.PathInterface
	ExpTime    time.Time
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
	p.Interfaces = []sciond.PathInterface{}
	for _, segment := range p.Segments {
		p.Interfaces = append(p.Interfaces, segment.Interfaces...)
	}
}

func (p *Path) computeExpTime() {
	p.ExpTime = time.Unix(1<<63-1, 0)
	for _, segment := range p.Segments {
		t := segment.InfoField.Timestamp().Add(time.Duration(segment.ExpTime) * time.Second)
		if t.Before(p.ExpTime) {
			p.ExpTime = t
		}
	}
}

func (p *Path) WriteTo(w io.Writer) (int64, error) {
	var total int64
	for _, segment := range p.Segments {
		n, err := segment.InfoField.WriteTo(w)
		total += n
		if err != nil {
			return total, err
		}
		for _, hopField := range segment.HopFields {
			n, err := hopField.WriteTo(w)
			total += n
			if err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

type Segment struct {
	InfoField  *InfoField
	HopFields  []*HopField
	Type       proto.PathSegType
	Interfaces []sciond.PathInterface
	ExpTime    uint32
}

// initInfoFieldFrom copies the info field in pathSegment, and sets it as the
// info field of segment.
func (segment *Segment) initInfoFieldFrom(pathSegment *seg.PathSegment) {
	infoField, err := pathSegment.InfoF()
	if err != nil {
		panic(err)
	}
	segment.InfoField = &InfoField{
		InfoField: infoField,
	}
}

// appendHopFieldFrom copies the Hop Field in entry, and appends it to segment.
func (segment *Segment) appendHopFieldFrom(entry *seg.HopEntry) *HopField {
	inputHopField, err := entry.HopField()
	if err != nil {
		panic(err)
	}
	hopField := &HopField{
		HopField: inputHopField,
	}
	segment.HopFields = append(segment.HopFields, hopField)
	if segment.InfoField.Hops == 0xff {
		panic("too many hops")
	}
	segment.InfoField.Hops += 1
	return hopField
}

func (segment *Segment) reverse() {
	for i, j := 0, len(segment.HopFields)-1; i < j; i, j = i+1, j-1 {
		segment.HopFields[i], segment.HopFields[j] = segment.HopFields[j], segment.HopFields[i]
	}
	for i, j := 0, len(segment.Interfaces)-1; i < j; i, j = i+1, j-1 {
		segment.Interfaces[i], segment.Interfaces[j] = segment.Interfaces[j], segment.Interfaces[i]
	}
}

type InfoField struct {
	*spath.InfoField
}

func (field *InfoField) String() string {
	return fmt.Sprintf("IF %s%s%s ISD=%d",
		flagPrint("C", field.ConsDir),
		flagPrint("S", field.Shortcut),
		flagPrint("P", field.Peer),
		field.ISD)
}

type HopField struct {
	*spath.HopField
}

func (field *HopField) String() string {
	return fmt.Sprintf("HF %s%s InIF=%d OutIF=%d",
		flagPrint("X", field.Xover),
		flagPrint("V", field.VerifyOnly),
		field.ConsIngress,
		field.ConsEgress)
}

func flagPrint(name string, b bool) string {
	if b == false {
		return "."
	}
	return name
}
