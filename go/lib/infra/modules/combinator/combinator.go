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
// followed by WriteRawFwdPath to obtain the wire format of a path:
//  for path := range Combine(src, dst, ups, cores, downs) {
//    RawFwdPathWriteTo(path, buffer)
//  }
package combinator

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/spath"
)

// Combine constructs paths between src and dst using the supplied
// segments. All possible paths are returned (except paths that completely
// contain a shortcut path), sorted according to weight (on equal weight, see
// pathSolutionList.Less for the tie-breaking algorithm).
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
	Type SegmentType
}

// UpFlag returns 1 if the segment is an UpSegment or CoreSegment.
func (s *InputSegment) UpFlag() int {
	if s.Type == UpSegment || s.Type == CoreSegment {
		return 1
	}
	return 0
}

type SegmentType int

const (
	UpSegment SegmentType = iota
	CoreSegment
	DownSegment
)

// DAMG is a Directed Acyclic Multigraph.
//
// Vertices are either ASes (identified by their ISD-AS number) or peering
// links (identified by the the ISD-AS numbers of the peers, and the IFIDs on
// the peering link).
type DAMG struct {
	Adjacencies map[Vertex]VertexInfo
}

// VertexInfo maps destination vertices to the list of edges that point towards
// them.
type VertexInfo map[Vertex]EdgeList

// NewDAMG creates a new graph from sets of path segments.
//
// Each up segment is traversed backwards. The AS in the last ASEntry
// represents the source AS for all the edges we add. For each ASEntry, a new
// vertex is added for the inIA (i.e., remote upstream AS) in the HopEntry at
// index 0, together with an edge from the source AS to the inIA. The edge is
// annotated with the segment we're currently traversing. If we're not
// currently at the second to last ASEntry in the traversal, the edge is also
// annotated with a Shortcut value equal to the index of the ASEntry.  For all
// subsequent hop entries in the current ASEntry (i.e., the peer entries), we
// add a peering link vertex, together with an edge from the source AS to the
// peering Vertex. The edge is annotated with the segment we're currently
// traversing, a shortcut identifier containing the index of the ASEntry, and a
// peering identifier containing the index of the hop entry.
//
// Each core segment is traversed backwards. The algorithm is similar to up
// segment traversal, except only hop field 0 is taken into account (since
// peerings do not make sense) and shortcuts are ignored.
//
// Each down segment is traversed backwards. The algorithm is the same as up
// segment traversal, except the direction of the edges is reversed. The last
// ASEntry in the segment represents the destination AS, and all other Vertices
// we add will include an edge from them to the destination AS. Shortcuts and
// Peering annotations have the same semantics as in up segment traversal.
func NewDAMG(ups, cores, downs []*seg.PathSegment) *DAMG {
	g := &DAMG{
		Adjacencies: make(map[Vertex]VertexInfo),
	}
	for _, segment := range ups {
		g.traverseSegment(&InputSegment{PathSegment: segment, Type: UpSegment})
	}
	for _, segment := range cores {
		g.traverseSegment(&InputSegment{PathSegment: segment, Type: CoreSegment})
	}
	for _, segment := range downs {
		g.traverseSegment(&InputSegment{PathSegment: segment, Type: DownSegment})
	}
	return g
}

func (g *DAMG) traverseSegment(segment *InputSegment) {
	asEntries := segment.ASEntries

	// Last AS in the PCB is the root for edge addition. For Ups and Cores,
	// edges will originate from srcIA. For Downs, edges will go towards srcIA.
	pinnedIA := asEntries[len(asEntries)-1].IA()

	for asEntryIndex := len(asEntries) - 1; asEntryIndex >= 0; asEntryIndex-- {
		// Whenever we add an edge that is not towards the first AS in the PCB,
		// we are creating a shortcut. We use the asEntryIndex to annotate the
		// edges as such, as we need the metadata during forwarding path
		// construction when adding verify-only HFs and pruning useless pieces
		// of the segment.

		currentIA := asEntries[asEntryIndex].IA()
		// Construct edges for each hop in the current ASEntry.
		for hopEntryIndex, hop := range asEntries[asEntryIndex].HopEntries {
			he, err := hop.HopField()
			if err != nil {
				// should've been caught during MAC verification, abort
				panic(err)
			}

			// build new edge
			var srcVertex, dstVertex Vertex
			srcVertex = VertexFromIA(pinnedIA)
			if hopEntryIndex == 0 {
				if asEntryIndex == len(asEntries)-1 {
					// This is the entry for our local AS; we're not interested in routing here,
					// so we skip this entry.
					continue
				}
				if he.ForwardOnly {
					// We are not allowed to route to this AS
					continue
				}
				dstVertex = VertexFromIA(currentIA)
			} else {
				dstVertex = VertexFromPeering(currentIA, he.Ingress, hop.RawInIA.IA(), hop.RemoteInIF)
			}

			if segment.Type == DownSegment {
				// reverse peering vertices (to have them match those created
				// during up-segment exploration), and reverse edge orientation.
				dstVertex = dstVertex.Reverse()
				srcVertex, dstVertex = dstVertex, srcVertex
			}

			g.AddEdge(srcVertex, dstVertex, segment, &Edge{
				Weight:      len(asEntries) - asEntryIndex, // weight increases going towards ASEntry 0
				Shortcut:    asEntryIndex,
				Peer:        hopEntryIndex,
				ForwardOnly: he.ForwardOnly,
			})
		}
	}
}

func (g *DAMG) AddEdge(src, dst Vertex, segment *InputSegment, edge *Edge) {
	if _, ok := g.Adjacencies[src]; !ok {
		g.Adjacencies[src] = make(map[Vertex]EdgeList)
	}
	if _, ok := g.Adjacencies[dst]; !ok {
		g.Adjacencies[dst] = make(map[Vertex]EdgeList)
	}
	neighborMap := g.Adjacencies[src]
	if _, ok := neighborMap[dst]; !ok {
		g.Adjacencies[src][dst] = make(EdgeList)
	}
	g.Adjacencies[src][dst][segment] = edge
}

// GetPaths returns all the paths from src to dst, sorted according to weight.
func (g *DAMG) GetPaths(src, dst Vertex) PathSolutionList {
	var solutions PathSolutionList

	queue := PathSolutionList{&PathSolution{currentVertex: src}}
	for len(queue) > 0 {
		currentPathSolution := queue[0]
		queue = queue[1:]

		for nextVertex, edgeList := range g.Adjacencies[currentPathSolution.currentVertex] {
			for segment, edge := range edgeList {
				// Create a copy of the old solution s.t. trail slices do not
				// get mixed during appends.
				newSolution := &PathSolution{
					edges:         append([]*solutionEdge{}, currentPathSolution.edges...),
					currentVertex: nextVertex,
					cost:          currentPathSolution.cost + edge.Weight,
				}

				// Append the explored edge to the solution, and add it to the
				// queue of candidate solutions.
				newSolution.edges = append(newSolution.edges,
					&solutionEdge{
						edge:    edge,
						segment: segment,
						src:     currentPathSolution.currentVertex,
						dst:     nextVertex,
					})
				queue = append(queue, newSolution)

				if nextVertex == dst {
					// Do not allow solutions that terminate in an edge marked with ForwardOnly
					if edge.ForwardOnly == false {
						solutions = append(solutions, newSolution)
					}
					// Do not break, because we want all solutions
				}
			}
		}
	}

	sort.Sort(solutions)
	return solutions
}

func (g *DAMG) String() string {
	buffer := new(bytes.Buffer)

	fmt.Fprintf(buffer, "G:\n")
	for src, neighborMap := range g.Adjacencies {
		fmt.Fprintf(buffer, "  %v\n", src)
		for neighbor, edges := range neighborMap {
			fmt.Fprintf(buffer, "    %v\n", neighbor)
			for _, edge := range edges {
				fmt.Fprintf(buffer, "      %v\n", edge)
			}
		}
	}

	return string(buffer.Bytes())
}

// Vertex is a union-like type for the AS vertices and Peering link vertices in
// a DAMG that can be used as key in maps.
type Vertex struct {
	IA       addr.IA
	UpIA     addr.IA
	UpIFID   common.IFIDType
	DownIA   addr.IA
	DownIFID common.IFIDType
}

func VertexFromIA(ia addr.IA) Vertex {
	return Vertex{IA: ia}
}

func VertexFromPeering(upIA addr.IA, upIFID common.IFIDType,
	downIA addr.IA, downIFID common.IFIDType) Vertex {

	return Vertex{UpIA: upIA, UpIFID: upIFID, DownIA: downIA, DownIFID: downIFID}
}

func (v Vertex) String() string {
	if !v.IA.IsZero() {
		return fmt.Sprintf("ia.%v", v.IA)
	}
	return fmt.Sprintf("peering.%v:%v.%v:%v", v.UpIA, v.UpIFID, v.DownIA, v.DownIFID)
}

// Reverse returns a new vertex that contains the peering information in
// reverse. AS vertices remain unchanged.
func (v Vertex) Reverse() Vertex {
	return Vertex{IA: v.IA, UpIA: v.DownIA, UpIFID: v.DownIFID, DownIA: v.UpIA, DownIFID: v.UpIFID}
}

// EdgeList is used to keep the set of edges going from one vertex to another.
// The edges are keyed by path segment pointer.
type EdgeList map[*InputSegment]*Edge

// Edge represents an edge for the DAMG.
type Edge struct {
	Weight int
	// Shortcut is the index on where the forwarding portion of this segment
	// should end (for up-segments) or start (for down-segments). An additional
	// V-only HF upstream of this HF needs to be included for verification.
	// This is also set when crossing peering links. If 0, the full segment is
	// used.
	Shortcut int
	// Peer is the index in the hop entries array for this peer entry. If 0,
	// the standard hop entry at index 0 is used (instead of a peer entry).
	Peer int
	// ForwardOnly is set if the edge contains a segment (or a portion of a
	// segment) that ends with a forward-only hop field. Such an edge cannot be
	// the final edge in a solution.
	ForwardOnly bool
}

type PathSolution struct {
	// edges contains the edges in the solution, one for each segment
	edges []*solutionEdge
	// currentVertex is the currentVertex being visited
	currentVertex Vertex
	// cost is the sum of edge weights
	cost int
}

// GetFwdPathMetadata builds the complete metadata for a forwarding path by
// extracting it from a path between source and destination in the DAMG.
func (solution *PathSolution) GetFwdPathMetadata() *Path {
	var path = &Path{}
	solutionEdges := solution.edges
	for edgeIdx, solEdge := range solutionEdges {
		// VERY DANGEROUS, FIX REFERENCE MUTATION
		currentSegment := &Segment{Type: solEdge.segment.Type}
		currentSegment.SetIF(solEdge.segment.PathSegment)
		currentSegment.InfoField.Up = (solEdge.segment.UpFlag() == 1)
		path.Segments = append(path.Segments, currentSegment)

		// Go through each ASEntry, starting from the last one, until we
		// find a shortcut (which can be 0, meaning the end of the segment).
		asEntries := solEdge.segment.ASEntries
		for asEntryIdx := len(asEntries) - 1; asEntryIdx >= solEdge.edge.Shortcut; asEntryIdx-- {
			asEntry := asEntries[asEntryIdx]

			// Normal hop field.
			newHF := currentSegment.AppendHF(asEntry.HopEntries[0])
			if asEntryIdx == solEdge.edge.Shortcut {
				// We've reached the ASEntry where we want to switch
				// segments; this can happen either when we reach the end
				// of the segment (so Shortcut = 0, Peer = 0), we reach a
				// Shortcut annotation (so we don't need to go to the end
				// of the segment anymore, Peer = 0), or when we need to
				// traverse a peering link.

				// If this is not the last segment in the path, set Xover flag.
				if edgeIdx != len(solutionEdges)-1 {
					newHF.Xover = true
				}

				if solEdge.edge.Shortcut != 0 && solEdge.edge.Peer != 0 {
					newHF.Xover = true
					currentSegment.InfoField.Peer = true
					newHF := currentSegment.AppendHF(asEntry.HopEntries[solEdge.edge.Peer])
					newHF.Xover = true
				}

				if solEdge.edge.Shortcut != 0 {
					// Normal or peering shortcut. Include the verify-only hop field.
					currentSegment.InfoField.Shortcut = true
					newHF := currentSegment.AppendHF(asEntries[asEntryIdx-1].HopEntries[0])
					newHF.VerifyOnly = true
				}
			}
		}
	}
	path.ReverseDownSegment()
	return path
}

// PathSolutionList is a sort.Interface implementation for a slice of solutions.
type PathSolutionList []*PathSolution

func (sl PathSolutionList) Len() int {
	return len(sl)
}

// Less sorts according to the following priority list:
//  - total path cost
//  - number of segments
//  - for the up segment, then core segment, then down segment:
//    - length of segment
//    - IA numbers of ASEntries
//    - for each ASEntry, the ingress IFID of the used hop entry
func (sl PathSolutionList) Less(i, j int) bool {
	if sl[i].cost != sl[j].cost {
		return sl[i].cost < sl[j].cost
	}

	trailI, trailJ := sl[i].edges, sl[j].edges
	if len(trailI) != len(trailJ) {
		return len(trailI) < len(trailJ)
	}

	for k := range trailI {
		entriesI, entriesJ := trailI[k].segment.ASEntries, trailJ[k].segment.ASEntries
		if len(entriesI) != len(entriesJ) {
			return len(entriesI) < len(entriesJ)
		}

		iaI, iaJ := entriesI[k].IA(), entriesJ[k].IA()
		if !iaI.Eq(iaJ) {
			return iaI.IAInt() < iaJ.IAInt()
		}

		edgeI, edgeJ := trailI[k].edge, trailJ[k].edge
		for k := range entriesI {
			idxI, idxJ := 0, 0
			if k == edgeI.Shortcut {
				idxI = edgeI.Peer
			}
			if k == edgeJ.Shortcut {
				idxJ = edgeJ.Peer
			}

			heI, heJ := entriesI[k].HopEntries[idxI], entriesJ[k].HopEntries[idxJ]
			hfI, err := heI.HopField()
			if err != nil {
				panic(err)
			}
			hfJ, err := heJ.HopField()
			if err != nil {
				panic(err)
			}

			if hfI.Ingress != hfJ.Ingress {
				return hfI.Ingress < hfJ.Ingress
			}
		}
	}
	return false
}

func (sl PathSolutionList) Swap(i, j int) {
	sl[i], sl[j] = sl[j], sl[i]
}

// solutionEdge contains a graph edge and additional metadata required during
// graph exploration.
type solutionEdge struct {
	edge *Edge
	src  Vertex
	dst  Vertex
	// The segment associated with this edge, used during forwarding path construction
	segment *InputSegment
}

type Path struct {
	Segments []*Segment
}

func (p *Path) String() string {
	var strs []string
	for _, segment := range p.Segments {
		strs = append(strs, segment.InfoField.String())
		for _, hopField := range segment.HopFields {
			strs = append(strs, hopField.String())
		}
	}
	return "[" + strings.Join(strs, " ") + "]"
}

func (p *Path) WriteTo(w io.Writer) (n int64, err error) {
	for _, segment := range p.Segments {
		m, e := segment.InfoField.WriteTo(w)
		n += m
		if err != nil {
			return n, e
		}

		for _, hopField := range segment.HopFields {
			m, e := hopField.WriteTo(w)
			n += m
			if e != nil {
				return n, e
			}
		}
	}
	return n, nil
}

func (p *Path) ReverseDownSegment() {
	for _, segment := range p.Segments {
		if segment.Type == DownSegment {
			segment.Reverse()
		}
	}
}

type Segment struct {
	InfoField *InfoField
	HopFields []*HopField
	Type      SegmentType
}

func (segment *Segment) SetIF(pathSegment *seg.PathSegment) {
	infoField, err := pathSegment.InfoF()
	if err != nil {
		panic(err)
	}
	segment.InfoField = &InfoField{
		InfoField: infoField,
	}
}

func (segment *Segment) AppendHF(entry *seg.HopEntry) *HopField {
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

func (segment *Segment) Reverse() {
	for i, j := 0, len(segment.HopFields)-1; i < j; i, j = i+1, j-1 {
		segment.HopFields[i], segment.HopFields[j] = segment.HopFields[j], segment.HopFields[i]
	}
}

type InfoField struct {
	*spath.InfoField
}

func (field *InfoField) String() string {
	return fmt.Sprintf("(IF %s%s%s ISD=%d)",
		flagPrint("P", boolToInt(field.Peer)),
		flagPrint("S", boolToInt(field.Shortcut)),
		flagPrint("U", boolToInt(field.Up)),
		field.ISD)
}

func (field *InfoField) PathField() *pathField {
	return &pathField{
		Type:     IF,
		Up:       boolToInt(field.Up),
		Peer:     boolToInt(field.Peer),
		Shortcut: boolToInt(field.Shortcut),
		ISD:      addr.ISD(field.ISD),
		Hops:     field.Hops,
	}
}

type HopField struct {
	*spath.HopField
}

func (field *HopField) String() string {
	return fmt.Sprintf("(HF %s%s InIF=%d OutIF=%d)",
		flagPrint("V", boolToInt(field.VerifyOnly)),
		flagPrint("X", boolToInt(field.Xover)),
		field.Ingress,
		field.Egress)
}

func (field *HopField) PathField() *pathField {
	return &pathField{
		Type:  HF,
		Xover: boolToInt(field.Xover),
		Vonly: boolToInt(field.VerifyOnly),
		InIF:  field.Ingress,
		OutIF: field.Egress,
	}
}

func flagPrint(name string, value int) string {
	if value == 0 {
		return "."
	}
	return name
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// pathField contains metadata about info fields or hop fields. It is used to
// simplify testing.
type pathField struct {
	Type fieldType

	// IF specific
	Up       int
	Peer     int
	Shortcut int
	ISD      addr.ISD
	Hops     uint8

	// HF specific
	Xover int
	Vonly int
	InIF  common.IFIDType
	OutIF common.IFIDType
	RawHF []byte
}

func (pf pathField) String() string {
	switch pf.Type {
	case IF:
		return fmt.Sprintf("(IF %s%s%s ISD=%d)",
			flagPrint("P", pf.Peer), flagPrint("S", pf.Shortcut), flagPrint("U", pf.Up), pf.ISD)
	case HF:
		return fmt.Sprintf("(HF %s%s InIF=%d OutIF=%d)",
			flagPrint("V", pf.Vonly), flagPrint("X", pf.Xover), pf.InIF, pf.OutIF)
	default:
		panic("unknown PathField type")
	}
}

type fieldType int

const (
	IF fieldType = iota
	HF
)
