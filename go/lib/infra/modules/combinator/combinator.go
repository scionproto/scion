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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/spath"
)

// Combine constructs paths between src and dst using the supplied
// segments. All possible paths are returned (except paths that completely
// contain a shortcut path), sorted according to weight (on equal weight, see
// pathSolutionList.Less for the tie-breaking algorithm).
func Combine(src, dst addr.IA, ups, cores, downs []*seg.PathSegment) [][]*PathField {
	paths := NewDAMG(ups, cores, downs).GetPaths(VertexFromIA(src), VertexFromIA(dst))

	var fieldsSlice [][]*PathField
	for _, path := range paths {
		fieldsSlice = append(fieldsSlice, path.GetFwdPathMetadata())
	}
	return fieldsSlice
}

// RawFwdPathWriteTo dumps the contents of fields to w. It returns the number
// of bytes written, and an error (if one occurred).
func RawFwdPathWriteTo(fields []*PathField, w io.Writer) (int, error) {
	var total int
	for _, field := range fields {
		n, err := field.WriteTo(w)
		total += int(n)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Segment is a local representation of a path segment that includes the
// segment's type.
type Segment struct {
	ASEntries []*seg.ASEntry
	Type      SegmentType
}

// UpFlag returns 1 if the segment is an UpSegment or CoreSegment.
func (s *Segment) UpFlag() int {
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
		g.traverseSegment(&Segment{ASEntries: segment.ASEntries, Type: UpSegment})
	}
	for _, segment := range cores {
		g.traverseSegment(&Segment{ASEntries: segment.ASEntries, Type: CoreSegment})
	}
	for _, segment := range downs {
		g.traverseSegment(&Segment{ASEntries: segment.ASEntries, Type: DownSegment})
	}
	return g
}

func (g *DAMG) traverseSegment(segment *Segment) {
	asEntries := segment.ASEntries

	// Last AS in the PCB is the root for edge addition. For Ups and Cores,
	// edges will originate from srcIA. For Downs, edges will go towards srcIA.
	pinnedIA := asEntries[len(asEntries)-1].IA()

	// Ignore entry at index 0 (so ASEntry of beacon origin) as all the
	// information is included in the RawInIA field of the next one.
	for asEntryIndex := len(asEntries) - 1; asEntryIndex > 0; asEntryIndex-- {
		// Whenever we add an edge that is not towards the first AS in the PCB,
		// we are creating a shortcut. We use the shortcut below to annotate
		// the edges as such, as we need the metadata during forwarding path
		// construction when adding verify-only HFs and pruning useless pieces
		// of the segment.

		// decrement by 1 because we're adding the vertex for ASEntry k when
		// traversing ASEntry index k+1
		shortcut := asEntryIndex - 1

		currentIA := asEntries[asEntryIndex].IA()
		// Construct edges for each hop in the current ASEntry.
		for hopEntryIndex, hop := range asEntries[asEntryIndex].HopEntries {
			if hopEntryIndex != 0 {
				// This is a peering entry. For peering links, we're adding
				// peering vertices containing ASEntry k (and the AS across the
				// peering link) when traversing ASEntry k itself, so no longer
				// decrement by one.
				shortcut = asEntryIndex
			}
			nextIA := hop.RawInIA.IA()

			// build new edge
			var srcVertex, dstVertex Vertex
			srcVertex = VertexFromIA(pinnedIA)
			if hopEntryIndex == 0 {
				dstVertex = VertexFromIA(nextIA)
			} else {
				he, err := hop.HopField()
				if err != nil {
					// should've been caught during MAC verification, abort
					panic(err)
				}
				dstVertex = VertexFromPeering(currentIA, he.Ingress, nextIA, hop.RemoteInIF)
			}

			if segment.Type == DownSegment {
				// reverse peering vertices (to have them match those created
				// during up-segment exploration), and reverse edge orientation.
				dstVertex = dstVertex.Reverse()
				srcVertex, dstVertex = dstVertex, srcVertex
			}

			g.AddEdge(srcVertex, dstVertex, segment, &Edge{
				Weight:   len(asEntries) - asEntryIndex, // weight increases going towards ASEntry 0
				Shortcut: shortcut,
				Peer:     hopEntryIndex,
			})
		}
	}
}

func (g *DAMG) AddEdge(src, dst Vertex, segment *Segment, edge *Edge) {
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
					super, sub := solutions.findPathIncludes(newSolution)
					solutions = solutions.RemoveAll(super)
					if len(sub) == 0 {
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
	IA addr.IA

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
type EdgeList map[*Segment]*Edge

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
func (solution *PathSolution) GetFwdPathMetadata() []*PathField {
	var fields []*PathField

	solutionEdges := solution.edges
	for edgeIdx, solEdge := range solutionEdges {
		currentIF := &PathField{
			Type: IF,
			Up:   solEdge.segment.UpFlag(),
			ISD:  solEdge.segment.ASEntries[0].IA().I,
		}
		fields = append(fields, currentIF)

		switch solEdge.segment.Type {
		case UpSegment, CoreSegment:
			// Go through each ASEntry, starting from the last one, until we
			// find a shortcut or we reach the beginning of the segment
			for asEntryIdx := len(solEdge.segment.ASEntries) - 1; asEntryIdx >= 0; asEntryIdx-- {
				asEntry := solEdge.segment.ASEntries[asEntryIdx]

				if asEntryIdx == solEdge.edge.Shortcut {
					// We've reached the ASEntry where we want to switch
					// segments; this can happen either when we reach the end
					// of the segment (so Shortcut = 0, Peer = 0), we reach a
					// Shortcut annotation (so we don't need to go to the end
					// of the segment anymore, Peer = 0), or when we need to
					// traverse a peering link.
					asEntryHF := NewHFPathField(asEntry.HopEntries[solEdge.edge.Peer])
					if edgeIdx != len(solutionEdges)-1 {
						// Only enable Xover flag if this is not the last segment.
						asEntryHF.Xover = 1
					}
					fields = append(fields, asEntryHF)
					currentIF.Hops++

					if solEdge.edge.Shortcut != 0 && solEdge.segment.Type == UpSegment {
						// This was an actual Shortcut. If Peer is non-zero, it
						// means we are crossing a peering link, so set the
						// Peer flag in the current InfoField. Otherwise, it's
						// an intra-ISD shortcut, so set the Shortcut flag
						// instead.
						if solEdge.edge.Peer != 0 {
							currentIF.Peer = 1
						} else {
							if edgeIdx != len(solutionEdges)-1 {
								// NOTE(scrye): for some reason, as defined in
								// the book, single-segment shortcuts do not
								// have the shortcut flag set.
								currentIF.Shortcut = 1
							}
						}

						// For actual shortcuts, include a verify-only HF
						// afterwards.
						asEntryHF := NewHFPathField(
							solEdge.segment.ASEntries[asEntryIdx-1].HopEntries[0])
						asEntryHF.Vonly = 1
						fields = append(fields, asEntryHF)
						currentIF.Hops++
						break
					}
				} else {
					// Normal hop field.
					asEntryHF := NewHFPathField(asEntry.HopEntries[0])
					fields = append(fields, asEntryHF)
				}
			}
		case DownSegment:
			// If this is a shortcut, we need to start from the verify-only HF
			if solEdge.edge.Shortcut != 0 {
				asEntryHF := NewHFPathField(
					solEdge.segment.ASEntries[solEdge.edge.Shortcut-1].HopEntries[0])
				asEntryHF.Vonly = 1
				fields = append(fields, asEntryHF)
				currentIF.Hops++
			}

			for index := solEdge.edge.Shortcut; index < len(solEdge.segment.ASEntries); index++ {
				entry := solEdge.segment.ASEntries[index]
				// If we're crossing a peering link, we need to start off by
				// selecting the one matching  the peering link in the up
				// segment
				if index == solEdge.edge.Shortcut && solEdge.edge.Peer != 0 {
					currentIF.Peer = 1
					asEntryHF := NewHFPathField(entry.HopEntries[solEdge.edge.Peer])
					asEntryHF.Xover = 1
					fields = append(fields, asEntryHF)
					currentIF.Hops++
				} else {
					asEntryHF := NewHFPathField(entry.HopEntries[0])
					fields = append(fields, asEntryHF)
					currentIF.Hops++
				}
			}
		}
	}
	return fields
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

func (sl PathSolutionList) RemoveAll(positions []int) PathSolutionList {
	if len(sl) < len(positions) {
		fmt.Printf("GARBAGE %d, %d, %v\n", len(sl), len(positions), positions)
		return sl
	}
	newSL := make(PathSolutionList, len(sl)-len(positions))
	for srcIndex, dstIndex, skipIndex := 0, 0, 0; srcIndex < len(sl); srcIndex++ {
		if skipIndex < len(positions) && srcIndex == positions[skipIndex] {
			// Skip this entry
			skipIndex++
		} else {
			// Copy entry and increase indices
			newSL[dstIndex] = sl[srcIndex]
			dstIndex++
		}
	}
	return newSL
}

// findPathIncludes reports information about which solutions contain path
// segments that are completely included (as defined by method
// solutionEdge.Include) in the path segments in newSolution. The indices of
// the respective existing solutions are returned in slice sub.
//
// Slice super contains the reverse relationship.
func (solutions PathSolutionList) findPathIncludes(newSolution *PathSolution) (super, sub []int) {
	for _, newEdge := range newSolution.edges {
		for solutionIndex, existingSolution := range solutions {
			for _, edge := range existingSolution.edges {
				if newEdge.Includes(edge) {
					sub = insertSorted(sub, solutionIndex)
				}
				if edge.Includes(newEdge) {
					super = insertSorted(super, solutionIndex)
				}
			}
		}
	}
	return super, sub
}

// solutionEdge contains a graph edge and additional metadata required during
// graph exploration.
type solutionEdge struct {
	edge *Edge
	src  Vertex
	dst  Vertex
	// The segment associated with this edge, used during forwarding path construction
	segment *Segment
}

// Method Includes tests whether the path within the current edge includes the
// path in other. If the paths are identical, the method returns false.
//
// If other includes a peering link, the method returns false (because in that
// case we want to keep the longer paths).
func (solEdge *solutionEdge) Includes(otherEdge *solutionEdge) bool {
	if solEdge.segment == otherEdge.segment {
		if solEdge.edge.Shortcut < otherEdge.edge.Shortcut && otherEdge.edge.Peer == 0 {
			return true
		}
	}
	return false
}

// PathField contains metadata about info fields or hop fields.
type PathField struct {
	Type FieldType

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

func NewHFPathField(he *seg.HopEntry) *PathField {
	hf, err := he.HopField()
	if err != nil {
		panic(err)
	}
	return &PathField{
		Type:  HF,
		InIF:  hf.Ingress,
		OutIF: hf.Egress,
		RawHF: he.RawHopField,
	}
}

func (pf PathField) String() string {
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

func (pf PathField) WriteTo(w io.Writer) (n int64, err error) {
	switch pf.Type {
	case IF:
		infoField := spath.InfoField{
			Up:       pf.Up == 1,
			Shortcut: pf.Shortcut == 1,
			Peer:     pf.Peer == 1,
			TsInt:    0,
			ISD:      uint16(pf.ISD),
			Hops:     pf.Hops,
		}
		return infoField.WriteTo(w)
	case HF:
		n, err := w.Write(pf.RawHF)
		return int64(n), err
	default:
		panic("unknown type")
	}
}

type FieldType int

const (
	IF FieldType = iota
	HF
)

func flagPrint(name string, value int) string {
	if value == 0 {
		return "."
	}
	return name
}

func insertSorted(s []int, value int) []int {
	index := sort.SearchInts(s, value)
	if index < len(s) && s[index] == value {
		return s
	}

	s = append(s, 0)
	copy(s[index+1:], s[index:])
	s[index] = value
	return s
}
