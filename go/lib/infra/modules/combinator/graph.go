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

package combinator

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

// VertexInfo maps destination vertices to the list of edges that point towards
// them.
type VertexInfo map[Vertex]EdgeMap

// DMG is a Directed Multigraph.
//
// Vertices are either ASes (identified by their ISD-AS number) or peering
// links (identified by the the ISD-AS numbers of the peers, and the IFIDs on
// the peering link).
type DMG struct {
	Adjacencies map[Vertex]VertexInfo
}

// NewDMG creates a new graph from sets of path segments.
//
// The input segments are traversed to construct the graph. Each segment is
// traversed in reverse, from the last AS Entry to the first one. During this
// traversal, we save the AS number of the first traversed ASEntry (i.e., last
// one in ASEntries array) as pinnedIA. This will represent the source of the
// edges we add for Up and Core segments, and the destination for Down
// segments.
//
// For each ASEntry, all hop entries are explored. If the hop entry is a
// “normal” hop entry (i.e., the one at index 0), we check the following:
// (1) If this is the last ASEntry in the segment, it means we’re routing to
// pinnedIA. This is not interesting so we continue to the next hop entry
// without changing anything in the graph. (2) Otherwise, a vertex is added
// (if one doesn’t exist) for the current AS. Then, an edge is added from
// pinnedIA to this vertex, in the case of up- and core-segments, or from this
// vertex to pinnedIA (in the case of down-segments). The edge is annotated
// with the segment that is currently being traversed, and ShortcutID is set to
// the position of the current ASEntry in the ASEntries array. PeerID is set to
// 0.
//
// If the hop entry is a peer entry (i.e., its index is different from 0), a
// peering vertex is added based on (IA, Ingress, InIA, RemoteInIF) for up
// segments, and on (InIA, RemoteInIF, IA, Ingress) for down segments. Note
// that the AS number in the peering vertex is not pinnedIA, but the one
// participating in the peering. The edge is annotated with the segment that is
// currently being traversed, and ShortcutID is set to the position of the
// current ASEntry in the ASEntries array. The direction of the edge is from
// pinnedIA to the peering vertex for up-segments, and the reverse for
// down-segments. PeerID is set to the index of the current hop entry.
func NewDMG(ups, cores, downs []*seg.PathSegment) *DMG {
	g := &DMG{
		Adjacencies: make(map[Vertex]VertexInfo),
	}
	for _, segment := range ups {
		g.traverseSegment(&InputSegment{PathSegment: segment, Type: proto.PathSegType_up})
	}
	for _, segment := range cores {
		g.traverseSegment(&InputSegment{PathSegment: segment, Type: proto.PathSegType_core})
	}
	for _, segment := range downs {
		g.traverseSegment(&InputSegment{PathSegment: segment, Type: proto.PathSegType_down})
	}
	return g
}

func (g *DMG) traverseSegment(segment *InputSegment) {
	asEntries := segment.ASEntries

	// Directly process core segments, because we're not interested in
	// shortcuts. Add edge from last entry IA to first entry IA.
	if segment.Type == proto.PathSegType_core {
		g.AddEdge(
			VertexFromIA(asEntries[len(asEntries)-1].Local),
			VertexFromIA(asEntries[0].Local),
			segment,
			&Edge{Weight: len(asEntries) - 1},
		)
		return
	}

	// Up or Down segment. Last AS in the PCB is the root for edge addition.
	// For Ups, edges will originate from pinnedIA. For Downs, edges will go
	// towards pinnedIA.
	pinnedIA := asEntries[len(asEntries)-1].Local

	for asEntryIndex := len(asEntries) - 1; asEntryIndex >= 0; asEntryIndex-- {
		// Whenever we add an edge that is not towards the first AS in the PCB,
		// we are creating a shortcut. We use the asEntryIndex to annotate the
		// edges as such, as we need the metadata during forwarding path
		// construction when adding verify-only HFs and pruning unneeded pieces
		// of the segment.

		currentIA := asEntries[asEntryIndex].Local

		type Tuple struct {
			Src, Dst Vertex
			Peer     int
		}

		var tuples []Tuple
		// This is the entry for our local AS; we're not interested in routing here,
		// so we skip this entry.
		if asEntryIndex != len(asEntries)-1 {
			tuples = append(tuples, Tuple{
				Src: VertexFromIA(pinnedIA),
				Dst: VertexFromIA(currentIA),
			})
		}

		for peerEntryIdx, peer := range asEntries[asEntryIndex].PeerEntries {
			ingress := common.IFIDType(peer.HopField.ConsIngress)
			remote := common.IFIDType(peer.PeerInterface)
			tuples = append(tuples, Tuple{
				Src:  VertexFromIA(pinnedIA),
				Dst:  VertexFromPeering(currentIA, ingress, peer.Peer, remote),
				Peer: peerEntryIdx + 1,
			})
		}

		for _, tuple := range tuples {
			weight := len(asEntries) - 1 - asEntryIndex

			if segment.Type == proto.PathSegType_down {
				// reverse peering vertices (to have them match those created
				// during up-segment exploration), and reverse edge orientation.
				tuple.Dst = tuple.Dst.Reverse()
				tuple.Src, tuple.Dst = tuple.Dst, tuple.Src
				if tuple.Peer != 0 {
					// Count the peering link itself, but only once
					weight += 1
				}
			}

			g.AddEdge(tuple.Src, tuple.Dst, segment, &Edge{
				Weight:   weight,
				Shortcut: asEntryIndex,
				Peer:     tuple.Peer,
			})
		}
	}
}

func (g *DMG) AddEdge(src, dst Vertex, segment *InputSegment, edge *Edge) {
	if _, ok := g.Adjacencies[src]; !ok {
		g.Adjacencies[src] = make(VertexInfo)
	}
	if _, ok := g.Adjacencies[dst]; !ok {
		g.Adjacencies[dst] = make(VertexInfo)
	}
	neighborMap := g.Adjacencies[src]
	if _, ok := neighborMap[dst]; !ok {
		neighborMap[dst] = make(EdgeMap)
	}
	neighborMap[dst][segment] = edge
}

// GetPaths returns all the paths from src to dst, sorted according to weight.
func (g *DMG) GetPaths(src, dst Vertex) PathSolutionList {
	var solutions PathSolutionList
	queue := PathSolutionList{&PathSolution{currentVertex: src}}
	for len(queue) > 0 {
		currentPathSolution := queue[0]
		queue = queue[1:]

		for nextVertex, edgeList := range g.Adjacencies[currentPathSolution.currentVertex] {
			for segment, edge := range edgeList {
				// Makes sure the the segment would be valid in a path.
				if !validNextSeg(currentPathSolution.currentSeg, segment) {
					continue
				}
				// Create a copy of the old solution s.t. trail slices do not
				// get mixed during appends.
				newSolution := &PathSolution{
					edges:         append([]*solutionEdge{}, currentPathSolution.edges...),
					currentVertex: nextVertex,
					currentSeg:    segment,
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

				if nextVertex == dst {
					solutions = append(solutions, newSolution)
					// Do not break, because we want all solutions
				} else {
					queue = append(queue, newSolution)
				}
			}
		}
	}
	sort.Sort(solutions)
	return solutions
}

// Vertex is a union-like type for the AS vertices and Peering link vertices in
// a DMG that can be used as key in maps.
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

// Reverse returns a new vertex that contains the peering information in
// reverse. AS vertices remain unchanged.
func (v Vertex) Reverse() Vertex {
	return Vertex{IA: v.IA, UpIA: v.DownIA, UpIFID: v.DownIFID, DownIA: v.UpIA, DownIFID: v.UpIFID}
}

// EdgeMap is used to keep the set of edges going from one vertex to another.
// The edges are keyed by path segment pointer.
type EdgeMap map[*InputSegment]*Edge

// Edge represents an edge for the DMG.
type Edge struct {
	Weight int
	// Shortcut is the ASEntry index on where the forwarding portion of this
	// segment should end (for up-segments) or start (for down-segments). An
	// additional V-only HF upstream of this ASEntry needs to be included for
	// verification.  This is also set when crossing peering links. If 0, the
	// full segment is used.
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
	// currentSeg is the current segment being visited
	currentSeg *InputSegment
	// cost is the sum of edge weights
	cost int
}

// getFwdPathMetadata builds the complete metadata for a forwarding path by
// extracting it from a path between source and destination in the DMG.
func (solution *PathSolution) getFwdPathMetadata() *Path {
	path := &Path{
		Weight: solution.cost,
		Mtu:    ^uint16(0),
	}
	for _, solEdge := range solution.edges {
		var hops []*HopField
		var intfs []snet.PathInterface

		// Go through each ASEntry, starting from the last one, until we
		// find a shortcut (which can be 0, meaning the end of the segment).
		asEntries := solEdge.segment.ASEntries
		for asEntryIdx := len(asEntries) - 1; asEntryIdx >= solEdge.edge.Shortcut; asEntryIdx-- {
			isShortcut := asEntryIdx == solEdge.edge.Shortcut && solEdge.edge.Shortcut != 0
			isPeer := asEntryIdx == solEdge.edge.Shortcut && solEdge.edge.Peer != 0
			asEntry := asEntries[asEntryIdx]

			// Regular hop field.
			entry := asEntry.HopEntry
			hopField := &HopField{
				ExpTime:     entry.HopField.ExpTime,
				ConsIngress: entry.HopField.ConsIngress,
				ConsEgress:  entry.HopField.ConsEgress,
				MAC:         append([]byte(nil), entry.HopField.MAC...),
			}

			// We don't know if this hop entry is used for forwarding (a peer
			// entry might be used instead, which would override mtu later)
			forwardingLinkMtu := entry.IngressMTU

			if isPeer {
				// We've reached the ASEntry where we want to switch
				// segments on a peering link.
				peer := asEntry.PeerEntries[solEdge.edge.Peer-1]
				hopField = &HopField{
					ExpTime:     peer.HopField.ExpTime,
					ConsIngress: peer.HopField.ConsIngress,
					ConsEgress:  peer.HopField.ConsEgress,
					MAC:         append([]byte(nil), peer.HopField.MAC...),
				}
				forwardingLinkMtu = peer.PeerMTU
			}

			// Segment is traversed in reverse construction direction.
			// Only include non-zero interfaces.
			if hopField.ConsEgress != 0 {
				intfs = append(intfs, snet.PathInterface{
					IA: asEntry.Local,
					ID: common.IFIDType(hopField.ConsEgress),
				})
			}
			// In a non-peer shortcut the AS is not traversed completely.
			if hopField.ConsIngress != 0 && (!isShortcut || isPeer) {
				intfs = append(intfs, snet.PathInterface{
					IA: asEntry.Local,
					ID: common.IFIDType(hopField.ConsIngress),
				})
			}
			hops = append(hops, hopField)

			path.Mtu = minUint16(path.Mtu, uint16(asEntry.MTU))
			if forwardingLinkMtu != 0 {
				// The first HE in a segment has MTU 0, so we ignore those
				path.Mtu = minUint16(path.Mtu, uint16(forwardingLinkMtu))
			}
		}
		path.Segments = append(path.Segments, &Segment{
			Type: solEdge.segment.Type,
			InfoField: &InfoField{
				Timestamp: solEdge.segment.Info.Timestamp,
				SegID:     calculateBeta(solEdge),
				ConsDir:   solEdge.segment.IsDownSeg(),
				Peer:      solEdge.edge.Peer != 0,
			},
			HopFields:  hops,
			Interfaces: intfs,
		})
	}
	path.reverseDownSegment()
	path.aggregateInterfaces()
	path.StaticInfo = solution.collectMetadata()
	return path
}

func calculateBeta(edge *solutionEdge) uint16 {
	var index int
	if edge.segment.IsDownSeg() {
		index = edge.edge.Shortcut
		// If this is a peer, we need to set beta i+1.
		if edge.edge.Peer != 0 {
			index++
		}
	} else {
		index = len(edge.segment.ASEntries) - 1
	}
	beta := edge.segment.Info.SegmentID
	for i := 0; i < index; i++ {
		hop := edge.segment.ASEntries[i].HopEntry
		beta = beta ^ binary.BigEndian.Uint16(hop.HopField.MAC)
	}
	return beta
}

// PathSolutionList is a sort.Interface implementation for a slice of solutions.
type PathSolutionList []*PathSolution

func (sl PathSolutionList) Len() int {
	return len(sl)
}

// Less sorts according to the following priority list:
//  - total path cost (number of hops)
//  - number of segments
//  - segmentIDs
//  - shortcut index
//  - peer entry index
func (sl PathSolutionList) Less(i, j int) bool {
	if sl[i].cost != sl[j].cost {
		return sl[i].cost < sl[j].cost
	}

	trailI, trailJ := sl[i].edges, sl[j].edges
	if len(trailI) != len(trailJ) {
		return len(trailI) < len(trailJ)
	}

	for ki := range trailI {
		idI := trailI[ki].segment.ID()
		idJ := trailJ[ki].segment.ID()
		idcmp := bytes.Compare(idI, idJ)
		if idcmp != 0 {
			return idcmp == -1
		}
		if trailI[ki].edge.Shortcut != trailJ[ki].edge.Shortcut {
			return trailI[ki].edge.Shortcut < trailJ[ki].edge.Shortcut
		}
		if trailI[ki].edge.Peer != trailJ[ki].edge.Peer {
			return trailI[ki].edge.Peer < trailJ[ki].edge.Peer
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

func minUint16(x, y uint16) uint16 {
	if x < y {
		return x
	}
	return y
}

// validNextSeg returns whether nextSeg is a valid next segment in a path from the given currSeg.
// A path can only contain at most 1 up, 1 core, and 1 down segment.
func validNextSeg(currSeg, nextSeg *InputSegment) bool {
	if currSeg == nil {
		// If we have no segment any segment can be first.
		return true
	}
	switch currSeg.Type {
	case proto.PathSegType_up:
		return nextSeg.Type == proto.PathSegType_core || nextSeg.Type == proto.PathSegType_down
	case proto.PathSegType_core:
		return nextSeg.Type == proto.PathSegType_down
	case proto.PathSegType_down:
		return false
	default:
		panic(fmt.Sprintf("Invalid segment type: %v", currSeg.Type))
	}
}
