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
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

// vertexInfo maps destination vertices to the list of edges that point towards
// them.
type vertexInfo map[vertex]edgeMap

// dmg is a Directed Multigraph.
//
// Vertices are either ASes (identified by their ISD-AS number) or peering
// links (identified by the the ISD-AS numbers of the peers, and the IFIDs on
// the peering link).
type dmg struct {
	Adjacencies map[vertex]vertexInfo
}

// newDMG creates a new graph from sets of path segments.
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
func newDMG(ups, cores, downs []*seg.PathSegment) *dmg {
	g := &dmg{
		Adjacencies: make(map[vertex]vertexInfo),
	}
	for _, segment := range ups {
		g.traverseSegment(&inputSegment{PathSegment: segment, Type: proto.PathSegType_up})
	}
	for _, segment := range cores {
		g.traverseSegment(&inputSegment{PathSegment: segment, Type: proto.PathSegType_core})
	}
	for _, segment := range downs {
		g.traverseSegment(&inputSegment{PathSegment: segment, Type: proto.PathSegType_down})
	}
	return g
}

func (g *dmg) traverseSegment(segment *inputSegment) {
	asEntries := segment.ASEntries

	// Directly process core segments, because we're not interested in
	// shortcuts. Add edge from last entry IA to first entry IA.
	if segment.Type == proto.PathSegType_core {
		g.AddEdge(
			vertexFromIA(asEntries[len(asEntries)-1].Local),
			vertexFromIA(asEntries[0].Local),
			segment,
			&edge{Weight: len(asEntries) - 1},
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
			Src, Dst vertex
			Peer     int
		}

		var tuples []Tuple
		// This is the entry for our local AS; we're not interested in routing here,
		// so we skip this entry.
		if asEntryIndex != len(asEntries)-1 {
			tuples = append(tuples, Tuple{
				Src: vertexFromIA(pinnedIA),
				Dst: vertexFromIA(currentIA),
			})
		}

		for peerEntryIdx, peer := range asEntries[asEntryIndex].PeerEntries {
			ingress := common.IFIDType(peer.HopField.ConsIngress)
			remote := common.IFIDType(peer.PeerInterface)
			tuples = append(tuples, Tuple{
				Src:  vertexFromIA(pinnedIA),
				Dst:  vertexFromPeering(currentIA, ingress, peer.Peer, remote),
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

			g.AddEdge(tuple.Src, tuple.Dst, segment, &edge{
				Weight:   weight,
				Shortcut: asEntryIndex,
				Peer:     tuple.Peer,
			})
		}
	}
}

func (g *dmg) AddEdge(src, dst vertex, segment *inputSegment, e *edge) {
	if _, ok := g.Adjacencies[src]; !ok {
		g.Adjacencies[src] = make(vertexInfo)
	}
	if _, ok := g.Adjacencies[dst]; !ok {
		g.Adjacencies[dst] = make(vertexInfo)
	}
	neighborMap := g.Adjacencies[src]
	if _, ok := neighborMap[dst]; !ok {
		neighborMap[dst] = make(edgeMap)
	}
	neighborMap[dst][segment] = e
}

// GetPaths returns all the paths from src to dst, sorted according to weight.
func (g *dmg) GetPaths(src, dst vertex) pathSolutionList {
	var solutions pathSolutionList
	queue := pathSolutionList{&pathSolution{currentVertex: src}}
	for len(queue) > 0 {
		currentPathSolution := queue[0]
		queue = queue[1:]

		for nextVertex, edgeList := range g.Adjacencies[currentPathSolution.currentVertex] {
			for segment, e := range edgeList {
				// Makes sure the the segment would be valid in a path.
				if !validNextSeg(currentPathSolution.currentSeg, segment) {
					continue
				}
				// Create a copy of the old solution s.t. trail slices do not
				// get mixed during appends.
				newSolution := &pathSolution{
					edges:         append([]*solutionEdge{}, currentPathSolution.edges...),
					currentVertex: nextVertex,
					currentSeg:    segment,
					cost:          currentPathSolution.cost + e.Weight,
				}

				// Append the explored edge to the solution, and add it to the
				// queue of candidate solutions.
				newSolution.edges = append(newSolution.edges,
					&solutionEdge{
						edge:    e,
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

// inputSegment is a local representation of a path segment that includes the
// segment's type.
type inputSegment struct {
	*seg.PathSegment
	Type proto.PathSegType
}

// IsDownSeg returns true if the segment is a DownSegment.
func (s *inputSegment) IsDownSeg() bool {
	return s.Type == proto.PathSegType_down
}

// Vertex is a union-like type for the AS vertices and Peering link vertices in
// a DMG that can be used as key in maps.
type vertex struct {
	IA       addr.IA
	UpIA     addr.IA
	UpIFID   common.IFIDType
	DownIA   addr.IA
	DownIFID common.IFIDType
}

func vertexFromIA(ia addr.IA) vertex {
	return vertex{IA: ia}
}

func vertexFromPeering(upIA addr.IA, upIFID common.IFIDType,
	downIA addr.IA, downIFID common.IFIDType) vertex {

	return vertex{UpIA: upIA, UpIFID: upIFID, DownIA: downIA, DownIFID: downIFID}
}

// Reverse returns a new vertex that contains the peering information in
// reverse. AS vertices remain unchanged.
func (v vertex) Reverse() vertex {
	return vertex{IA: v.IA, UpIA: v.DownIA, UpIFID: v.DownIFID, DownIA: v.UpIA, DownIFID: v.UpIFID}
}

// edgeMap is used to keep the set of edges going from one vertex to another.
// The edges are keyed by path segment pointer.
type edgeMap map[*inputSegment]*edge

// edge represents an edge for the DMG.
type edge struct {
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

type pathSolution struct {
	// edges contains the edges in the solution, one for each segment
	edges []*solutionEdge
	// currentVertex is the currentVertex being visited
	currentVertex vertex
	// currentSeg is the current segment being visited
	currentSeg *inputSegment
	// cost is the sum of edge weights
	cost int
}

// Path builds the forwarding path with metadata by extracting it from a path
// between source and destination in the DMG.
func (solution *pathSolution) Path() Path {
	mtu := ^uint16(0)
	var segments segmentList
	for _, solEdge := range solution.edges {
		var hops []*path.HopField
		var intfs []snet.PathInterface
		var pathASEntries []seg.ASEntry // ASEntries that on the path, eventually in path order.

		// Go through each ASEntry, starting from the last one, until we
		// find a shortcut (which can be 0, meaning the end of the segment).
		asEntries := solEdge.segment.ASEntries
		for asEntryIdx := len(asEntries) - 1; asEntryIdx >= solEdge.edge.Shortcut; asEntryIdx-- {
			isShortcut := asEntryIdx == solEdge.edge.Shortcut && solEdge.edge.Shortcut != 0
			isPeer := asEntryIdx == solEdge.edge.Shortcut && solEdge.edge.Peer != 0
			asEntry := asEntries[asEntryIdx]

			var hopField *path.HopField
			var forwardingLinkMtu int
			if !isPeer {
				// Regular hop field.
				entry := asEntry.HopEntry
				hopField = &path.HopField{
					ExpTime:     entry.HopField.ExpTime,
					ConsIngress: entry.HopField.ConsIngress,
					ConsEgress:  entry.HopField.ConsEgress,
					Mac:         append([]byte(nil), entry.HopField.MAC...),
				}
				forwardingLinkMtu = entry.IngressMTU
			} else {
				// We've reached the ASEntry where we want to switch
				// segments on a peering link.
				peer := asEntry.PeerEntries[solEdge.edge.Peer-1]
				hopField = &path.HopField{
					ExpTime:     peer.HopField.ExpTime,
					ConsIngress: peer.HopField.ConsIngress,
					ConsEgress:  peer.HopField.ConsEgress,
					Mac:         append([]byte(nil), peer.HopField.MAC...),
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
			pathASEntries = append(pathASEntries, asEntry)

			mtu = minUint16(mtu, uint16(asEntry.MTU))
			if forwardingLinkMtu != 0 {
				// The first HE in a segment has MTU 0, so we ignore those
				mtu = minUint16(mtu, uint16(forwardingLinkMtu))
			}
		}

		if solEdge.segment.Type == proto.PathSegType_down {
			reverseHops(hops)
			reverseIntfs(intfs)
			reverseASEntries(pathASEntries)
		}

		segments = append(segments, segment{
			InfoField: &path.InfoField{
				Timestamp: util.TimeToSecs(solEdge.segment.Info.Timestamp),
				SegID:     calculateBeta(solEdge),
				ConsDir:   solEdge.segment.IsDownSeg(),
				Peer:      solEdge.edge.Peer != 0,
			},
			HopFields:  hops,
			Interfaces: intfs,
			ASEntries:  pathASEntries,
		})
	}

	interfaces := segments.Interfaces()
	asEntries := segments.ASEntries()
	staticInfo := collectMetadata(interfaces, asEntries)

	return Path{
		SPath: segments.SPath(),
		Metadata: snet.PathMetadata{
			Interfaces:   interfaces,
			MTU:          mtu,
			Expiry:       segments.ComputeExpTime(),
			Latency:      staticInfo.Latency,
			Bandwidth:    staticInfo.Bandwidth,
			Geo:          staticInfo.Geo,
			LinkType:     staticInfo.LinkType,
			InternalHops: staticInfo.InternalHops,
			Notes:        staticInfo.Notes,
		},
		Weight: solution.cost,
	}
}

func reverseHops(s []*path.HopField) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func reverseIntfs(s []snet.PathInterface) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func reverseASEntries(s []seg.ASEntry) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func calculateBeta(se *solutionEdge) uint16 {
	var index int
	if se.segment.IsDownSeg() {
		index = se.edge.Shortcut
		// If this is a peer, we need to set beta i+1.
		if se.edge.Peer != 0 {
			index++
		}
	} else {
		index = len(se.segment.ASEntries) - 1
	}
	beta := se.segment.Info.SegmentID
	for i := 0; i < index; i++ {
		hop := se.segment.ASEntries[i].HopEntry
		beta = beta ^ binary.BigEndian.Uint16(hop.HopField.MAC)
	}
	return beta
}

// PathSolutionList is a sort.Interface implementation for a slice of solutions.
type pathSolutionList []*pathSolution

func (sl pathSolutionList) Len() int {
	return len(sl)
}

// Less sorts according to the following priority list:
//  - total path cost (number of hops)
//  - number of segments
//  - segmentIDs
//  - shortcut index
//  - peer entry index
func (sl pathSolutionList) Less(i, j int) bool {
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

func (sl pathSolutionList) Swap(i, j int) {
	sl[i], sl[j] = sl[j], sl[i]
}

// solutionEdge contains a graph edge and additional metadata required during
// graph exploration.
type solutionEdge struct {
	edge *edge
	src  vertex
	dst  vertex
	// The segment associated with this edge, used during forwarding path construction
	segment *inputSegment
}

func minUint16(x, y uint16) uint16 {
	if x < y {
		return x
	}
	return y
}

// validNextSeg returns whether nextSeg is a valid next segment in a path from the given currSeg.
// A path can only contain at most 1 up, 1 core, and 1 down segment.
func validNextSeg(currSeg, nextSeg *inputSegment) bool {
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

// segment is a helper that represents a path segment during the conversion
// from the graph solution to the raw forwarding information.
type segment struct {
	InfoField  *path.InfoField
	HopFields  []*path.HopField
	Interfaces []snet.PathInterface
	ASEntries  []seg.ASEntry
}

func (segment *segment) ComputeExpTime() time.Time {
	ts := util.SecsToTime(segment.InfoField.Timestamp)
	return ts.Add(segment.computeHopFieldsTTL())
}

func (segment *segment) computeHopFieldsTTL() time.Duration {
	minTTL := time.Duration(path.MaxTTL) * time.Second
	for _, hf := range segment.HopFields {
		offset := path.ExpTimeToDuration(hf.ExpTime)
		if minTTL > offset {
			minTTL = offset
		}
	}
	return minTTL
}

// segmentList is a helper that represents a path as a sequence of up to three
// segments during the conversion from the graph solution to the raw forwarding
// information.
type segmentList []segment

// Interfaces returns the concatenated lists of interfaces from the individual
// segments
func (s segmentList) Interfaces() []snet.PathInterface {
	var intfs []snet.PathInterface
	for _, seg := range s {
		intfs = append(intfs, seg.Interfaces...)
	}
	return intfs
}

// ASEntries returns the concatenated lists of AS entries from the
// individual segments, in the order of appearance on the path.
func (s segmentList) ASEntries() []seg.ASEntry {
	var asEntries []seg.ASEntry
	for _, seg := range s {
		asEntries = append(asEntries, seg.ASEntries...)
	}
	return asEntries
}

func (s segmentList) ComputeExpTime() time.Time {
	minTimestamp := spath.MaxExpirationTime
	for _, segment := range s {
		expTime := segment.ComputeExpTime()
		if minTimestamp.After(expTime) {
			minTimestamp = expTime
		}
	}
	return minTimestamp
}

func (s segmentList) SPath() spath.Path {
	var meta scion.MetaHdr
	var infos []*path.InfoField
	var hops []*path.HopField

	for i, segment := range s {
		meta.SegLen[i] = uint8(len(segment.HopFields))
		infos = append(infos, segment.InfoField)
		hops = append(hops, segment.HopFields...)
	}
	sp := scion.Decoded{
		Base: scion.Base{
			PathMeta: meta,
			NumHops:  len(hops),
			NumINF:   len(s),
		},
		InfoFields: infos,
		HopFields:  hops,
	}
	raw := make([]byte, sp.Len())
	if err := sp.SerializeTo(raw); err != nil {
		panic(err)
	}
	return spath.Path{Raw: raw, Type: slayers.PathTypeSCION}
}
