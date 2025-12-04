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
	"cmp"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/ctrl/path_mgmt/proto"
	"github.com/scionproto/scion/pkg/private/util"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

const (
	maxTimestamp = math.MaxUint32
)

// MaxExpirationTime is the maximum absolute expiration time of SCION hop
// fields.
var maxExpirationTime = time.Unix(maxTimestamp, 0).Add(path.ExpTimeToDuration(math.MaxUint8))

// vertexInfo maps destination vertices to the list of edges that point towards
// them.
type vertexInfo map[vertex]edgeMap

// dmg is a Directed Multigraph.
//
// Vertices are either ASes (identified by their ISD-AS number) or peering
// links (identified by the the ISD-AS numbers of the peers, and the IfIDs on
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

func printDMG(g *dmg) {
	var srcs []vertex
	for src := range g.Adjacencies {
		srcs = append(srcs, src)
	}
	slices.SortFunc(srcs, func(a, b vertex) int {
		return cmp.Or(
			cmp.Compare(a.IA, b.IA),
			cmp.Compare(a.UpIA, b.UpIA),
			cmp.Compare(a.DownIA, b.DownIA),
		)
	})

	for _, src := range srcs {
		neighbors := g.Adjacencies[src]
		fmt.Printf("%v Up %v#%v Down %v#%v\n", src.IA, src.UpIA, src.UpIfID, src.DownIA, src.DownIfID)

		var dsts []vertex
		for dst := range neighbors {
			dsts = append(dsts, dst)
		}
		slices.SortFunc(dsts, func(a, b vertex) int {
			return cmp.Or(
				cmp.Compare(a.IA, b.IA),
				cmp.Compare(a.UpIA, b.UpIA),
				cmp.Compare(a.DownIA, b.DownIA),
			)
		})

		for _, dst := range dsts {
			edgeList := neighbors[dst]

			var segments []*inputSegment
			for segment := range edgeList {
				segments = append(segments, segment)
			}
			slices.SortFunc(segments, func(a, b *inputSegment) int {
				return bytes.Compare(a.ID(), b.ID())
			})

			for _, segment := range segments {
				e := edgeList[segment]
				fmt.Printf(" --(%v, shortcut=%d, peer=%d)--> %v\n",
					segment.GetLoggingID(), e.Shortcut, e.Peer, dst.IA)
			}
		}
	}

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
		type Tuple struct {
			Src, Dst vertex
			Peer     int
		}

		for peerEntryIdx, peer := range asEntries[0].PeerEntries {
			ingress := iface.ID(peer.HopField.ConsIngress)
			remote := iface.ID(peer.PeerInterface)

			tuple := Tuple{
				Src:  vertexFromPeering(peer.Peer, remote, asEntries[0].Local, ingress),
				Dst:  vertexFromIA(asEntries[0].Local),
				Peer: peerEntryIdx + 1,
			}

			g.AddEdge(tuple.Src, tuple.Dst, segment, &edge{
				Weight:   1,
				Shortcut: 0, // First hop
				Peer:     tuple.Peer,
			})

		}

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
		// construction when pruning unneeded pieces of the segment.

		currentIA := asEntries[asEntryIndex].Local

		type Tuple struct {
			Src, Dst vertex
			Peer     int
		}

		var tuples []Tuple
		// This is the entry for our local AS; we're not interested in routing here,
		// so we skip this entry.
		if asEntryIndex != len(asEntries)-1 && segment.Type != proto.PathSegType_core {
			tuples = append(tuples, Tuple{
				Src: vertexFromIA(pinnedIA),
				Dst: vertexFromIA(currentIA),
			})
		}

		for peerEntryIdx, peer := range asEntries[asEntryIndex].PeerEntries {
			ingress := iface.ID(peer.HopField.ConsIngress)
			remote := iface.ID(peer.PeerInterface)

			tuples = append(tuples, Tuple{
				Src:  vertexFromIA(pinnedIA),
				Dst:  vertexFromPeering(currentIA, ingress, peer.Peer, remote), // <-----
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
func (g *dmg) GetPaths(src, dst vertex) []*pathSolution {
	var solutions []*pathSolution
	queue := []*pathSolution{{currentVertex: src}}
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
	slices.SortFunc(solutions, func(a, b *pathSolution) int {
		d := cmp.Or(
			cmp.Compare(a.cost, b.cost),
			cmp.Compare(len(a.edges), len(b.edges)),
		)
		if d != 0 {
			return d
		}
		trailA, trailB := a.edges, b.edges
		for ka := range trailA {
			idA := trailA[ka].segment.ID()
			idB := trailB[ka].segment.ID()
			d := cmp.Or(
				bytes.Compare(idA, idB),
				cmp.Compare(trailA[ka].edge.Shortcut, trailB[ka].edge.Shortcut),
				cmp.Compare(trailA[ka].edge.Peer, trailB[ka].edge.Peer),
			)
			if d != 0 {
				return d
			}
		}
		return 0
	})
	return solutions
}

// inputSegment is a local representation of a path segment that includes the
// segment's type. The type (up down or core) indicates the role that this
// segment holds in a path solution. That is, in which order the hops would
// be used for building an actual forwarding path (e.g. from the end in the
// case of an UP segment). However, the hops within the referred PathSegment
// *always* remain in construction order.
type inputSegment struct {
	*seg.PathSegment
	Type proto.PathSegType
	id   []byte
}

// IsDownSeg returns true if the segment is a DownSegment.
func (s *inputSegment) IsDownSeg() bool {
	return s.Type == proto.PathSegType_down
}

func (s *inputSegment) ID() []byte {
	if s.id == nil {
		s.id = s.PathSegment.ID()
	}
	return s.id
}

// Vertex is a union-like type for the AS vertices and Peering link vertices in
// a DMG that can be used as key in maps.
type vertex struct {
	IA       addr.IA
	UpIA     addr.IA
	UpIfID   iface.ID
	DownIA   addr.IA
	DownIfID iface.ID
}

func vertexFromIA(ia addr.IA) vertex {
	return vertex{IA: ia}
}

func vertexFromPeering(upIA addr.IA, upIfID iface.ID,
	downIA addr.IA, downIfID iface.ID,
) vertex {
	return vertex{UpIA: upIA, UpIfID: upIfID, DownIA: downIA, DownIfID: downIfID}
}

// Reverse returns a new vertex that contains the peering information in
// reverse. AS vertices remain unchanged.
func (v vertex) Reverse() vertex {
	return vertex{IA: v.IA, UpIA: v.DownIA, UpIfID: v.DownIfID, DownIA: v.UpIA, DownIfID: v.UpIfID}
}

// edgeMap is used to keep the set of edges going from one vertex to another.
// The edges are keyed by path segment pointer.
type edgeMap map[*inputSegment]*edge

// edge represents an edge for the DMG.
type edge struct {
	Weight int
	// Shortcut is the ASEntry index on where the forwarding portion of this
	// segment should end (for up-segments) or start (for down-segments).
	// This is also set when crossing peering links. If 0, the full segment is
	// used.
	Shortcut int
	// Peer is the index + 1 in the peer entries array for ASEntry defined by the
	// Shortcut index. This is 0 for non-peer shortcuts.
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
func (solution *pathSolution) Path(hashState hashState) Path {
	fmt.Println("PATH")

	mtu := ^uint16(0)
	var segments segmentList
	var epicPathAuths [][]byte
	for _, solEdge := range solution.edges {
		fmt.Println(solEdge.src, solEdge.dst)
		fmt.Println(solEdge.edge.Shortcut)

		var hops []path.HopField
		var intfs []snet.PathInterface
		var pathASEntries []seg.ASEntry // ASEntries that on the path, eventually in path order.
		var epicSegAuths [][]byte

		// TODO: rephrase, this is a lie for core.
		// Segments are in construction order, regardless of whether they're
		// up or down segments. We traverse them FROM THE END. So, in reverse
		// forwarding order for down segments and in forwarding order for
		// up segments.
		// We go through each ASEntry, starting from the last one until we
		// find a shortcut (which can be 0, meaning the end of the segment).
		asEntries := solEdge.segment.ASEntries

		isCoreWithShortcut := solEdge.segment.Type == proto.PathSegType_core && solEdge.edge.Peer != 0

		if !isCoreWithShortcut {
			for asEntryIdx := len(asEntries) - 1; asEntryIdx >= solEdge.edge.Shortcut; asEntryIdx-- {
				isShortcut := asEntryIdx == solEdge.edge.Shortcut && solEdge.edge.Shortcut != 0
				isPeer := asEntryIdx == solEdge.edge.Shortcut && solEdge.edge.Peer != 0
				fmt.Println("isShortcut", isShortcut, "isPeer", isPeer)
				asEntry := asEntries[asEntryIdx]

				var hopField path.HopField
				var epicAuth []byte
				if !isPeer {
					// Regular hop field.
					entry := asEntry.HopEntry
					hopField = path.HopField{
						ExpTime:     entry.HopField.ExpTime,
						ConsIngress: entry.HopField.ConsIngress,
						ConsEgress:  entry.HopField.ConsEgress,
						Mac:         entry.HopField.MAC,
					}
					// The Hop Entry's ingress MTU needs to be used to calculate the MTU for the
					// segment. Except for the ingress MTU of segment's first HE that is used.
					if entry.IngressMTU != 0 && !isShortcut {
						mtu = min(mtu, uint16(entry.IngressMTU))
					}
					epicAuth = getAuth(&asEntry)
				} else {
					// We've reached the ASEntry where we want to switch
					// segments on a peering link.
					peer := asEntry.PeerEntries[solEdge.edge.Peer-1]
					hopField = path.HopField{
						ExpTime:     peer.HopField.ExpTime,
						ConsIngress: peer.HopField.ConsIngress,
						ConsEgress:  peer.HopField.ConsEgress,
						Mac:         peer.HopField.MAC,
					}
					mtu = min(mtu, uint16(peer.PeerMTU))
					epicAuth = getAuthPeer(&asEntry, solEdge.edge.Peer-1)
				}

				// Segment is traversed in reverse construction direction.
				// Only include non-zero interfaces.
				if hopField.ConsEgress != 0 {
					intfs = append(intfs, snet.PathInterface{
						IA: asEntry.Local,
						ID: iface.ID(hopField.ConsEgress),
					})
				}
				// In a non-peer shortcut the AS is not traversed completely.
				if hopField.ConsIngress != 0 && (!isShortcut || isPeer) {
					intfs = append(intfs, snet.PathInterface{
						IA: asEntry.Local,
						ID: iface.ID(hopField.ConsIngress),
					})
				}
				hops = append(hops, hopField)
				fmt.Println("non core", intfs)
				pathASEntries = append(pathASEntries, asEntry)
				epicSegAuths = append(epicSegAuths, epicAuth)
				mtu = min(mtu, uint16(asEntry.MTU))
			}
		} else {
			for asEntryIdx := solEdge.edge.Shortcut; asEntryIdx >= 0; asEntryIdx-- {
				// TODO
				isShortcut := asEntryIdx == solEdge.edge.Shortcut && solEdge.edge.Shortcut != 0
				isPeer := asEntryIdx == solEdge.edge.Shortcut && solEdge.edge.Peer != 0
				fmt.Println("isShortcut", isShortcut, "isPeer", isPeer)
				asEntry := asEntries[asEntryIdx]

				var hopField path.HopField
				var epicAuth []byte
				if !isPeer {
					// Regular hop field.
					entry := asEntry.HopEntry
					hopField = path.HopField{
						ExpTime:     entry.HopField.ExpTime,
						ConsIngress: entry.HopField.ConsIngress,
						ConsEgress:  entry.HopField.ConsEgress,
						Mac:         entry.HopField.MAC,
					}
					// The Hop Entry's ingress MTU needs to be used to calculate the MTU for the
					// segment. Except for the ingress MTU of segment's first HE that is used.
					if entry.IngressMTU != 0 && !isShortcut {
						mtu = min(mtu, uint16(entry.IngressMTU))
					}
					epicAuth = getAuth(&asEntry)
				} else {
					// We've reached the ASEntry where we want to switch
					// segments on a peering link.
					peer := asEntry.PeerEntries[solEdge.edge.Peer-1]
					hopField = path.HopField{
						ExpTime:     peer.HopField.ExpTime,
						ConsIngress: peer.HopField.ConsIngress,
						ConsEgress:  peer.HopField.ConsEgress,
						Mac:         peer.HopField.MAC,
					}
					mtu = min(mtu, uint16(peer.PeerMTU))
					epicAuth = getAuthPeer(&asEntry, solEdge.edge.Peer-1)
				}

				// In a non-peer shortcut the AS is not traversed completely.
				if hopField.ConsIngress != 0 {
					intfs = append(intfs, snet.PathInterface{
						IA: asEntry.Local,
						ID: iface.ID(hopField.ConsIngress),
					})
				}
				hops = append(hops, hopField)
				fmt.Println("core", intfs)
				pathASEntries = append(pathASEntries, asEntry)
				epicSegAuths = append(epicSegAuths, epicAuth)
				mtu = min(mtu, uint16(asEntry.MTU))
			}
		}

		// Put the hops in forwarding order. Needed for down segments
		// since we collected hops from the end, just like for up
		// segments.
		if solEdge.segment.Type == proto.PathSegType_down {
			slices.Reverse(hops)
			slices.Reverse(intfs)
			slices.Reverse(pathASEntries)
			slices.Reverse(epicSegAuths)
		}

		segments = append(segments, segment{
			InfoField: path.InfoField{
				Timestamp: util.TimeToSecs(solEdge.segment.Info.Timestamp),
				SegID:     calculateBeta(solEdge),
				ConsDir:   solEdge.segment.IsDownSeg(),
				Peer:      solEdge.edge.Peer != 0,
			},
			HopFields:  hops,
			Interfaces: intfs,
			ASEntries:  pathASEntries,
		})
		fmt.Println("hops:", len(intfs))
		epicPathAuths = append(epicPathAuths, epicSegAuths...)
	}
	fmt.Println("segments:", len(segments))

	interfaces := segments.Interfaces()
	asEntries := segments.ASEntries()
	fmt.Println(interfaces)
	staticInfo := collectMetadata(interfaces, asEntries)

	path := Path{
		SCIONPath: segments.ScionPath(),
		Metadata: snet.PathMetadata{
			Interfaces:           interfaces,
			MTU:                  mtu,
			Expiry:               segments.ComputeExpTime(),
			Latency:              staticInfo.Latency,
			Bandwidth:            staticInfo.Bandwidth,
			Geo:                  staticInfo.Geo,
			LinkType:             staticInfo.LinkType,
			InternalHops:         staticInfo.InternalHops,
			Notes:                staticInfo.Notes,
			DiscoveryInformation: staticInfo.DiscoveryInformation,
		},
		Weight:      solution.cost,
		Fingerprint: fingerprint(interfaces, hashState),
	}

	if authPHVF, authLHVF, ok := isEpicAvailable(epicPathAuths); ok {
		path.Metadata.EpicAuths = snet.EpicAuths{
			AuthPHVF: authPHVF,
			AuthLHVF: authLHVF,
		}
	}

	return path
}

func getAuth(a *seg.ASEntry) []byte {
	if a.UnsignedExtensions.EpicDetached == nil {
		return nil
	}

	auth := make([]byte, 16)
	copy(auth[0:6], a.HopEntry.HopField.MAC[:])
	copy(auth[6:16], a.UnsignedExtensions.EpicDetached.AuthHopEntry)
	return auth
}

func getAuthPeer(a *seg.ASEntry, i int) []byte {
	if a.UnsignedExtensions.EpicDetached == nil {
		return nil
	}

	auth := make([]byte, 16)
	copy(auth[0:6], a.HopEntry.HopField.MAC[:])
	copy(auth[6:16], a.UnsignedExtensions.EpicDetached.AuthPeerEntries[i])
	return auth
}

func isEpicAvailable(epicPathAuths [][]byte) ([]byte, []byte, bool) {
	l := len(epicPathAuths)
	if l < 2 {
		return nil, nil, false
	}
	if epicPathAuths[l-1] == nil || epicPathAuths[l-2] == nil {
		return nil, nil, false
	}
	return epicPathAuths[l-2], epicPathAuths[l-1], true
}

func calculateBeta(se *solutionEdge) uint16 {
	// If this is a peer hop, we need to set beta[i] = beta[i+1]. That is, the SegID
	// accumulator must correspond to the next (in construction order) hop.
	//
	// This is because this peering hop has a MAC that chains to its non-peering
	// counterpart, the same as what the next hop (in construction order) chains to.
	// So both this and the next hop are to be validated from the same SegID
	// accumulator value: the one for the *next* hop, calculated on the regular
	// non-peering segment.
	//
	// Note that, when traversing peer hops, the SegID accumulator is left untouched for the
	// next router on the path to use.

	var index int
	if se.segment.IsDownSeg() {
		index = se.edge.Shortcut
		if se.edge.Peer != 0 {
			index++
		}
	} else {
		index = len(se.segment.ASEntries) - 1
		if index == se.edge.Shortcut && se.edge.Peer != 0 {
			index++
		}
	}
	beta := se.segment.Info.SegmentID
	for i := 0; i < index; i++ {
		hop := se.segment.ASEntries[i].HopEntry
		beta = beta ^ binary.BigEndian.Uint16(hop.HopField.MAC[:])
	}
	return beta
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
		panic("Invalid segment type: " + currSeg.Type.String())
	}
}

// segment is a helper that represents a path segment during the conversion
// from the graph solution to the raw forwarding information. The hops should
// be in forwarding order.
type segment struct {
	InfoField  path.InfoField
	HopFields  []path.HopField
	Interfaces []snet.PathInterface
	ASEntries  []seg.ASEntry
}

func (segment *segment) ComputeExpTime() time.Time {
	ts := util.SecsToTime(segment.InfoField.Timestamp)
	return ts.Add(segment.computeHopFieldsTTL())
}

func (segment *segment) computeHopFieldsTTL() time.Duration {
	minTTL := path.MaxTTL
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
	minTimestamp := maxExpirationTime
	for _, segment := range s {
		expTime := segment.ComputeExpTime()
		if minTimestamp.After(expTime) {
			minTimestamp = expTime
		}
	}
	return minTimestamp
}

func (s segmentList) ScionPath() snetpath.SCION {
	var meta scion.MetaHdr
	var infos []path.InfoField
	var hops []path.HopField

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
	return snetpath.SCION{Raw: raw}
}
