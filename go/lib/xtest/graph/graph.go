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

// Package graph implements a multigraph model of a SCION network for use in
// tests. The default Mock SCIOND implementation uses the graph to simulate
// path lookups.
//
// Note that the graph always returns the shortest paths, regardless whether
// they are valid SCION paths (e.g., the path might cross multiple peering
// links).
package graph

import (
	"fmt"
	"sort"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/proto"
)

// Graph implements a graph of ASes and IFIDs for testing purposes. IFIDs
// must be globally unique.
//
// Nodes are represented by ASes.
//
// Edges are represented by pairs of IFIDs.
type Graph struct {
	// maps IFIDs to the other IFID of the edge
	links map[common.IFIDType]common.IFIDType
	// specifies whether an IFID is on a peering link
	isPeer map[common.IFIDType]bool
	// maps IFIDs to the AS they belong to
	parents map[common.IFIDType]addr.IA
	// maps ASes to a structure containing a slice of their IFIDs
	ases map[addr.IA]*AS

	lock sync.Mutex
}

// New allocates a new empty graph.
func New() *Graph {
	return &Graph{
		links:   make(map[common.IFIDType]common.IFIDType),
		isPeer:  make(map[common.IFIDType]bool),
		parents: make(map[common.IFIDType]addr.IA),
		ases:    make(map[addr.IA]*AS),
	}
}

// NewFromDescription initializes a new graph from description desc.
func NewFromDescription(desc *Description) *Graph {
	graph := New()
	for _, node := range desc.Nodes {
		graph.Add(node)
	}
	for _, edge := range desc.Edges {
		graph.AddLink(edge.Xia, edge.Xifid, edge.Yia, edge.Yifid, edge.Peer)
	}
	return graph
}

// Add adds a new node to the graph. If ia is not a valid string representation
// of an ISD-AS, Add panics.
func (g *Graph) Add(ia string) {
	g.lock.Lock()
	defer g.lock.Unlock()
	isdas := MustParseIA(ia)
	g.ases[isdas] = &AS{
		IFIDs: make(map[common.IFIDType]struct{}),
	}
}

// AddLink adds a new edge between the ASes described by xIA and yIA, with
// xIFID in xIA and yIFID in yIA. If xIA or yIA are not valid string
// representations of an ISD-AS, AddLink panics.
func (g *Graph) AddLink(xIA string, xIFID common.IFIDType,
	yIA string, yIFID common.IFIDType, peer bool) {

	g.lock.Lock()
	defer g.lock.Unlock()
	x := MustParseIA(xIA)
	y := MustParseIA(yIA)
	if _, ok := g.ases[x]; !ok {
		panic(fmt.Sprintf("AS %s not in graph", xIA))
	}
	if _, ok := g.ases[y]; !ok {
		panic(fmt.Sprintf("AS %s not in graph", yIA))
	}
	if _, ok := g.links[xIFID]; ok {
		panic(fmt.Sprintf("IFID %d is not unique", xIFID))
	}
	if _, ok := g.links[yIFID]; ok {
		panic(fmt.Sprintf("IFID %d is not unique", yIFID))
	}
	g.links[xIFID] = yIFID
	g.links[yIFID] = xIFID
	g.isPeer[xIFID] = peer
	g.isPeer[yIFID] = peer
	g.parents[xIFID] = x
	g.parents[yIFID] = y
	g.ases[x].IFIDs[xIFID] = struct{}{}
	g.ases[y].IFIDs[yIFID] = struct{}{}
}

// RemoveLink deletes the edge containing ifid from the graph.
func (g *Graph) RemoveLink(ifid common.IFIDType) {
	g.lock.Lock()
	defer g.lock.Unlock()
	ia := g.parents[ifid]
	neighborIFID := g.links[ifid]
	neighborIA := g.parents[neighborIFID]

	delete(g.links, ifid)
	delete(g.links, neighborIFID)
	delete(g.isPeer, ifid)
	delete(g.isPeer, neighborIFID)
	delete(g.parents, ifid)
	delete(g.parents, neighborIFID)
	g.ases[ia].Delete(ifid)
	g.ases[neighborIA].Delete(neighborIFID)
}

// GetParent returns the parent AS of ifid.
func (g *Graph) GetParent(ifid common.IFIDType) addr.IA {
	g.lock.Lock()
	defer g.lock.Unlock()
	return g.parents[ifid]
}

// GetPaths returns all the minimum-length paths. If xIA = yIA, a 1-length
// slice containing an empty path is returned. If no path exists between xIA
// and yIA, a 0-length slice is returned.
//
// Note that this always returns shortest length paths, even if they might not
// be valid SCION paths.
func (g *Graph) GetPaths(xIA string, yIA string) [][]common.IFIDType {
	g.lock.Lock()
	defer g.lock.Unlock()
	src := MustParseIA(xIA)
	dst := MustParseIA(yIA)
	solutionLength := 1000 // Infinity
	queue := []*solution{
		newSolution(src),
	}
	var solution [][]common.IFIDType
	for {
		if len(queue) == 0 {
			// Nothing left to explore.
			break
		}
		// Explore the next element in the queue.
		curSolution := queue[0]
		queue = queue[1:]

		if curSolution.Len() > solutionLength {
			break
		}

		// If we found the solution, save the length to stop exploring
		// longer paths.
		if curSolution.CurrentIA == dst {
			solutionLength = curSolution.Len()
			solution = append(solution, curSolution.trail)
			continue
		}

		// Explore neighboring ASes, if not visited yet.
		for ifid := range g.ases[curSolution.CurrentIA].IFIDs {
			nextIFID := g.links[ifid]
			nextIA := g.parents[nextIFID]
			if curSolution.Visited(nextIA) {
				continue
			}
			// Copy to avoid mutating the trails of other explorations.
			nextTrail := curSolution.Copy()
			nextTrail.Add(ifid, nextIFID, nextIA)
			nextTrail.CurrentIA = nextIA
			queue = append(queue, nextTrail)
		}
	}
	return solution
}

// Beacon constructs path segments across a series of egress ifids. The parent
// AS of the first IFID is the origin of the beacon, and the beacon propagates
// down to the parent AS of the remote counterpart of the last IFID. The
// constructed segment includes peering links. The hop fields in the returned
// segment do not contain valid MACs.
func (g *Graph) Beacon(ifids []common.IFIDType) *seg.PathSegment {
	var remoteInIF, inIF, outIF, remoteOutIF common.IFIDType
	var inIA, currIA, outIA addr.IA

	var segment *seg.PathSegment
	if len(ifids) == 0 {
		return segment
	}

	if _, ok := g.parents[ifids[0]]; !ok {
		panic(fmt.Sprintf("%d unknown ifid", ifids[0]))
	}

	segment, err := seg.NewSeg(
		&spath.InfoField{
			ISD: uint16(g.parents[ifids[0]].I),
		})
	if err != nil {
		panic(err)
	}

	currIA = g.parents[ifids[0]]
	for i := 0; i <= len(ifids); i++ {
		switch {
		case i < len(ifids):
			var ok bool
			outIF = ifids[i]
			if remoteOutIF, ok = g.links[outIF]; !ok {
				panic(fmt.Sprintf("%d unknown ifid", outIF))
			}
			outIA = g.parents[remoteOutIF]
		case i == len(ifids):
			outIF = 0
			remoteOutIF = 0
			outIA = addr.IA{}
		}

		asEntry := &seg.ASEntry{
			RawIA: currIA.IAInt(),
		}

		b := make(common.RawBytes, spath.HopFieldLength)
		spath.NewHopField(b, inIF, outIF, spath.DefaultHopFExpiry)
		localHopEntry := &seg.HopEntry{
			RawInIA:     inIA.IAInt(),
			RemoteInIF:  remoteInIF,
			InMTU:       1280,
			RawOutIA:    outIA.IAInt(),
			RemoteOutIF: remoteOutIF,
			RawHopField: b,
		}
		asEntry.HopEntries = append(asEntry.HopEntries, localHopEntry)

		as := g.ases[currIA]

		// use int to avoid implementing sort.Interface
		var ifids []int
		for peeringLocalIF := range as.IFIDs {
			ifids = append(ifids, int(peeringLocalIF))
		}
		sort.Ints(ifids)

		for _, intIFID := range ifids {
			peeringLocalIF := common.IFIDType(intIFID)
			if g.isPeer[peeringLocalIF] {
				b := make(common.RawBytes, spath.HopFieldLength)
				spath.NewHopField(b, peeringLocalIF, outIF, spath.DefaultHopFExpiry)
				peeringRemoteIF := g.links[peeringLocalIF]
				peeringIA := g.parents[peeringRemoteIF]
				peerHopEntry := &seg.HopEntry{
					RawInIA:     peeringIA.IAInt(),
					RemoteInIF:  peeringRemoteIF,
					InMTU:       1280,
					RawOutIA:    outIA.IAInt(),
					RemoteOutIF: remoteOutIF,
					RawHopField: b,
				}
				asEntry.HopEntries = append(asEntry.HopEntries, peerHopEntry)
			}
		}

		segment.AddASEntry(asEntry, proto.SignType_none, common.RawBytes{})
		remoteInIF = outIF
		inIF = remoteOutIF
		inIA = currIA
		currIA = g.parents[remoteOutIF]
	}
	return segment
}

// DeleteInterface removes ifid from the graph without deleting its remote
// counterpart. This is useful for testing IFID misconfigurations.
func (g *Graph) DeleteInterface(ifid common.IFIDType) {
	delete(g.links, ifid)
}

// AS contains a list of all the IFIDs in an AS.
type AS struct {
	IFIDs map[common.IFIDType]struct{}
}

// Delete removes ifid from as.
func (as *AS) Delete(ifid common.IFIDType) {
	if _, ok := as.IFIDs[ifid]; !ok {
		panic("ifid not found")
	}
	delete(as.IFIDs, ifid)
}

// solution tracks the state of a candidate solution for the graph
// exploration in graph.GetPaths.
type solution struct {
	// current AS in the exploration
	CurrentIA addr.IA
	// whether the AS has already been visited by this path, to avoid loops
	visited map[addr.IA]struct{}
	// the trail of IFIDs
	trail []common.IFIDType
}

func newSolution(start addr.IA) *solution {
	return &solution{
		visited:   map[addr.IA]struct{}{start: {}},
		CurrentIA: start,
	}
}

func (s *solution) Copy() *solution {
	newS := &solution{}
	newS.CurrentIA = s.CurrentIA
	newS.visited = make(map[addr.IA]struct{})
	for ia := range s.visited {
		newS.visited[ia] = struct{}{}
	}
	newS.trail = append([]common.IFIDType{}, s.trail...)
	return newS
}

func (s *solution) Visited(ia addr.IA) bool {
	_, ok := s.visited[ia]
	return ok
}

// Add appends localIFID and nextIFID to the trail, and advances to nextIA.
func (s *solution) Add(localIFID, nextIFID common.IFIDType, nextIA addr.IA) {
	s.visited[nextIA] = struct{}{}
	s.trail = append(s.trail, localIFID, nextIFID)
}

func (s *solution) Len() int {
	return len(s.trail) / 2
}

func MustParseIA(ia string) addr.IA {
	isdas, err := addr.IAFromString(ia)
	if err != nil {
		panic(err)
	}
	return isdas
}

// Description contains the entire specification of a graph. It is useful for
// one shot initilizations.
type Description struct {
	Nodes []string
	Edges []EdgeDesc
}

// EdgeDesc is used in Descriptions to describe the links between ASes.
type EdgeDesc struct {
	Xia   string
	Xifid common.IFIDType
	Yia   string
	Yifid common.IFIDType
	Peer  bool
}

// Graph description of the topology in doc/fig/default-topo.pdf.
// Comments mention root name for IFIDs.
var DefaultGraphDescription = &Description{
	Nodes: []string{
		"1-ff00:0:110", // 11
		"1-ff00:0:111", // 14
		"1-ff00:0:112", // 17
		"1-ff00:0:120", // 12
		"1-ff00:0:121", // 15
		"1-ff00:0:122", // 18
		"1-ff00:0:130", // 13
		"1-ff00:0:131", // 16
		"1-ff00:0:132", // 19
		"1-ff00:0:133", // 10
		"2-ff00:0:210", // 21
		"2-ff00:0:211", // 23
		"2-ff00:0:212", // 25
		"2-ff00:0:220", // 22
		"2-ff00:0:221", // 24
		"2-ff00:0:222", // 26
	},
	Edges: []EdgeDesc{
		{"1-ff00:0:110", 1112, "1-ff00:0:120", 1211, false},
		{"1-ff00:0:110", 1113, "1-ff00:0:130", 1311, false},
		{"1-ff00:0:110", 1121, "2-ff00:0:210", 2111, false},
		{"1-ff00:0:110", 1114, "1-ff00:0:111", 1411, false},
		{"1-ff00:0:120", 1213, "1-ff00:0:130", 1312, false},
		{"1-ff00:0:120", 1222, "2-ff00:0:220", 2212, false},
		{"1-ff00:0:120", 1215, "1-ff00:0:121", 1512, false},
		{"1-ff00:0:130", 1316, "1-ff00:0:131", 1613, false},
		{"1-ff00:0:111", 1415, "1-ff00:0:121", 1514, true},
		{"1-ff00:0:111", 1423, "2-ff00:0:211", 2314, true},
		{"1-ff00:0:111", 1417, "1-ff00:0:112", 1714, false},
		{"1-ff00:0:121", 1516, "1-ff00:0:131", 1615, true},
		{"1-ff00:0:121", 1518, "1-ff00:0:122", 1815, false},
		{"1-ff00:0:131", 1619, "1-ff00:0:132", 1916, false},
		{"1-ff00:0:132", 1910, "1-ff00:0:133", 1019, false},
		{"2-ff00:0:210", 2122, "2-ff00:0:220", 2221, false},
		{"2-ff00:0:210", 2123, "2-ff00:0:211", 2321, false},
		{"2-ff00:0:220", 2224, "2-ff00:0:221", 2422, false},
		{"2-ff00:0:211", 2324, "2-ff00:0:221", 2423, true},
		{"2-ff00:0:211", 2325, "2-ff00:0:212", 2523, false},
		{"2-ff00:0:211", 2326, "2-ff00:0:222", 2623, false},
		{"2-ff00:0:221", 2426, "2-ff00:0:222", 2624, false},
	},
}

func NewDefaultGraph() *Graph {
	return NewFromDescription(DefaultGraphDescription)
}
