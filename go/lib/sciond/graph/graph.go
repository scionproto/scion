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

// Package graph implements a multigraph model of a SCION network for use in
// tests. The default Mock SCIOND implementation uses the graph to simulate
// path lookups.
package graph

import (
	"fmt"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
)

// Graph implements a graph of ASes and IFIDs for testing purposes. IFIDs
// must be globally unique.
//
// Nodes are represented by ASes.
//
// Edges are represented by pairs of IFIDs.
type Graph struct {
	// maps IFIDs to the other IFID of the edge
	ifids map[uint64]uint64
	// maps IFIDs to the AS they belong to
	parents map[uint64]addr.IA
	// maps ASes to a structure containing a slice of their IFIDs
	ases map[addr.IA]*AS

	lock sync.Mutex
}

// New allocates a new empty graph.
func New() *Graph {
	return &Graph{
		ifids:   make(map[uint64]uint64),
		parents: make(map[uint64]addr.IA),
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
		graph.Connect(edge.xIA, edge.xIFID, edge.yIA, edge.yIFID)
	}
	return graph
}

// Add adds a new node to the graph. If ia is not a valid string representation
// of an ISD-AS, Add panics.
func (g *Graph) Add(ia string) {
	g.lock.Lock()
	defer g.lock.Unlock()
	isdas := MustParseIA(ia)
	g.ases[isdas] = &AS{}
}

// Connect adds a new edge between the ASes described by xIA and yIA, with
// xIFID in xIA and yIFID in yIA. If xIA or yIA are not valid string
// representations of an ISD-AS, Connect panics.
func (g *Graph) Connect(xIA string, xIFID uint64, yIA string, yIFID uint64) {
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
	g.ifids[xIFID] = yIFID
	g.ifids[yIFID] = xIFID
	g.parents[xIFID] = x
	g.parents[yIFID] = y
	g.ases[x].IFIDs = append(g.ases[x].IFIDs, xIFID)
	g.ases[y].IFIDs = append(g.ases[y].IFIDs, yIFID)
}

// Disconnect deletes the edge containing ifid from the graph.
func (g *Graph) Disconnect(ifid uint64) {
	g.lock.Lock()
	defer g.lock.Unlock()
	ia := g.parents[ifid]
	neighborIFID := g.ifids[ifid]
	neighborIA := g.parents[neighborIFID]

	delete(g.ifids, ifid)
	delete(g.ifids, neighborIFID)
	delete(g.parents, ifid)
	delete(g.parents, neighborIFID)
	g.ases[ia].Delete(ifid)
	g.ases[neighborIA].Delete(neighborIFID)
}

// GetParent returns the parent AS of ifid.
func (g *Graph) GetParent(ifid uint64) addr.IA {
	g.lock.Lock()
	defer g.lock.Unlock()
	return g.parents[ifid]
}

// GetPaths returns all the minimum-length paths. If xIA = yIA, a 1-length
// slice containing an empty path is returned. If no path exists between xIA
// and yIA, a 0-length slice is returned.
func (g *Graph) GetPaths(xIA string, yIA string) [][]uint64 {
	g.lock.Lock()
	defer g.lock.Unlock()
	src := MustParseIA(xIA)
	dst := MustParseIA(yIA)
	solutionLength := 1000 // Infinity
	visitTrailQueue := []*testVisitTrail{
		newTestVisitTrail(src),
	}
	solutionTrails := []*testVisitTrail{}
	for {
		if len(visitTrailQueue) == 0 {
			// Nothing left to explore.
			break
		}
		// Explore the next element in the queue.
		currentTrail := visitTrailQueue[0]
		visitTrailQueue = visitTrailQueue[1:]

		if currentTrail.Len() > solutionLength {
			break
		}

		// If we found the solution, save the length to stop exploring
		// longer paths.
		if currentTrail.currentIA == dst {
			solutionLength = currentTrail.Len()
			solutionTrails = append(solutionTrails, currentTrail)
			continue
		}

		// Explore neighboring ASes, if not visited yet.
		for _, ifid := range g.ases[currentTrail.Current()].IFIDs {
			nextIFID := g.ifids[ifid]
			nextIA := g.parents[nextIFID]
			if currentTrail.Visited(nextIA) {
				continue
			}
			// Copy to avoid mutating the trails of other explorations.
			nextTrail := currentTrail.Copy()
			nextTrail.Add(ifid, nextIFID, nextIA)
			nextTrail.SetCurrent(nextIA)
			visitTrailQueue = append(visitTrailQueue, nextTrail)
		}
	}

	// Return only the IFIDs.
	var solutions [][]uint64
	for _, s := range solutionTrails {
		solutions = append(solutions, s.trail)
	}
	return solutions
}

// AS contains a list of all the IFIDs in an AS.
type AS struct {
	IFIDs []uint64
}

// Delete removes ifid from as.
func (as *AS) Delete(ifid uint64) {
	for idx, iter := range as.IFIDs {
		if iter == ifid {
			as.IFIDs = append(as.IFIDs[0:idx], as.IFIDs[idx+1:]...)
			return
		}
	}
	panic("ifid not found")
}

// testVisitTrail tracks the state of a candidate solution for the graph
// exploration in graph.GetPaths.
type testVisitTrail struct {
	// current AS in the exploration
	currentIA addr.IA
	// whether the AS has already been visited by this path, to avoid loops
	visited map[addr.IA]bool
	// the trail of IFIDs
	trail []uint64
}

func newTestVisitTrail(start addr.IA) *testVisitTrail {
	return &testVisitTrail{
		visited:   map[addr.IA]bool{start: true},
		currentIA: start,
	}
}

func (trail *testVisitTrail) Copy() *testVisitTrail {
	newTrail := &testVisitTrail{}
	newTrail.currentIA = trail.currentIA
	newTrail.visited = make(map[addr.IA]bool)
	for ia, b := range trail.visited {
		newTrail.visited[ia] = b
	}
	newTrail.trail = append([]uint64{}, trail.trail...)
	return newTrail
}

func (trail *testVisitTrail) Visited(ia addr.IA) bool {
	return trail.visited[ia]
}

func (trail *testVisitTrail) Current() addr.IA {
	return trail.currentIA
}

func (trail *testVisitTrail) SetCurrent(ia addr.IA) {
	trail.currentIA = ia
}

// Add appends localIFID and nextIFID to the trail, and advances to nextIA.
func (trail *testVisitTrail) Add(localIFID, nextIFID uint64, nextIA addr.IA) {
	trail.visited[nextIA] = true
	trail.trail = append(trail.trail, localIFID, nextIFID)
}

func (trail *testVisitTrail) Len() int {
	return len(trail.trail) / 2
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
	Edges []DescriptionEdge
}

// DescriptionEdge is used in Descriptions to describe the links between ASes.
type DescriptionEdge struct {
	xIA   string
	xIFID uint64
	yIA   string
	yIFID uint64
}

// Graph description of the topology in doc/fig/default-topo.pdf.
var DefaultGraphDescription = &Description{
	Nodes: []string{"1-10", "1-11", "1-12", "1-13", "1-14", "1-15", "1-16", "1-17", "1-18",
		"1-19", "2-20", "2-21", "2-22", "2-23", "2-24", "2-25", "2-26"},
	Edges: []DescriptionEdge{
		// Non-core ISD 1
		{"1-10", 1019, "1-19", 1910},
		{"1-11", 1114, "1-14", 1411},
		{"1-12", 1215, "1-15", 1512},
		{"1-13", 1316, "1-16", 1613},
		{"1-14", 1417, "1-17", 1714},
		{"1-15", 1518, "1-18", 1815},
		{"1-16", 1619, "1-19", 1916},
		// Core ISD 1
		{"1-11", 1112, "1-12", 1211},
		{"1-11", 1113, "1-13", 1311},
		{"1-12", 1213, "1-13", 1312},
		// Non-core ISD 2
		{"2-21", 2123, "2-23", 2321},
		{"2-22", 2224, "2-24", 2422},
		{"2-23", 2325, "2-25", 2523},
		{"2-23", 2326, "2-26", 2623},
		{"2-24", 2426, "2-26", 2624},
		// Core ISD 2
		{"2-21", 2122, "2-22", 2221},
		// Inter-Core
		{"1-11", 1121, "2-21", 2111},
		{"1-12", 1222, "2-22", 2212},
		// Peering links
		{"1-14", 1415, "1-15", 1514},
		{"1-14", 1423, "2-23", 2314},
		{"1-15", 1516, "1-16", 1615},
		{"2-23", 2324, "2-24", 2324},
	},
}
