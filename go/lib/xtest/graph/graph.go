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
//
// Note that the graph always returns the shortest paths, regardless whether
// they are valid SCION paths (e.g., the path might cross multiple peering
// links).
package graph

import (
	"fmt"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
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
		graph.AddLink(edge.Xia, edge.Xifid, edge.Yia, edge.Yifid)
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
func (g *Graph) AddLink(xIA string, xIFID common.IFIDType, yIA string, yIFID common.IFIDType) {
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
}

// Graph description of the topology in doc/fig/default-topo.pdf.
var DefaultGraphDescription = &Description{
	Nodes: []string{
		"1-ff00:0:110", "1-ff00:0:111", "1-ff00:0:112",
		"1-ff00:0:120", "1-ff00:0:121", "1-ff00:0:122",
		"1-ff00:0:130", "1-ff00:0:131", "1-ff00:0:132", "1-ff00:0:133",
		"2-ff00:0:210", "2-ff00:0:211", "2-ff00:0:212",
		"2-ff00:0:220", "2-ff00:0:221", "2-ff00:0:222",
	},
	Edges: []EdgeDesc{
		{"1-ff00:0:110", 110120, "1-ff00:0:120", 120110},
		{"1-ff00:0:110", 110130, "1-ff00:0:130", 130110},
		{"1-ff00:0:110", 110210, "2-ff00:0:210", 210110},
		{"1-ff00:0:110", 110111, "1-ff00:0:111", 111110},
		{"1-ff00:0:120", 120130, "1-ff00:0:130", 130120},
		{"1-ff00:0:120", 120220, "2-ff00:0:220", 220120},
		{"1-ff00:0:120", 120121, "1-ff00:0:121", 121120},
		{"1-ff00:0:130", 130131, "1-ff00:0:131", 131130},
		{"1-ff00:0:111", 111121, "1-ff00:0:121", 121111},
		{"1-ff00:0:111", 111211, "2-ff00:0:211", 211111},
		{"1-ff00:0:111", 111112, "1-ff00:0:112", 112111},
		{"1-ff00:0:121", 121131, "1-ff00:0:131", 131121},
		{"1-ff00:0:121", 121122, "1-ff00:0:122", 122121},
		{"1-ff00:0:131", 131132, "1-ff00:0:132", 132131},
		{"1-ff00:0:132", 132133, "1-ff00:0:133", 133132},
		{"2-ff00:0:210", 210220, "2-ff00:0:220", 220210},
		{"2-ff00:0:210", 210211, "2-ff00:0:211", 211210},
		{"2-ff00:0:220", 220221, "2-ff00:0:221", 221220},
		{"2-ff00:0:211", 211221, "2-ff00:0:221", 221211},
		{"2-ff00:0:211", 211212, "2-ff00:0:212", 212211},
		{"2-ff00:0:211", 211222, "2-ff00:0:222", 222211},
		{"2-ff00:0:221", 221222, "2-ff00:0:222", 222221},
	},
}

func NewDefaultGraph() *Graph {
	return NewFromDescription(DefaultGraphDescription)
}
