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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/ctrl/seg/extensions/staticinfo"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
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

	signers map[addr.IA]Signer

	ctrl *gomock.Controller
	lock sync.Mutex
}

// New allocates a new empty graph.
func New(ctrl *gomock.Controller) *Graph {
	return &Graph{
		ctrl:    ctrl,
		links:   make(map[common.IFIDType]common.IFIDType),
		isPeer:  make(map[common.IFIDType]bool),
		parents: make(map[common.IFIDType]addr.IA),
		ases:    make(map[addr.IA]*AS),
		signers: make(map[addr.IA]Signer),
	}
}

// NewFromDescription initializes a new graph from description desc.
func NewFromDescription(ctrl *gomock.Controller, desc *Description) *Graph {
	graph := New(ctrl)
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
	g.signers[isdas] = NewSigner()
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
	return g.beacon(ifids, false)
}

func (g *Graph) BeaconWithStaticInfo(ifids []common.IFIDType) *seg.PathSegment {
	return g.beacon(ifids, true)
}

// beacon constructs path segments across a series of egress ifids. The parent
// AS of the first IFID is the origin of the beacon, and the beacon propagates
// down to the parent AS of the remote counterpart of the last IFID. The
// constructed segment includes peering links. The hop fields in the returned
// segment do not contain valid MACs.
func (g *Graph) beacon(ifids []common.IFIDType, addStaticInfo bool) *seg.PathSegment {
	var inIF, outIF, remoteOutIF common.IFIDType
	var currIA, outIA addr.IA

	var segment *seg.PathSegment
	if len(ifids) == 0 {
		return segment
	}

	if _, ok := g.parents[ifids[0]]; !ok {
		panic(fmt.Sprintf("%d unknown ifid", ifids[0]))
	}

	segment, err := seg.CreateSegment(time.Now(), uint16(rand.Int()))
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

		asEntry := seg.ASEntry{
			Local: currIA,
			Next:  outIA,
			MTU:   2000,
			HopEntry: seg.HopEntry{
				HopField: seg.HopField{
					ExpTime:     63,
					ConsIngress: uint16(inIF),
					ConsEgress:  uint16(outIF),
					MAC:         bytes.Repeat([]byte{uint8(i)}, 6),
				},
				IngressMTU: 1280,
			},
		}

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
				peeringRemoteIF := g.links[peeringLocalIF]
				asEntry.PeerEntries = append(asEntry.PeerEntries, seg.PeerEntry{
					Peer:          g.parents[peeringRemoteIF],
					PeerInterface: uint16(peeringRemoteIF),
					PeerMTU:       1280,
					HopField: seg.HopField{
						ExpTime:     63,
						ConsIngress: uint16(peeringLocalIF),
						ConsEgress:  uint16(outIF),
						MAC:         bytes.Repeat([]byte{uint8(i)}, 6),
					},
				})
			}
		}
		if addStaticInfo {
			asEntry.Extensions.StaticInfo = generateStaticInfo(g, currIA, inIF, outIF)
		}
		segment.AddASEntry(context.Background(), asEntry, g.signers[currIA])
		inIF = remoteOutIF
		currIA = g.parents[remoteOutIF]
	}
	return segment
}

// DeleteInterface removes ifid from the graph without deleting its remote
// counterpart. This is useful for testing IFID misconfigurations.
func (g *Graph) DeleteInterface(ifid common.IFIDType) {
	delete(g.links, ifid)
}

// Latency returns an arbitrary test latency value between two interfaces. The
// interfaces should either be part of the same AS, in which case the intra-AS
// latency is returned, or they should form a link of the graph. Otherwise,
// this panics.
// The value returned is symmetric, i.e. g.Latency(a, b) == g.Latency(b, a)
func (g *Graph) Latency(a, b common.IFIDType) time.Duration {
	sameIA := (g.parents[a] == g.parents[b])
	if !sameIA && g.links[a] != b {
		panic("interfaces must be in the same AS or connected by a link")
	}

	d := time.Microsecond * time.Duration(a*b*11939%10000) // value in 0-10ms
	if sameIA {
		return d
	}
	return d + 10*time.Millisecond // value in 10-20ms
}

// Bandwidth returns an arbitrary test bandwidth value between two interfaces.
// Analogous to Latency.
func (g *Graph) Bandwidth(a, b common.IFIDType) uint64 {
	sameIA := (g.parents[a] == g.parents[b])
	if !sameIA && g.links[a] != b {
		panic("interfaces must be in the same AS or connected by a link")
	}

	return 1000 * uint64(a*b*11939%10000) // value in 0-10_000_000kbps, 0-10Gbps
}

// GeoCoordinates returns an arbitrary test GeoCoordinate for the interface
func (g *Graph) GeoCoordinates(ifid common.IFIDType) staticinfo.GeoCoordinates {
	ia, ok := g.parents[ifid]
	if !ok {
		panic("unknown interface")
	}
	return staticinfo.GeoCoordinates{
		Latitude:  float32(ifid),
		Longitude: float32(ifid),
		Address:   fmt.Sprintf("Location %s#%d", ia, ifid),
	}
}

// LinkType returns an arbitrary test link type value for an inter-AS link.
// Only for inter-AS links, otherwise analogous to Latency.
func (g *Graph) LinkType(a, b common.IFIDType) staticinfo.LinkType {
	if g.links[a] != b {
		panic("interfaces must be connected by a link")
	}

	return staticinfo.LinkType(a * b % 3)
}

// InternalHops returns an arbitrary number of internal hops value between two
// interfaces of an AS.
func (g *Graph) InternalHops(a, b common.IFIDType) uint32 {
	if g.parents[a] != g.parents[b] {
		panic("interfaces must be in the same AS")
	}
	return uint32(a * b % 10)
}

type Signer struct {
	PrivateKey crypto.Signer
}

func NewSigner() Signer {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		panic(err)
	}
	return Signer{
		PrivateKey: priv,
	}
}

func (s Signer) Sign(ctx context.Context, msg []byte,
	associatedData ...[]byte) (*cryptopb.SignedMessage, error) {

	var l int
	for _, d := range associatedData {
		l += len(d)
	}
	hdr := signed.Header{
		SignatureAlgorithm:   signed.ECDSAWithSHA256,
		AssociatedDataLength: l,
	}

	return signed.Sign(hdr, msg, s.PrivateKey, associatedData...)
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
	if s == nil {
		return nil
	}
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

func NewDefaultGraph(ctrl *gomock.Controller) *Graph {
	return NewFromDescription(ctrl, DefaultGraphDescription)
}

// generateStaticInfo is used during mock beaconing. It takes any interface of the AS
// that is doing the beaconing as well as the egress interface for that beacon.
// It then uses that interface to generate characteristic StaticInfo for said interface,
// such that testcases can be written by looking only at the interfaces
// that send/receive beacons across the path.
// Characteristic StaticInfo is generated by simply taking the ifID of the interface and
// converting it to a format that fits the kind of StaticInfo that is being stored
// (e.g. typecast to uint16 for Latency). With this method, the StaticInfo for every
// interface has a unique value.
// The egress interface plays a special role, since it is used to generate ingress
// to egress metrics. Therefore for ASes that are neither the first nor the last on a
// path segment, looking only at the egress interface on which the beacon left the AS
// is sufficient when writing tests.
func generateStaticInfo(g *Graph, ia addr.IA,
	inIF, outIF common.IFIDType) *staticinfo.Extension {

	as := g.ases[ia]

	latency := staticinfo.LatencyInfo{}
	if outIF != 0 {
		latency.Intra = make(map[common.IFIDType]time.Duration)
		latency.Inter = make(map[common.IFIDType]time.Duration)
		for ifid := range as.IFIDs {
			if ifid != outIF {
				// Note: the test graph does not distinguish between parent/child or
				// core interfaces.
				// Otherwise, we could skip the parent interfaces and half of the
				// sibling interfaces here.
				latency.Intra[ifid] = g.Latency(ifid, outIF)
			}
			if ifid == outIF || g.isPeer[ifid] {
				latency.Inter[ifid] = g.Latency(ifid, g.links[ifid])
			}
		}
	}

	bandwidth := staticinfo.BandwidthInfo{}
	if outIF != 0 {
		bandwidth.Intra = make(map[common.IFIDType]uint64)
		bandwidth.Inter = make(map[common.IFIDType]uint64)
		for ifid := range as.IFIDs {
			if ifid != outIF {
				bandwidth.Intra[ifid] = g.Bandwidth(ifid, outIF)
			}
			if ifid == outIF || g.isPeer[ifid] {
				bandwidth.Inter[ifid] = g.Bandwidth(ifid, g.links[ifid])
			}
		}
	}

	geo := make(staticinfo.GeoInfo)
	for ifid := range as.IFIDs {
		geo[ifid] = g.GeoCoordinates(ifid)
	}

	linkType := make(staticinfo.LinkTypeInfo)
	for ifid := range as.IFIDs {
		linkType[ifid] = g.LinkType(ifid, g.links[ifid])
	}

	var internalHops staticinfo.InternalHopsInfo
	if outIF != 0 {
		internalHops = make(map[common.IFIDType]uint32)
		if inIF != 0 {
			internalHops[inIF] = g.InternalHops(inIF, outIF)
		}
		for ifid := range as.IFIDs {
			if ifid != outIF && ifid != inIF {
				internalHops[ifid] = g.InternalHops(ifid, outIF)
			}
		}
	}

	return &staticinfo.Extension{
		Latency:      latency,
		Bandwidth:    bandwidth,
		Geo:          geo,
		LinkType:     linkType,
		InternalHops: internalHops,
		Note:         fmt.Sprintf("Note %s", ia),
	}
}
