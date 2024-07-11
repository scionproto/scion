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
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	seg "github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/segment/extensions/staticinfo"
	"github.com/scionproto/scion/pkg/slayers/path"
)

// Graph implements a graph of ASes and IFIDs for testing purposes. IFIDs
// must be globally unique.
//
// Nodes are represented by ASes.
//
// Edges are represented by pairs of IFIDs.
type Graph struct {
	// maps IFIDs to the other IFID of the edge
	links map[uint16]uint16
	// specifies whether an IFID is on a peering link
	isPeer map[uint16]bool
	// maps IFIDs to the AS they belong to
	parents map[uint16]addr.IA
	// maps ASes to a structure containing a slice of their IFIDs
	ases map[addr.IA]*AS

	signers map[addr.IA]*Signer

	ctrl *gomock.Controller
	lock sync.Mutex
}

// New allocates a new empty graph.
func New(ctrl *gomock.Controller) *Graph {
	return &Graph{
		ctrl:    ctrl,
		links:   make(map[uint16]uint16),
		isPeer:  make(map[uint16]bool),
		parents: make(map[uint16]addr.IA),
		ases:    make(map[addr.IA]*AS),
		signers: make(map[addr.IA]*Signer),
	}
}

// NewFromDescription initializes a new graph from description desc.
func NewFromDescription(ctrl *gomock.Controller, desc *Description) *Graph {
	graph := New(ctrl)
	for _, node := range desc.Nodes {
		graph.Add(node)
	}
	for _, edge := range desc.Edges {
		graph.AddLink(edge.Xia, edge.XifId, edge.Yia, edge.YifId, edge.Peer)
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
		IFIDs: make(map[uint16]struct{}),
	}
	g.signers[isdas] = NewSigner(
		WithIA(isdas),
		WithTRCID(cppki.TRCID{
			ISD:    isdas.ISD(),
			Serial: 1,
			Base:   1,
		}),
	)
}

// GetSigner returns the signer for the ISD-AS.
func (g *Graph) GetSigner(ia string) *Signer {
	g.lock.Lock()
	defer g.lock.Unlock()
	return g.signers[MustParseIA(ia)]
}

// AddLink adds a new edge between the ASes described by xIA and yIA, with
// xIFID in xIA and yIFID in yIA. If xIA or yIA are not valid string
// representations of an ISD-AS, AddLink panics.
func (g *Graph) AddLink(xIA string, xIFID uint16,
	yIA string, yIFID uint16, peer bool) {

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

// RemoveLink deletes the edge containing ifId from the graph.
func (g *Graph) RemoveLink(ifId uint16) {
	g.lock.Lock()
	defer g.lock.Unlock()
	ia := g.parents[ifId]
	neighborIFID := g.links[ifId]
	neighborIA := g.parents[neighborIFID]

	delete(g.links, ifId)
	delete(g.links, neighborIFID)
	delete(g.isPeer, ifId)
	delete(g.isPeer, neighborIFID)
	delete(g.parents, ifId)
	delete(g.parents, neighborIFID)
	g.ases[ia].Delete(ifId)
	g.ases[neighborIA].Delete(neighborIFID)
}

// GetParent returns the parent AS of ifId.
func (g *Graph) GetParent(ifId uint16) addr.IA {
	g.lock.Lock()
	defer g.lock.Unlock()
	return g.parents[ifId]
}

// GetPaths returns all the minimum-length paths. If xIA = yIA, a 1-length
// slice containing an empty path is returned. If no path exists between xIA
// and yIA, a 0-length slice is returned.
//
// Note that this always returns shortest length paths, even if they might not
// be valid SCION paths.
func (g *Graph) GetPaths(xIA string, yIA string) [][]uint16 {
	g.lock.Lock()
	defer g.lock.Unlock()
	src := MustParseIA(xIA)
	dst := MustParseIA(yIA)
	solutionLength := 1000 // Infinity
	queue := []*solution{
		newSolution(src),
	}
	var solution [][]uint16
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
		for ifId := range g.ases[curSolution.CurrentIA].IFIDs {
			nextIFID := g.links[ifId]
			nextIA := g.parents[nextIFID]
			if curSolution.Visited(nextIA) {
				continue
			}
			// Copy to avoid mutating the trails of other explorations.
			nextTrail := curSolution.Copy()
			nextTrail.Add(ifId, nextIFID, nextIA)
			nextTrail.CurrentIA = nextIA
			queue = append(queue, nextTrail)
		}
	}
	return solution
}

// Beacon constructs path segments across a series of egress ifIds. The parent
// AS of the first IFID is the origin of the beacon, and the beacon propagates
// down to the parent AS of the remote counterpart of the last IFID. The
// constructed segment includes peering links. The hop fields in the returned
// segment do not contain valid MACs.
func (g *Graph) Beacon(ifIds []uint16) *seg.PathSegment {
	return g.beacon(ifIds, false)
}

func (g *Graph) BeaconWithStaticInfo(ifIds []uint16) *seg.PathSegment {
	return g.beacon(ifIds, true)
}

// beacon constructs path segments across a series of egress ifIds. The parent
// AS of the first IFID is the origin of the beacon, and the beacon propagates
// down to the parent AS of the remote counterpart of the last IFID. The
// constructed segment includes peering links. The hop fields in the returned
// segment do not contain valid MACs.
func (g *Graph) beacon(ifIds []uint16, addStaticInfo bool) *seg.PathSegment {
	var inIF, outIF, remoteOutIF uint16
	var currIA, outIA addr.IA

	var segment *seg.PathSegment
	if len(ifIds) == 0 {
		return segment
	}

	if _, ok := g.parents[ifIds[0]]; !ok {
		panic(fmt.Sprintf("%d unknown ifId", ifIds[0]))
	}

	segment, err := seg.CreateSegment(time.Now(), uint16(rand.Int()))
	if err != nil {
		panic(err)
	}

	currIA = g.parents[ifIds[0]]
	for i := 0; i <= len(ifIds); i++ {
		switch {
		case i < len(ifIds):
			var ok bool
			outIF = ifIds[i]
			if remoteOutIF, ok = g.links[outIF]; !ok {
				panic(fmt.Sprintf("%d unknown ifId", outIF))
			}
			outIA = g.parents[remoteOutIF]
		case i == len(ifIds):
			outIF = 0
			remoteOutIF = 0
			outIA = 0
		}

		mac := [path.MacLen]byte{byte(i)}
		asEntry := seg.ASEntry{
			Local: currIA,
			Next:  outIA,
			MTU:   2000,
			HopEntry: seg.HopEntry{
				HopField: seg.HopField{
					ExpTime:     63,
					ConsIngress: inIF,
					ConsEgress:  outIF,
					MAC:         mac,
				},
				IngressMTU: 1280,
			},
		}

		as := g.ases[currIA]

		// use int to avoid implementing sort.Interface
		var ifIds []int
		for peeringLocalIF := range as.IFIDs {
			ifIds = append(ifIds, int(peeringLocalIF))
		}
		sort.Ints(ifIds)

		for _, intIFID := range ifIds {
			peeringLocalIF := uint16(intIFID)
			if g.isPeer[peeringLocalIF] {
				peeringRemoteIF := g.links[peeringLocalIF]
				asEntry.PeerEntries = append(asEntry.PeerEntries, seg.PeerEntry{
					Peer:          g.parents[peeringRemoteIF],
					PeerInterface: peeringRemoteIF,
					PeerMTU:       1280,
					HopField: seg.HopField{
						ExpTime:     63,
						ConsIngress: peeringLocalIF,
						ConsEgress:  outIF,
						MAC:         mac,
					},
				})
			}
		}
		if addStaticInfo {
			asEntry.Extensions.StaticInfo = generateStaticInfo(g, currIA, inIF, outIF)
		}
		if err := segment.AddASEntry(context.Background(), asEntry, g.signers[currIA]); err != nil {
			panic(serrors.WrapStr("adding AS entry", err))
		}
		inIF = remoteOutIF
		currIA = g.parents[remoteOutIF]
	}
	return segment
}

// DeleteInterface removes ifId from the graph without deleting its remote
// counterpart. This is useful for testing IFID misconfigurations.
func (g *Graph) DeleteInterface(ifId uint16) {
	delete(g.links, ifId)
}

// Latency returns an arbitrary test latency value between two interfaces. The
// interfaces should either be part of the same AS, in which case the intra-AS
// latency is returned, or they should form a link of the graph. Otherwise,
// this panics.
// The value returned is symmetric, i.e. g.Latency(a, b) == g.Latency(b, a)
func (g *Graph) Latency(a, b uint16) time.Duration {
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
func (g *Graph) Bandwidth(a, b uint16) uint64 {
	sameIA := (g.parents[a] == g.parents[b])
	if !sameIA && g.links[a] != b {
		panic("interfaces must be in the same AS or connected by a link")
	}

	return 1000 * uint64(a*b*11939%10000) // value in 0-10_000_000kbps, 0-10Gbps
}

// GeoCoordinates returns an arbitrary test GeoCoordinate for the interface
func (g *Graph) GeoCoordinates(ifId uint16) staticinfo.GeoCoordinates {
	ia, ok := g.parents[ifId]
	if !ok {
		panic("unknown interface")
	}
	return staticinfo.GeoCoordinates{
		Latitude:  float32(ifId),
		Longitude: float32(ifId),
		Address:   fmt.Sprintf("Location %s#%d", ia, ifId),
	}
}

// LinkType returns an arbitrary test link type value for an inter-AS link.
// Only for inter-AS links, otherwise analogous to Latency.
func (g *Graph) LinkType(a, b uint16) staticinfo.LinkType {
	if g.links[a] != b {
		panic("interfaces must be connected by a link")
	}

	return staticinfo.LinkType(a * b % 3)
}

// InternalHops returns an arbitrary number of internal hops value between two
// interfaces of an AS.
func (g *Graph) InternalHops(a, b uint16) uint32 {
	if g.parents[a] != g.parents[b] {
		panic("interfaces must be in the same AS")
	}
	return uint32(a * b % 10)
}

// SignerOption allows customizing the generated Signer.
type SignerOption func(o *Signer)

// WithPrivateKey customizes the private key for the Signer.
func WithPrivateKey(key crypto.Signer) SignerOption {
	return func(o *Signer) {
		o.PrivateKey = key
	}
}

// WithIA customizes the ISD-AS for the Signer.
func WithIA(ia addr.IA) SignerOption {
	return func(o *Signer) {
		o.IA = ia
	}
}

// WithTRCID customizes the TRCID for the Signer.
func WithTRCID(trcID cppki.TRCID) SignerOption {
	return func(o *Signer) {
		o.TRCID = trcID
	}
}

// WithTimestamp customizes the signature timestamp for the Signer.
func WithTimestamp(ts time.Time) SignerOption {
	return func(o *Signer) {
		o.Timestamp = ts
	}
}

type Signer struct {
	PrivateKey crypto.Signer
	// Timestamp is the timestamp that this signer is bound to. If it is set,
	// all signatures are created with this timestamp. If it is not set, the
	// current time is used for the signature timestamp.
	Timestamp time.Time
	IA        addr.IA
	TRCID     cppki.TRCID
}

func NewSigner(opts ...SignerOption) *Signer {
	var s Signer
	for _, opt := range opts {
		opt(&s)
	}
	if s.PrivateKey == nil {
		var err error
		s.PrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
		if err != nil {
			panic(err)
		}
	}
	return &s
}

func (s Signer) Sign(ctx context.Context, msg []byte,
	associatedData ...[]byte) (*cryptopb.SignedMessage, error) {

	var l int
	for _, d := range associatedData {
		l += len(d)
	}
	ts := s.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	skid, err := cppki.SubjectKeyID(s.PrivateKey.Public())
	if err != nil {
		return nil, err
	}

	id := &cppb.VerificationKeyID{
		IsdAs:        uint64(s.IA),
		TrcBase:      uint64(s.TRCID.Base),
		TrcSerial:    uint64(s.TRCID.Serial),
		SubjectKeyId: skid,
	}
	rawID, err := proto.Marshal(id)
	if err != nil {
		return nil, err
	}

	hdr := signed.Header{
		SignatureAlgorithm:   signed.ECDSAWithSHA256,
		AssociatedDataLength: l,
		Timestamp:            ts,
		VerificationKeyID:    rawID,
	}

	return signed.Sign(hdr, msg, s.PrivateKey, associatedData...)
}

// AS contains a list of all the IFIDs in an AS.
type AS struct {
	IFIDs map[uint16]struct{}
}

// Delete removes ifId from as.
func (as *AS) Delete(ifId uint16) {
	if _, ok := as.IFIDs[ifId]; !ok {
		panic("ifId not found")
	}
	delete(as.IFIDs, ifId)
}

// solution tracks the state of a candidate solution for the graph
// exploration in graph.GetPaths.
type solution struct {
	// current AS in the exploration
	CurrentIA addr.IA
	// whether the AS has already been visited by this path, to avoid loops
	visited map[addr.IA]struct{}
	// the trail of IFIDs
	trail []uint16
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
	newS.trail = append([]uint16{}, s.trail...)
	return newS
}

func (s *solution) Visited(ia addr.IA) bool {
	_, ok := s.visited[ia]
	return ok
}

// Add appends localIFID and nextIFID to the trail, and advances to nextIA.
func (s *solution) Add(localIFID, nextIFID uint16, nextIA addr.IA) {
	s.visited[nextIA] = struct{}{}
	s.trail = append(s.trail, localIFID, nextIFID)
}

func (s *solution) Len() int {
	return len(s.trail) / 2
}

func MustParseIA(ia string) addr.IA {
	isdas, err := addr.ParseIA(ia)
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
	XifId uint16
	Yia   string
	YifId uint16
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
// Characteristic StaticInfo is generated by simply taking the ifId of the interface and
// converting it to a format that fits the kind of StaticInfo that is being stored
// (e.g. typecast to uint16 for Latency). With this method, the StaticInfo for every
// interface has a unique value.
// The egress interface plays a special role, since it is used to generate ingress
// to egress metrics. Therefore for ASes that are neither the first nor the last on a
// path segment, looking only at the egress interface on which the beacon left the AS
// is sufficient when writing tests.
func generateStaticInfo(g *Graph, ia addr.IA, inIF, outIF uint16) *staticinfo.Extension {
	as := g.ases[ia]

	latency := staticinfo.LatencyInfo{}
	if outIF != 0 {
		latency.Intra = make(map[common.IfIdType]time.Duration)
		latency.Inter = make(map[common.IfIdType]time.Duration)
		for ifId := range as.IFIDs {
			if ifId != outIF {
				// Note: the test graph does not distinguish between parent/child or
				// core interfaces.
				// Otherwise, we could skip the parent interfaces and half of the
				// sibling interfaces here.
				latency.Intra[common.IfIdType(ifId)] = g.Latency(ifId, outIF)
			}
			if ifId == outIF || g.isPeer[ifId] {
				latency.Inter[common.IfIdType(ifId)] = g.Latency(ifId, g.links[ifId])
			}
		}
	}

	bandwidth := staticinfo.BandwidthInfo{}
	if outIF != 0 {
		bandwidth.Intra = make(map[common.IfIdType]uint64)
		bandwidth.Inter = make(map[common.IfIdType]uint64)
		for ifId := range as.IFIDs {
			if ifId != outIF {
				bandwidth.Intra[common.IfIdType(ifId)] = g.Bandwidth(ifId, outIF)
			}
			if ifId == outIF || g.isPeer[ifId] {
				bandwidth.Inter[common.IfIdType(ifId)] = g.Bandwidth(ifId, g.links[ifId])
			}
		}
	}

	geo := make(staticinfo.GeoInfo)
	for ifId := range as.IFIDs {
		geo[common.IfIdType(ifId)] = g.GeoCoordinates(ifId)
	}

	linkType := make(staticinfo.LinkTypeInfo)
	for ifId := range as.IFIDs {
		linkType[common.IfIdType(ifId)] = g.LinkType(ifId, g.links[ifId])
	}

	var internalHops staticinfo.InternalHopsInfo
	if outIF != 0 {
		internalHops = make(map[common.IfIdType]uint32)
		if inIF != 0 {
			internalHops[common.IfIdType(inIF)] = g.InternalHops(inIF, outIF)
		}
		for ifId := range as.IFIDs {
			if ifId != outIF && ifId != inIF {
				internalHops[common.IfIdType(ifId)] = g.InternalHops(ifId, outIF)
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
