package combinator

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/proto"
)

// XXX(matzf) replace these types with appropriate definitions directly in
// snet.PathMetadata, making this available to applications. Remove this here
// PathMetadata (currently dead code) and change the logic below to directly
// fill in the data into snet.PathMetadata.

type ASnote struct {
	Note string
}

type ASGeo struct {
	Locations []GeoLoc
}

type GeoLoc struct {
	Latitude  float32
	Longitude float32
	Address   string
}

type ASLatency struct {
	IntraLatency uint16
	InterLatency uint16
	PeerLatency  uint16
}

type ASHops struct {
	Hops uint8
}

type ASLink struct {
	InterLinkType uint16
	PeerLinkType  uint16
}

type ASBandwidth struct {
	IntraBW uint32
	InterBW uint32
}

type PathMetadata struct {
	ASLatencies  map[addr.IA]ASLatency
	ASBandwidths map[addr.IA]ASBandwidth
	ASHops       map[addr.IA]ASHops
	Geo          map[addr.IA]ASGeo
	Links        map[addr.IA]ASLink
	Notes        map[addr.IA]ASnote
}

type asEntryList struct {
	Ups      []*seg.ASEntry
	Cores    []*seg.ASEntry
	Downs    []*seg.ASEntry
	UpPeer   int
	DownPeer int
}

// collectMetadata is the function used to extract StaticInfo
// from a *PathSolution.
func (solution *pathSolution) collectMetadata() *PathMetadata {
	asEntries := solution.gatherASEntries()
	return combineSegments(asEntries)
}

// gatherASEntries goes through the edges in the PathSolution found by GetPaths.
// For each edge, it goes through each ASEntry and adds it to a list,
// representing the up-, core-, and down segments respectively.
// It also saves the Peer value of the up and down edges.
func (solution *pathSolution) gatherASEntries() *asEntryList {
	var res asEntryList
	for _, solEdge := range solution.edges {
		asEntries := solEdge.segment.ASEntries
		var entryContainer *[]*seg.ASEntry
		switch solEdge.segment.Type {
		case proto.PathSegType_up:
			entryContainer = &res.Ups
			res.UpPeer = solEdge.edge.Peer
		case proto.PathSegType_core:
			entryContainer = &res.Cores
		case proto.PathSegType_down:
			entryContainer = &res.Downs
			res.DownPeer = solEdge.edge.Peer
		}
		for asEntryIdx := len(asEntries) - 1; asEntryIdx >= solEdge.edge.Shortcut; asEntryIdx-- {
			asEntry := asEntries[asEntryIdx]
			*entryContainer = append(*entryContainer, &asEntry)
		}
	}
	return &res
}

// extractPeerdata is used to treat ASEntries which are involved in peering.
// It includes saves the metrics for the egress, intra-AS, and peering
// connections in the respective fields in RawPathMetadata.
func extractPeerdata(res *PathMetadata, asEntry *seg.ASEntry,
	peerIfID common.IFIDType, includePeer bool) {

	ia := asEntry.Local
	staticInfo := seg.StaticInfoExtn{} // FIXME(roosd): enable again: asEntry.Exts.StaticInfo
	for i := 0; i < len(staticInfo.Latency.Peerlatencies); i++ {
		if staticInfo.Latency.Peerlatencies[i].IfID == peerIfID {
			if includePeer {
				res.ASLatencies[ia] = ASLatency{
					IntraLatency: staticInfo.Latency.Peerlatencies[i].IntraDelay,
					InterLatency: staticInfo.Latency.Egresslatency,
					PeerLatency:  staticInfo.Latency.Peerlatencies[i].Interdelay,
				}
			} else {
				res.ASLatencies[ia] = ASLatency{
					IntraLatency: staticInfo.Latency.Peerlatencies[i].IntraDelay,
					InterLatency: staticInfo.Latency.Egresslatency,
				}
			}
			break
		}
	}
	for i := 0; i < len(staticInfo.Linktype.Peerlinks); i++ {
		if staticInfo.Linktype.Peerlinks[i].IfID == peerIfID {
			if includePeer {
				res.Links[ia] = ASLink{
					InterLinkType: staticInfo.Linktype.EgressLinkType,
					PeerLinkType:  staticInfo.Linktype.Peerlinks[i].LinkType,
				}
			} else {
				res.Links[ia] = ASLink{
					InterLinkType: staticInfo.Linktype.EgressLinkType,
				}
			}
			break
		}
	}
	for i := 0; i < len(staticInfo.Bandwidth.Bandwidths); i++ {
		if staticInfo.Bandwidth.Bandwidths[i].IfID == peerIfID {
			res.ASBandwidths[ia] = ASBandwidth{
				IntraBW: staticInfo.Bandwidth.Bandwidths[i].BW,
				InterBW: staticInfo.Bandwidth.EgressBW,
			}
			break
		}
	}
	for i := 0; i < len(staticInfo.Hops.InterfaceHops); i++ {
		if staticInfo.Hops.InterfaceHops[i].IfID == peerIfID {
			res.ASHops[ia] = ASHops{
				Hops: staticInfo.Hops.InterfaceHops[i].Hops,
			}
			break
		}
	}
	res.Geo[ia] = getGeo(asEntry)
	res.Notes[ia] = ASnote{
		Note: staticInfo.Note,
	}
}

// extractSingleSegmentFinalASData is used to extract StaticInfo from
// the final AS in a path that does not contain all 3 segments.
func extractSingleSegmentFinalASData(res *PathMetadata, asEntry *seg.ASEntry) {
	ia := asEntry.Local
	staticInfo := seg.StaticInfoExtn{} // FIXME(roosd): enable again: asEntry.Exts.StaticInfo
	res.ASLatencies[ia] = ASLatency{
		InterLatency: staticInfo.Latency.Egresslatency,
		PeerLatency:  0,
	}
	res.Links[ia] = ASLink{
		InterLinkType: staticInfo.Linktype.EgressLinkType,
	}
	res.ASBandwidths[ia] = ASBandwidth{
		InterBW: staticInfo.Bandwidth.EgressBW,
	}
	res.ASHops[ia] = ASHops{}
	res.Geo[ia] = getGeo(asEntry)
	res.Notes[ia] = ASnote{
		Note: staticInfo.Note,
	}
}

// extractNormaldata is used to extract StaticInfo from an AS that is
// "in the middle" of a path, i.e. it is neither the first nor last AS
// in the segment. It only uses egress and ingress to egress values from
// staticInfo.

func extractNormaldata(res *PathMetadata, asEntry *seg.ASEntry) {
	ia := asEntry.Local
	staticInfo := seg.StaticInfoExtn{} // FIXME(roosd): enable again: asEntry.Exts.StaticInfo
	res.ASLatencies[ia] = ASLatency{
		IntraLatency: staticInfo.Latency.IngressToEgressLatency,
		InterLatency: staticInfo.Latency.Egresslatency,
		PeerLatency:  0,
	}
	res.Links[ia] = ASLink{
		InterLinkType: staticInfo.Linktype.EgressLinkType,
	}
	res.ASBandwidths[ia] = ASBandwidth{
		IntraBW: staticInfo.Bandwidth.IngressToEgressBW,
		InterBW: staticInfo.Bandwidth.EgressBW,
	}
	res.ASHops[ia] = ASHops{
		Hops: staticInfo.Hops.InToOutHops,
	}
	res.Geo[ia] = getGeo(asEntry)
	res.Notes[ia] = ASnote{
		Note: staticInfo.Note,
	}
}

// extractUpOverdata is used to extract StaticInfo from the last AS in the up segment,
// when the path crosses over into the core segment (i.e. the AS is also the first AS
// in the core segment).
func extractUpOverdata(res *PathMetadata, oldASEntry *seg.ASEntry, newASEntry *seg.ASEntry) {
	ia := newASEntry.Local
	// FIXME(roosd): enable again: staticInfo := oldASEntry.Exts.StaticInfo
	staticInfo := seg.StaticInfoExtn{}
	hopEntry := newASEntry.HopEntry
	newIngressIfID := common.IFIDType(hopEntry.HopField.ConsIngress)
	for i := 0; i < len(staticInfo.Latency.Childlatencies); i++ {
		if staticInfo.Latency.Childlatencies[i].IfID == newIngressIfID {
			res.ASLatencies[ia] = ASLatency{
				IntraLatency: staticInfo.Latency.Childlatencies[i].Intradelay,
				InterLatency: staticInfo.Latency.Egresslatency,
			}
			break
		}
	}
	res.Links[ia] = ASLink{
		InterLinkType: staticInfo.Linktype.EgressLinkType,
	}

	for i := 0; i < len(staticInfo.Bandwidth.Bandwidths); i++ {
		if staticInfo.Bandwidth.Bandwidths[i].IfID == newIngressIfID {
			res.ASBandwidths[ia] = ASBandwidth{
				IntraBW: staticInfo.Bandwidth.Bandwidths[i].BW,
				InterBW: staticInfo.Bandwidth.EgressBW,
			}
			break
		}
	}
	for i := 0; i < len(staticInfo.Hops.InterfaceHops); i++ {
		if staticInfo.Hops.InterfaceHops[i].IfID == newIngressIfID {
			res.ASHops[ia] = ASHops{
				Hops: staticInfo.Hops.InterfaceHops[i].Hops,
			}
			break
		}
	}
	res.Geo[ia] = getGeo(newASEntry)
	res.Notes[ia] = ASnote{
		Note: staticInfo.Note,
	}
}

// extractCoreOverdata is used to extract StaticInfo from the last AS in the core segment,
// when the path crosses over into the down segment (i.e. the AS is also the last AS
// in the down segment).
func extractCoreOverdata(res *PathMetadata, oldASEntry *seg.ASEntry, newASEntry *seg.ASEntry) {
	ia := newASEntry.Local
	staticInfo := seg.StaticInfoExtn{} // FIXME(roosd): enable again: := newASEntry.Exts.StaticInfo
	oldSI := seg.StaticInfoExtn{}      // FIXME(roosd): enable again: := oldASEntry.Exts.StaticInfo
	hopEntry := oldASEntry.HopEntry
	oldEgressIfID := common.IFIDType(hopEntry.HopField.ConsEgress)
	for i := 0; i < len(staticInfo.Latency.Childlatencies); i++ {
		if staticInfo.Latency.Childlatencies[i].IfID == oldEgressIfID {
			res.ASLatencies[ia] = ASLatency{
				IntraLatency: staticInfo.Latency.Childlatencies[i].Intradelay,
				InterLatency: staticInfo.Latency.Egresslatency,
				PeerLatency:  oldSI.Latency.Egresslatency,
			}
			break
		}
	}
	res.Links[ia] = ASLink{
		InterLinkType: staticInfo.Linktype.EgressLinkType,
		PeerLinkType:  oldSI.Linktype.EgressLinkType,
	}

	for i := 0; i < len(staticInfo.Bandwidth.Bandwidths); i++ {
		if staticInfo.Bandwidth.Bandwidths[i].IfID == oldEgressIfID {
			res.ASBandwidths[ia] = ASBandwidth{
				IntraBW: staticInfo.Bandwidth.Bandwidths[i].BW,
				InterBW: staticInfo.Bandwidth.EgressBW,
			}
			break
		}
	}
	for i := 0; i < len(staticInfo.Hops.InterfaceHops); i++ {
		if staticInfo.Hops.InterfaceHops[i].IfID == oldEgressIfID {
			res.ASHops[ia] = ASHops{
				Hops: staticInfo.Hops.InterfaceHops[i].Hops,
			}
			break
		}
	}
	res.Geo[ia] = getGeo(newASEntry)
	res.Notes[ia] = ASnote{
		Note: staticInfo.Note,
	}
}

// combineSegments is responsible for going through each list of ASEntries
// representing a path segment and calling the extractor
// functions from above that correspond to the
// particular role/position of each ASEntry in the segment.
func combineSegments(ases *asEntryList) *PathMetadata {
	meta := &PathMetadata{
		ASLatencies:  make(map[addr.IA]ASLatency),
		ASBandwidths: make(map[addr.IA]ASBandwidth),
		ASHops:       make(map[addr.IA]ASHops),
		Geo:          make(map[addr.IA]ASGeo),
		Links:        make(map[addr.IA]ASLink),
		Notes:        make(map[addr.IA]ASnote),
	}
	// first insert the meta from the segments
	lastUp := addMetaFromSegment(meta, ases.Ups)
	lastCore := addMetaFromSegment(meta, ases.Cores)
	lastDown := addMetaFromSegment(meta, ases.Downs)

	// then stitch the segments metadata and insert them
	if lastUp != nil && ases.UpPeer != 0 {
		// This is the last AS in the segment and it is connected to the down segment via peering.
		extractPeerdata(meta, lastUp, peerIfID(lastUp.PeerEntries[ases.UpPeer-1]), false)
		lastUp = nil
	}
	// if len(ases.Ups) > 0 && len(ases.Cores) > 0 && ases.Cores[0] != nil {
	// TODO(juagargi): beware that here ^^, as well as in the original code, lastUp could be nil
	if lastUp != nil && len(ases.Cores) > 0 && ases.Cores[0] != nil {
		// We're in the AS where we cross over from the up to the core segment
		extractUpOverdata(meta, lastUp, ases.Cores[0])
	}

	if lastDown != nil && ases.DownPeer != 0 {
		// This is the last AS in the segment and it is connected to the down segment via peering.
		extractPeerdata(meta, lastDown, peerIfID(lastDown.PeerEntries[ases.DownPeer-1]), true)
		lastDown = nil
	}
	if lastDown != nil && lastCore != nil {
		extractCoreOverdata(meta, lastCore, lastDown)
		lastDown, lastCore, lastUp = nil, nil, nil
	} else if lastDown != nil && lastUp != nil {
		extractCoreOverdata(meta, lastUp, lastDown)
		lastDown, lastUp = nil, nil
	}

	// put a "stopper" at last entry for this cases: only up, only core, up-core, and only down.
	var lastFinal *seg.ASEntry
	if lastUp != nil {
		lastFinal = lastUp
	}
	if lastCore != nil {
		lastFinal = lastCore
	}
	if lastFinal == nil && lastDown != nil {
		lastFinal = lastDown
	}
	if lastFinal != nil {
		extractSingleSegmentFinalASData(meta, lastFinal)
	}

	return meta
}

// inclusion of info from segment. Returns the last ASEntry of the segment if len >1
func addMetaFromSegment(meta *PathMetadata, segment []*seg.ASEntry) *seg.ASEntry {
	if len(segment) == 0 {
		return nil
	}
	asEntry := segment[0]
	s := &seg.StaticInfoExtn{} // FIXME(roosd): enable again := asEntry.Exts.StaticInfo
	if false {
		// For the first AS on the path, only extract
		// the note and the geodata, since all other data
		// is not available as part of the saved
		// s as we only have metrics describing a connection
		// between BRs (i.e. the "edges" of an AS) and a path could
		// potentially originate somewhere in the "middle" of the AS.
		meta.Geo[asEntry.Local] = getGeo(asEntry)
		meta.Notes[asEntry.Local] = ASnote{Note: s.Note}
	}
	for i := 1; i < len(segment)-1; i++ {
		// If the AS is in the middle of the segment, simply extract
		// the egress and ingressToEgress metrics from the corresponding
		// fields in s.
		if true { // FIXME(roosd): enable again: if segment[i].Exts.StaticInfo == nil {
			continue
		}
		extractNormaldata(meta, segment[i])
	}
	// FIXME(roosd): enable again:
	// if len(segment) > 1 && segment[len(segment)-1].Exts.StaticInfo != nil {
	if false {
		// the stitching is done later
		return segment[len(segment)-1]
	}
	return nil
}

func getGeo(asEntry *seg.ASEntry) ASGeo {
	var locations []GeoLoc
	// FIXME(roosd): Enable again := asEntry.Exts.StaticInfo.Geo.Locations
	staticInfo := seg.StaticInfoExtn{}
	for _, loc := range staticInfo.Geo.Locations {
		locations = append(locations, GeoLoc{
			Latitude:  loc.GPSData.Latitude,
			Longitude: loc.GPSData.Longitude,
			Address:   loc.GPSData.Address,
		})
	}
	res := ASGeo{
		Locations: locations,
	}
	return res
}

func peerIfID(he seg.PeerEntry) common.IFIDType {
	return common.IFIDType(he.HopField.ConsIngress)
}
