package combinator

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/proto"
)

type ASnote struct {
	Note string
}

type ASGeo struct {
	Locations []GeoLoc
}

type GeoLoc struct {
	Latitude  float32 `capnp:"latitude"`
	Longitude float32 `capnp:"longitude"`
	Address   string  `capnp:"address"`
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

// CollectMetadata is the function used to extract StaticInfo
// from a *PathSolution.
func (solution *PathSolution) collectMetadata() *PathMetadata {
	asEntries := solution.gatherASEntries()
	return combineSegments(asEntries)
}

// gatherASEntries goes through the edges in the PathSolution found by GetPaths.
// For each edge, it goes through each ASEntry and adds it to a list,
// representing the up-, core-, and down segments respectively.
// It also saves the Peer value of the up and down edges.
func (solution *PathSolution) gatherASEntries() *asEntryList {
	var res asEntryList
	for _, solEdge := range solution.edges {
		asEntries := solEdge.segment.ASEntries
		currType := solEdge.segment.Type
		for asEntryIdx := len(asEntries) - 1; asEntryIdx >= solEdge.edge.Shortcut; asEntryIdx-- {
			asEntry := asEntries[asEntryIdx]
			switch currType {
			case proto.PathSegType_up:
				res.Ups = append(res.Ups, asEntry)
			case proto.PathSegType_core:
				res.Cores = append(res.Cores, asEntry)
			case proto.PathSegType_down:
				res.Downs = append(res.Downs, asEntry)
			}
		}
		switch currType {
		case proto.PathSegType_up:
			res.UpPeer = solEdge.edge.Peer
		case proto.PathSegType_down:
			res.DownPeer = solEdge.edge.Peer
		}
	}
	return &res
}

// extractPeerdata is used to treat ASEntries which are involved in peering.
// It includes saves the metrics for the egress, intra-AS, and peering
// connections in the respective fields in RawPathMetadata.
func extractPeerdata(res *PathMetadata, asEntry *seg.ASEntry,
	peerIfID common.IFIDType, includePeer bool) {

	ia := asEntry.IA()
	staticInfo := asEntry.Exts.StaticInfo
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
		}
	}
	for i := 0; i < len(staticInfo.Bandwidth.Bandwidths); i++ {
		if staticInfo.Bandwidth.Bandwidths[i].IfID == peerIfID {
			res.ASBandwidths[ia] = ASBandwidth{
				IntraBW: staticInfo.Bandwidth.Bandwidths[i].BW,
				InterBW: staticInfo.Bandwidth.EgressBW,
			}
		}
	}
	for i := 0; i < len(staticInfo.Hops.InterfaceHops); i++ {
		if staticInfo.Hops.InterfaceHops[i].IfID == peerIfID {
			res.ASHops[ia] = ASHops{
				Hops: staticInfo.Hops.InterfaceHops[i].Hops,
			}
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
	ia := asEntry.IA()
	staticInfo := asEntry.Exts.StaticInfo
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
	ia := asEntry.IA()
	staticInfo := asEntry.Exts.StaticInfo
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
	ia := newASEntry.IA()
	staticInfo := oldASEntry.Exts.StaticInfo
	hopEntry := newASEntry.HopEntries[0]
	hf, _ := hopEntry.HopField()
	newIngressIfID := hf.ConsIngress
	for i := 0; i < len(staticInfo.Latency.Childlatencies); i++ {
		if staticInfo.Latency.Childlatencies[i].IfID == newIngressIfID {
			res.ASLatencies[ia] = ASLatency{
				IntraLatency: staticInfo.Latency.Childlatencies[i].Intradelay,
				InterLatency: staticInfo.Latency.Egresslatency,
			}
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
		}
	}
	for i := 0; i < len(staticInfo.Hops.InterfaceHops); i++ {
		if staticInfo.Hops.InterfaceHops[i].IfID == newIngressIfID {
			res.ASHops[ia] = ASHops{
				Hops: staticInfo.Hops.InterfaceHops[i].Hops,
			}
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
	ia := newASEntry.IA()
	staticInfo := newASEntry.Exts.StaticInfo
	oldSI := oldASEntry.Exts.StaticInfo
	hopEntry := oldASEntry.HopEntries[0]
	hf, _ := hopEntry.HopField()
	oldEgressIfID := hf.ConsEgress
	for i := 0; i < len(staticInfo.Latency.Childlatencies); i++ {
		if staticInfo.Latency.Childlatencies[i].IfID == oldEgressIfID {
			res.ASLatencies[ia] = ASLatency{
				IntraLatency: staticInfo.Latency.Childlatencies[i].Intradelay,
				InterLatency: staticInfo.Latency.Egresslatency,
				PeerLatency:  oldSI.Latency.Egresslatency,
			}
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
		}
	}
	for i := 0; i < len(staticInfo.Hops.InterfaceHops); i++ {
		if staticInfo.Hops.InterfaceHops[i].IfID == oldEgressIfID {
			res.ASHops[ia] = ASHops{
				Hops: staticInfo.Hops.InterfaceHops[i].Hops,
			}
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
	var lastUpASEntry *seg.ASEntry
	var lastCoreASEntry *seg.ASEntry
	res := &PathMetadata{
		ASLatencies:  make(map[addr.IA]ASLatency),
		ASBandwidths: make(map[addr.IA]ASBandwidth),
		ASHops:       make(map[addr.IA]ASHops),
		Geo:          make(map[addr.IA]ASGeo),
		Links:        make(map[addr.IA]ASLink),
		Notes:        make(map[addr.IA]ASnote),
	}
	// Go through ASEntries in the up segment
	// and extract the static info data from them
	for idx := 0; idx < len(ases.Ups); idx++ {
		asEntry := ases.Ups[idx]
		s := asEntry.Exts.StaticInfo
		if s == nil {
			continue
		}
		if idx == 0 {
			// For the first AS on the path, only extract
			// the note and the geodata, since all other data
			// is not available as part of the saved
			// s as we only have metrics describing a connection
			// between BRs (i.e. the "edges" of an AS) and a path could
			// potentially originate somewhere in the "middle" of the AS.
			res.Geo[asEntry.IA()] = getGeo(asEntry)
			res.Notes[asEntry.IA()] = ASnote{Note: s.Note}
		} else if idx < (len(ases.Ups) - 1) {
			// If the AS is in the middle of the segment, simply extract
			// the egress and ingressToEgress metrics from the corresponding
			// fields in s.
			extractNormaldata(res, asEntry)
		} else {
			// We're in the last AS on the up segment, distinguish
			// 3 cases:
			if (len(ases.Cores) == 0) && (len(ases.Downs) == 0) {
				// This is the only segment and thus the final
				// AS on the path.
				extractSingleSegmentFinalASData(res, asEntry)
			} else if ases.UpPeer != 0 {
				// This is the last AS in the segment and it
				// is connected to the down segment via a peering
				// connection.
				peerEntry := asEntry.HopEntries[ases.UpPeer]
				PE, _ := peerEntry.HopField()
				peerIfID := PE.ConsIngress
				extractPeerdata(res, asEntry, peerIfID, false)
			} else {
				// If the last up AS is not involved in peering,
				// do nothing except store the ASEntry in LastUpASEntry.
				// The actual crossover will be treated as part of the core
				// segment.
				lastUpASEntry = asEntry
			}
		}
	}
	// Go through ASEntries in the core segment
	// and extract the static info data from them
	for idx := 0; idx < len(ases.Cores); idx++ {
		asEntry := ases.Cores[idx]
		s := asEntry.Exts.StaticInfo
		if s == nil {
			continue
		}
		if idx == 0 {
			if len(ases.Ups) > 0 {
				// We're in the AS where we cross over from the up to the core segment
				extractUpOverdata(res, lastUpASEntry, asEntry)
			} else {
				// This is the first AS in the path, so we only extract
				// its geodata and the note
				res.Geo[asEntry.IA()] = getGeo(asEntry)
				res.Notes[asEntry.IA()] = ASnote{Note: s.Note}
			}
		} else if idx < (len(ases.Cores) - 1) {
			// If the AS is in the middle of the segment, simply extract
			// the egress and ingressToEgress metrics from the corresponding
			// fields in s.
			extractNormaldata(res, asEntry)
		} else {
			// If we're in the last AS of the segment
			// only set LastCoreASEntry.
			// It will later be used to treat the crossover
			// when we look at the down segment.
			lastCoreASEntry = asEntry
			if len(ases.Downs) == 0 {
				// If this is the last AS on the path (i.e. there is no
				// down segment) extract data accordingly.
				extractSingleSegmentFinalASData(res, asEntry)
			}
		}
	}
	// Go through ASEntries in the down segment
	// and extract the static info data from them
	for idx := 0; idx < len(ases.Downs); idx++ {
		asEntry := ases.Downs[idx]
		s := asEntry.Exts.StaticInfo
		if s == nil {
			continue
		}
		if idx == 0 {
			// for the last AS on the path, only extract
			// the note and the geodata (analogous to the first AS).
			res.Geo[asEntry.IA()] = getGeo(asEntry)
			res.Notes[asEntry.IA()] = ASnote{Note: s.Note}
		} else if idx < (len(ases.Downs) - 1) {
			extractNormaldata(res, asEntry)
		} else {
			if ases.DownPeer != 0 {
				// We're in the AS where we peered over from the up to the down segment
				peerEntry := asEntry.HopEntries[ases.DownPeer]
				PE, _ := peerEntry.HopField()
				peerIfID := PE.ConsIngress
				extractPeerdata(res, asEntry, peerIfID, true)
			} else {
				if len(ases.Cores) > 0 {
					// We're in the AS where we cross over from the core to the down segment
					extractCoreOverdata(res, lastCoreASEntry, asEntry)
				}
				if (len(ases.Ups) > 0) && (len(ases.Cores) == 0) {
					// We're in the AS where we cross over from the up to
					// the down segment via a shortcut (analogous to crossing
					// over from core to down, thus we use ExtractCoreOverdata())
					extractCoreOverdata(res, lastUpASEntry, asEntry)
				}
				if (len(ases.Ups) == 0) && (len(ases.Cores) == 0) {
					extractSingleSegmentFinalASData(res, asEntry)
				}
			}
		}
	}
	return res
}

func getGeo(asEntry *seg.ASEntry) ASGeo {
	var locations []GeoLoc
	for _, loc := range asEntry.Exts.StaticInfo.Geo.Locations {
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
