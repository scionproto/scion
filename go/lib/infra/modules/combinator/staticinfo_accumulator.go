package combinator

import (
	"fmt"
	"math"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/proto"
)

type ASnote struct {
	Note string
}

type ASGeo struct {
	locations []GeoLoc
}

type GeoLoc struct {
	Latitude  float32 `capnp:"latitude"`
	Longitude float32 `capnp:"longitude"`
	Address   string  `capnp:"address"`
}

func (s *GeoLoc) ProtoId() proto.ProtoIdType {
	return proto.DenseStaticInfo_Geo_GPSData_TypeID
}

func (s *GeoLoc) String() string {
	return fmt.Sprintf("Latitude: %f\nLongitude: %f\nAddress: %s\n",
		s.Latitude, s.Longitude, s.Address)
}

type ASDelay struct {
	Intradelay uint16
	Interdelay uint16
	Peerdelay  uint16
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

type DenseASLinkType struct {
	InterLinkType uint16   `capnp:"interLinkType"`
	PeerLinkType  uint16   `capnp:"peerLinkType"`
	ISD           addr.ISD `capnp:"isd"`
	AS            addr.AS  `capnp:"as"`
}

func (s *DenseASLinkType) ProtoId() proto.ProtoIdType {
	return proto.DenseStaticInfo_InterfaceLinkType_TypeID
}

func (s *DenseASLinkType) String() string {
	return fmt.Sprintf("InterLinkType: %d\nPeerLinkType: %d\nISD: %d\nAS: %d\n",
		s.InterLinkType, s.PeerLinkType, s.ISD, s.AS)
}

type DenseGeo struct {
	RouterLocations []GeoLoc `capnp:"routerLocations"`
	ISD             addr.ISD `capnp:"isd"`
	AS              addr.AS  `capnp:"as"`
}

func (s *DenseGeo) ProtoId() proto.ProtoIdType {
	return proto.DenseStaticInfo_Geo_TypeID
}

func (s *DenseGeo) String() string {
	return fmt.Sprintf("RouterLocations: %v\nISD: %d\nAS: %d\n",
		s.RouterLocations, s.ISD, s.AS)
}

type DenseNote struct {
	Note string   `capnp:"note"`
	ISD  addr.ISD `capnp:"isd"`
	AS   addr.AS  `capnp:"as"`
}

func (s *DenseNote) ProtoId() proto.ProtoIdType {
	return proto.DenseStaticInfo_Note_TypeID
}

func (s *DenseNote) String() string {
	return fmt.Sprintf("Text: %s\nISD: %d\nAS: %d\n",
		s.Note, s.ISD, s.AS)
}

type Pathmetadata struct {
	SingleDelays map[addr.IA]ASDelay
	Singlebw     map[addr.IA]ASBandwidth
	SingleHops   map[addr.IA]ASHops
	Internalhops map[addr.IA]uint8
	Geo          map[addr.IA]ASGeo
	Links        map[addr.IA]ASLink
	Notes        map[addr.IA]ASnote
}

// Densemetadata is the condensed form of metadata retaining only the most important values.
type Densemetadata struct {
	TotalDelay  uint16            `capnp:"totalDelay"`
	TotalHops   uint8             `capnp:"totalHops"`
	MinOfMaxBWs uint32            `capnp:"bandwidthBottleneck"`
	LinkTypes   []DenseASLinkType `capnp:"linkTypes"`
	Locations   []DenseGeo        `capnp:"asLocations"`
	Notes       []DenseNote       `capnp:"notes"`
}

func (s *Densemetadata) ProtoId() proto.ProtoIdType {
	return proto.DenseStaticInfo_TypeID
}

func (s *Densemetadata) String() string {
	return fmt.Sprintf("TotalDelay: %v\nTotalHops: %v\n"+
		"BandwidthBottleneck: %v\nLinkTypes: %v\nASLocations: %v\nNotes: %v\n",
		s.TotalDelay, s.TotalHops, s.MinOfMaxBWs, s.LinkTypes, s.Locations,
		s.Notes)
}

// Condensemetadata takes pathmetadata and extracts/condenses
// the most important values to be transmitted to SCIOND
func (data *Pathmetadata) Condensemetadata() *Densemetadata {
	ret := &Densemetadata{
		TotalDelay:  0,
		TotalHops:   0,
		MinOfMaxBWs: math.MaxUint32,
	}

	for _, val := range data.Singlebw {
		var asmaxbw uint32 = math.MaxUint32
		if val.IntraBW > 0 {
			asmaxbw = uint32(math.Min(float64(val.IntraBW), float64(asmaxbw)))
		}
		if val.InterBW > 0 {
			asmaxbw = uint32(math.Min(float64(val.InterBW), float64(asmaxbw)))
		}
		if asmaxbw < (math.MaxUint32) {
			ret.MinOfMaxBWs = uint32(math.Min(float64(ret.MinOfMaxBWs), float64(asmaxbw)))
		}
	}

	if !(ret.MinOfMaxBWs < math.MaxUint32) {
		ret.MinOfMaxBWs = 0
	}

	for _, val := range data.SingleDelays {
		ret.TotalDelay += val.Interdelay + val.Intradelay + val.Peerdelay
	}

	for _, val := range data.SingleHops {
		ret.TotalHops += val.Hops
	}

	for IA, note := range data.Notes {
		ret.Notes = append(ret.Notes, DenseNote{
			Note: note.Note,
			ISD:  IA.I,
			AS:   IA.A,
		})
	}

	for IA, loc := range data.Geo {
		ret.Locations = append(ret.Locations, DenseGeo{
			ISD:             IA.I,
			AS:              IA.A,
			RouterLocations: loc.locations,
		})
	}

	for IA, link := range data.Links {
		ret.LinkTypes = append(ret.LinkTypes, DenseASLinkType{
			InterLinkType: link.InterLinkType,
			PeerLinkType:  link.PeerLinkType,
			ISD:           IA.I,
			AS:            IA.A,
		})
	}

	return ret
}

type ASEntryList struct {
	Ups      []*seg.ASEntry
	Cores    []*seg.ASEntry
	Downs    []*seg.ASEntry
	UpPeer   int
	DownPeer int
}

func (solution *PathSolution) GatherASEntries() *ASEntryList {
	var res ASEntryList
	for _, solEdge := range solution.edges {
		asEntries := solEdge.segment.ASEntries
		currType := solEdge.segment.Type
		for asEntryIdx := len(asEntries) - 1; asEntryIdx >= solEdge.edge.Shortcut; asEntryIdx-- {
			asEntry := asEntries[asEntryIdx]
			switch currType {
			case proto.PathSegType_up:
				res.Ups = append(res.Ups, asEntry)
			case proto.PathSegType_core:
				res.Cores = append(res.Ups, asEntry)
			case proto.PathSegType_down:
				res.Downs = append(res.Ups, asEntry)
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

func (res *Pathmetadata) ExtractPeerdata(asEntry *seg.ASEntry, peerIfID common.IFIDType, includePeer bool) {
	IA := asEntry.IA()
	StaticInfo := asEntry.Exts.StaticInfo
	for i := 0; i < len(StaticInfo.Latency.Peerlatencies); i++ {
		if StaticInfo.Latency.Peerlatencies[i].IfID == peerIfID {
			if includePeer {
				res.SingleDelays[IA] = ASDelay{
					Intradelay: StaticInfo.Latency.Peerlatencies[i].IntraDelay,
					Interdelay: StaticInfo.Latency.Egresslatency,
					Peerdelay:  StaticInfo.Latency.Peerlatencies[i].Interdelay,
				}
			} else {
				res.SingleDelays[IA] = ASDelay{
					Intradelay: StaticInfo.Latency.Peerlatencies[i].IntraDelay,
					Interdelay: StaticInfo.Latency.Egresslatency,
				}
			}
		}
	}
	for i := 0; i < len(StaticInfo.Linktype.Peerlinks); i++ {
		if StaticInfo.Linktype.Peerlinks[i].IfID == peerIfID {
			if includePeer {
				res.Links[IA] = ASLink{
					InterLinkType: StaticInfo.Linktype.EgressLinkType,
					PeerLinkType:  StaticInfo.Linktype.Peerlinks[i].LinkType,
				}
			} else {
				res.Links[IA] = ASLink{
					InterLinkType: StaticInfo.Linktype.EgressLinkType,
				}
			}
		}
	}
	for i := 0; i < len(StaticInfo.Bandwidth.Bandwidths); i++ {
		if StaticInfo.Bandwidth.Bandwidths[i].IfID == peerIfID {
			res.Singlebw[IA] = ASBandwidth{
				IntraBW: StaticInfo.Bandwidth.Bandwidths[i].BW,
				InterBW: StaticInfo.Bandwidth.EgressBW,
			}
		}
	}
	for i := 0; i < len(StaticInfo.Hops.InterfaceHops); i++ {
		if StaticInfo.Hops.InterfaceHops[i].IfID == peerIfID {
			res.SingleHops[IA] = ASHops{
				Hops: StaticInfo.Hops.InterfaceHops[i].Hops,
			}
		}
	}
	res.Geo[IA] = getGeo(asEntry)
	res.Notes[IA] = ASnote{
		Note: StaticInfo.Note,
	}
}

func (res *Pathmetadata) ExtractNormaldata(asEntry *seg.ASEntry) {
	IA := asEntry.IA()
	StaticInfo := asEntry.Exts.StaticInfo
	res.SingleDelays[IA] = ASDelay{
		Intradelay: StaticInfo.Latency.IngressToEgressLatency,
		Interdelay: StaticInfo.Latency.Egresslatency,
		Peerdelay:  0,
	}
	res.Links[IA] = ASLink{
		InterLinkType: StaticInfo.Linktype.EgressLinkType,
	}
	res.Singlebw[IA] = ASBandwidth{
		IntraBW: StaticInfo.Bandwidth.IngressToEgressBW,
		InterBW: StaticInfo.Bandwidth.EgressBW,
	}
	res.SingleHops[IA] = ASHops{
		Hops: StaticInfo.Hops.InToOutHops,
	}
	res.Geo[IA] = getGeo(asEntry)
	res.Notes[IA] = ASnote{
		Note: StaticInfo.Note,
	}
}

func (res *Pathmetadata) ExtractUpOverdata(oldASEntry *seg.ASEntry, newASEntry *seg.ASEntry) {
	IA := newASEntry.IA()
	StaticInfo := newASEntry.Exts.StaticInfo
	hopEntry := oldASEntry.HopEntries[0]
	HF, _ := hopEntry.HopField()
	oldEgressIFID := HF.ConsEgress
	for i := 0; i < len(StaticInfo.Latency.Childlatencies); i++ {
		if StaticInfo.Latency.Childlatencies[i].IfID == oldEgressIFID {
			res.SingleDelays[IA] = ASDelay{
				Intradelay: StaticInfo.Latency.Childlatencies[i].Intradelay,
				Interdelay: StaticInfo.Latency.Egresslatency,
				Peerdelay:  oldASEntry.Exts.StaticInfo.Latency.Egresslatency,
			}
		}
	}
	res.Links[IA] = ASLink{
		InterLinkType: StaticInfo.Linktype.EgressLinkType,
		PeerLinkType:  oldASEntry.Exts.StaticInfo.Linktype.EgressLinkType,
	}

	for i := 0; i < len(StaticInfo.Bandwidth.Bandwidths); i++ {
		if StaticInfo.Bandwidth.Bandwidths[i].IfID == oldEgressIFID {
			res.Singlebw[IA] = ASBandwidth{
				IntraBW: StaticInfo.Bandwidth.Bandwidths[i].BW,
				InterBW: StaticInfo.Bandwidth.EgressBW,
			}
		}
	}
	for i := 0; i < len(StaticInfo.Hops.InterfaceHops); i++ {
		if StaticInfo.Hops.InterfaceHops[i].IfID == oldEgressIFID {
			res.SingleHops[IA] = ASHops{
				Hops: StaticInfo.Hops.InterfaceHops[i].Hops,
			}
		}
	}
	res.Geo[IA] = getGeo(newASEntry)
	res.Notes[IA] = ASnote{
		Note: StaticInfo.Note,
	}
}

func (res *Pathmetadata) ExtractCoreOverdata(oldASEntry *seg.ASEntry, newASEntry *seg.ASEntry) {
	IA := newASEntry.IA()
	StaticInfo := newASEntry.Exts.StaticInfo
	hopEntry := oldASEntry.HopEntries[0]
	HF, _ := hopEntry.HopField()
	oldIngressIfID := HF.ConsIngress
	for i := 0; i < len(StaticInfo.Latency.Childlatencies); i++ {
		if StaticInfo.Latency.Childlatencies[i].IfID == oldIngressIfID {
			res.SingleDelays[IA] = ASDelay{
				Intradelay: StaticInfo.Latency.Childlatencies[i].Intradelay,
				Interdelay: StaticInfo.Latency.Egresslatency,
			}
		}
	}
	res.Links[IA] = ASLink{
		InterLinkType: StaticInfo.Linktype.EgressLinkType,
	}

	for i := 0; i < len(StaticInfo.Bandwidth.Bandwidths); i++ {
		if StaticInfo.Bandwidth.Bandwidths[i].IfID == oldIngressIfID {
			res.Singlebw[IA] = ASBandwidth{
				IntraBW: StaticInfo.Bandwidth.Bandwidths[i].BW,
				InterBW: StaticInfo.Bandwidth.EgressBW,
			}
		}
	}
	for i := 0; i < len(StaticInfo.Hops.InterfaceHops); i++ {
		if StaticInfo.Hops.InterfaceHops[i].IfID == oldIngressIfID {
			res.SingleHops[IA] = ASHops{
				Hops: StaticInfo.Hops.InterfaceHops[i].Hops,
			}
		}
	}
	res.Geo[IA] = getGeo(newASEntry)
	res.Notes[IA] = ASnote{
		Note: StaticInfo.Note,
	}
}

func (ASes *ASEntryList) CombineSegments() *Pathmetadata {
	var res Pathmetadata
	var LastUpASEntry *seg.ASEntry
	var LastCoreASEntry *seg.ASEntry
	// Go through ASEntries in the up segment (except for the first one)
	// and extract the static info data from them
	for idx := 0; idx < len(ASes.Ups); idx++ {
		asEntry := ASes.Ups[idx]
		if idx == 0 {
			res.Geo[asEntry.IA()] = getGeo(asEntry)
			continue
		}
		if (idx > 0) && (idx < (len(ASes.Ups) - 1)) {
			res.ExtractNormaldata(asEntry)
		} else {
			if ASes.UpPeer != 0 {
				peerEntry := asEntry.HopEntries[ASes.UpPeer]
				PE, _ := peerEntry.HopField()
				peerIfID := PE.ConsIngress
				res.ExtractPeerdata(asEntry, peerIfID, true)
			} else {
				// If the last up AS is not involved in peering,
				// do nothing except store the as in LastUpASEntry
				LastUpASEntry = asEntry
			}
		}
	}

	// Go through ASEntries in the core segment
	// and extract the static info data from them
	for idx := 0; idx < len(ASes.Cores); idx++ {
		asEntry := ASes.Cores[idx]
		// If we're in the first inspected AS (i.e the last AS of the segment)
		// only set LastCoreASEntry
		if idx == 0 {
			LastCoreASEntry = asEntry
			if len(ASes.Cores) == 0 {
				res.Geo[asEntry.IA()] = getGeo(asEntry)
			}
			continue
		}
		if (idx > 0) && (idx < (len(ASes.Ups) - 1)) {
			res.ExtractNormaldata(asEntry)
		} else {
			if len(ASes.Ups) > 0 {
				// We're in the AS where we cross over from the up to the core segment
				res.ExtractUpOverdata(asEntry, LastUpASEntry)
			}
		}
	}

	// Go through ASEntries in the down segment except for the first one
	// and extract the static info data from them
	for idx := 0; idx < len(ASes.Cores); idx++ {
		asEntry := ASes.Cores[idx]
		if idx == 0 {
			res.Geo[asEntry.IA()] = getGeo(asEntry)
			continue
		}
		if (idx > 0) && (idx < (len(ASes.Ups) - 1)) {
			res.ExtractNormaldata(asEntry)
		} else {
			if ASes.DownPeer != 0 {
				// We're in the AS where we peered over from the up to the down segment
				peerEntry := asEntry.HopEntries[ASes.UpPeer]
				PE, _ := peerEntry.HopField()
				peerIfID := PE.ConsIngress
				res.ExtractPeerdata(asEntry, peerIfID, false)
			} else {
				if len(ASes.Cores) > 0 {
					// We're in the AS where we cross over from the core to the down segment
					res.ExtractCoreOverdata(LastCoreASEntry, asEntry)
				}
				if (len(ASes.Ups) > 0) && (len(ASes.Cores) == 0) {
					// We're in the AS where we cross over from the up to the down segment via a shortcut
					res.ExtractUpOverdata(LastUpASEntry, asEntry)
				}
			}
		}
	}
	return &res
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
		locations: locations,
	}
	return res
}
