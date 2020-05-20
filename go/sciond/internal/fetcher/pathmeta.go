package fetcher

import (
	"fmt"
	"math"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra/modules/combinator"
	"github.com/scionproto/scion/go/proto"
)

// PathMetadata is the condensed form of metadata retaining only the most important values.
type PathMetadata struct {
	TotalLatency uint16            `capnp:"totalLatency"`
	TotalHops    uint8             `capnp:"totalHops"`
	MinOfMaxBWs  uint32            `capnp:"minimalBandwidth"`
	LinkTypes    []DenseASLinkType `capnp:"linkTypes"`
	Locations    []DenseGeo        `capnp:"asLocations"`
	Notes        []DenseNote       `capnp:"notes"`
}

func (s *PathMetadata) ProtoId() proto.ProtoIdType {
	return proto.PathMetadata_TypeID
}

func (s *PathMetadata) String() string {
	return fmt.Sprintf("TotalLatency: %v\nTotalHops: %v\n"+
		"BandwidthBottleneck: %v\nLinkTypes: %v\nASLocations: %v\nNotes: %v\n",
		s.TotalLatency, s.TotalHops, s.MinOfMaxBWs, s.LinkTypes, s.Locations,
		s.Notes)
}

type DenseASLinkType struct {
	InterLinkType uint16     `capnp:"interLinkType"`
	PeerLinkType  uint16     `capnp:"peerLinkType"`
	RawIA         addr.IAInt `capnp:"isdas"`
}

func (s *DenseASLinkType) ProtoId() proto.ProtoIdType {
	return proto.PathMetadata_InterfaceLinkType_TypeID
}

func (s *DenseASLinkType) String() string {
	return fmt.Sprintf("InterLinkType: %d\nPeerLinkType: %d\nISD: %d\nAS: %d\n",
		s.InterLinkType, s.PeerLinkType, s.RawIA.IA().I, s.RawIA.IA().A)
}

type DenseGeo struct {
	RouterLocations []DenseGeoLoc `capnp:"routerLocations"`
	RawIA           addr.IAInt    `capnp:"isdas"`
}

func (s *DenseGeo) ProtoId() proto.ProtoIdType {
	return proto.PathMetadata_Geo_TypeID
}

func (s *DenseGeo) String() string {
	return fmt.Sprintf("RouterLocations: %v\nISD: %d\nAS: %d\n",
		s.RouterLocations, s.RawIA.IA().I, s.RawIA.IA().A)
}

type DenseGeoLoc struct {
	Latitude  float32 `capnp:"latitude"`
	Longitude float32 `capnp:"longitude"`
	Address   string  `capnp:"address"`
}

func (s *DenseGeoLoc) ProtoId() proto.ProtoIdType {
	return proto.PathMetadata_Geo_GPSData_TypeID
}

func (s *DenseGeoLoc) String() string {
	return fmt.Sprintf("Latitude: %f\nLongitude: %f\nAddress: %s\n",
		s.Latitude, s.Longitude, s.Address)
}

type DenseNote struct {
	Note  string     `capnp:"note"`
	RawIA addr.IAInt `capnp:"isdas"`
}

func (s *DenseNote) ProtoId() proto.ProtoIdType {
	return proto.PathMetadata_Note_TypeID
}

func (s *DenseNote) String() string {
	return fmt.Sprintf("Text: %s\nISD: %d\nAS: %d\n",
		s.Note, s.RawIA.IA().I, s.RawIA.IA().A)
}

// Condensemetadata takes RawPathMetadata and extracts/condenses
// the most important values to be transmitted to SCIOND
func Condensemetadata(data *combinator.PathMetadata) *PathMetadata {
	ret := &PathMetadata{
		TotalLatency: 0,
		TotalHops:    0,
		MinOfMaxBWs:  math.MaxUint32,
	}

	for _, val := range data.ASBandwidths {
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

	for _, val := range data.ASLatencies {
		ret.TotalLatency += val.InterLatency + val.IntraLatency + val.PeerLatency
	}

	for _, val := range data.ASHops {
		ret.TotalHops += val.Hops
	}

	for ia, note := range data.Notes {
		ret.Notes = append(ret.Notes, DenseNote{
			Note:  note.Note,
			RawIA: ia.IAInt(),
		})
	}

	for ia, loc := range data.Geo {
		newloc := DenseGeo{
			RouterLocations: []DenseGeoLoc{},
			RawIA:           ia.IAInt(),
		}
		for _, gpsdata := range loc.Locations {
			newloc.RouterLocations = append(newloc.RouterLocations,
				DenseGeoLoc{
					Latitude:  gpsdata.Latitude,
					Longitude: gpsdata.Longitude,
					Address:   gpsdata.Address,
				})
		}
		ret.Locations = append(ret.Locations, newloc)
	}

	for ia, link := range data.Links {
		ret.LinkTypes = append(ret.LinkTypes, DenseASLinkType{
			InterLinkType: link.InterLinkType,
			PeerLinkType:  link.PeerLinkType,
			RawIA:         ia.IAInt(),
		})
	}

	return ret
}
