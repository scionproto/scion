package sciond

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/proto"
)

// PathMetadata is the condensed form of metadata retaining only the most important values.
type PathMetadata struct {
	TotalLatency uint16            `capnp:"totalLatency"`
	TotalHops    uint8             `capnp:"totalHops"`
	MinOfMaxBWs  uint32            `capnp:"minimalBandwidth"`
	LinkTypes    []*DenseASLinkType `capnp:"linkTypes"`
	Locations    []*DenseGeo        `capnp:"asLocations"`
	Notes        []*DenseNote       `capnp:"notes"`
}

func (s *PathMetadata) ProtoId() proto.ProtoIdType {
	return proto.PathMetadata_TypeID
}

func (s *PathMetadata) String() string {
	return fmt.Sprintf("\nTotalLatency: %v ms\nTotalHops: %v\n"+
		"BandwidthBottleneck: %v Kb/s\nLinkTypes: %v\nASLocations: %v\nNotes: %v\n",
		s.TotalLatency, s.TotalHops, s.MinOfMaxBWs, s.LinkTypes, s.Locations,
		s.Notes)
}

func reverseTransformLinkType(linktype uint16) string{
	switch linktype {
	case 3:
		return "opennet"
	case 2:
		return "multihop"
	case 1:
		return "direct"
	default:
		return "unset"
	}
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
	return fmt.Sprintf("\nInterLinkType: %s\nPeerLinkType: %s\nISD: %d\nAS: %d\nRawIA: %v\n",
		reverseTransformLinkType(s.InterLinkType), reverseTransformLinkType(s.PeerLinkType),
		s.RawIA.IA().I, s.RawIA.IA().A, s.RawIA.IA())
}

type DenseGeo struct {
	RouterLocations []*DenseGeoLoc `capnp:"routerLocations"`
	RawIA           addr.IAInt    `capnp:"isdas"`
}

func (s *DenseGeo) ProtoId() proto.ProtoIdType {
	return proto.PathMetadata_Geo_TypeID
}

func (s *DenseGeo) String() string {
	return fmt.Sprintf("\nRouterLocations: %v\nISD: %d\nAS: %d\nRawIA: %v\n",
		s.RouterLocations, s.RawIA.IA().I, s.RawIA.IA().A, s.RawIA.IA())
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
	return fmt.Sprintf("Latitude: %f, Longitude: %f, Address: %s",
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
	return fmt.Sprintf("\nText: %s\nISD: %d\nAS: %d\nRawIA: %v\n",
		s.Note, s.RawIA.IA().I, s.RawIA.IA().A, s.RawIA.IA())
}
