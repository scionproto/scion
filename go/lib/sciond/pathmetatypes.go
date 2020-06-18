package sciond

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/proto"
)

// PathMetadata is the condensed form of metadata retaining only the most important values.
type PathMetadata struct {
	Latency uint16             `capnp:"totalLatency"`
	Hops    uint8              `capnp:"totalHops"`
	Bandwidth  uint32             `capnp:"minimalBandwidth"`
	LinkTypes    []LinkType `capnp:"linkTypes"`
	Geos    []*Geo        `capnp:"asLocations"`
	Notes        []*Note       `capnp:"notes"`
}

func (s *PathMetadata) ProtoId() proto.ProtoIdType {
	return proto.FwdPathMeta_PathMetadata_TypeID
}

func (s *PathMetadata) String() string {
	return fmt.Sprintf("\nTotalLatency: %v ms\nTotalHops: %v\n"+
		"BandwidthBottleneck: %v Kb/s\nLinkTypes: %v\nASLocations: %v\nNotes: %v\n",
		s.Latency, s.Hops, s.Bandwidth, s.LinkTypes, s.Geos,
		s.Notes)
}

type LinkType uint16

const (
	LinkTypeUnset LinkType = iota
	LinkTypeDirect
	LinkTypeMultihop
	LinkTypeOpennet
)

func (t LinkType) String() string {
	switch t {
	case LinkTypeDirect:
		return "direct"
	case LinkTypeMultihop:
		return "multihop"
	case LinkTypeOpennet:
		return "opennet"
	default:
		return "unset"
	}
}

type Geo struct {
	RouterLocations []*GeoLoc `capnp:"routerLocations"`
	RawIA           addr.IAInt     `capnp:"isdas"`
}

func (s *Geo) ProtoId() proto.ProtoIdType {
	return proto.FwdPathMeta_PathMetadata_Geo_TypeID
}

func (s *Geo) String() string {
	return fmt.Sprintf("\nRouterLocations: %v\nISD: %d\nAS: %d\nRawIA: %v\n",
		s.RouterLocations, s.RawIA.IA().I, s.RawIA.IA().A, s.RawIA.IA())
}

type GeoLoc struct {
	Latitude  float32 `capnp:"latitude"`
	Longitude float32 `capnp:"longitude"`
	Address   string  `capnp:"address"`
}

func (s *GeoLoc) ProtoId() proto.ProtoIdType {
	return proto.FwdPathMeta_PathMetadata_Geo_GPSData_TypeID
}

func (s *GeoLoc) String() string {
	return fmt.Sprintf("Latitude: %f, Longitude: %f, Address: %s",
		s.Latitude, s.Longitude, s.Address)
}

type Note struct {
	Note  string     `capnp:"note"`
	RawIA addr.IAInt `capnp:"isdas"`
}

func (s *Note) ProtoId() proto.ProtoIdType {
	return proto.FwdPathMeta_PathMetadata_Note_TypeID
}

func (s *Note) String() string {
	return fmt.Sprintf("\nText: %s\nISD: %d\nAS: %d\nRawIA: %v\n",
		s.Note, s.RawIA.IA().I, s.RawIA.IA().A, s.RawIA.IA())
}
