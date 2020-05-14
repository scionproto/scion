// Copyright 2020 ETH Zurich
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

package seg

import (
	"fmt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

type LatencyInfo struct {
	Egresslatency          uint16         `capnp:"egressLatency"`
	IngressToEgressLatency uint16         `capnp:"ingressToEgressLatency"`
	Childlatencies         []ChildLatency `capnp:"childLatencies"`
	Peerlatencies          []PeerLatency  `capnp:"peeringLatencies"`
}

func (s *LatencyInfo) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_LatencyInfo_TypeID
}

func (s *LatencyInfo) String() string {
	return fmt.Sprintf("IngressToEgressLatency: %d\nEgressLatency: %d\n"+
		"Childlatencies: %v\nPeerlatencies: %v\n", s.IngressToEgressLatency,
		s.Egresslatency, s.Childlatencies, s.Peerlatencies)
}

type ChildLatency struct {
	Intradelay uint16          `capnp:"intra"`
	IfID       common.IFIDType `capnp:"ifID"`
}

func (s *ChildLatency) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_LatencyInfo_ChildLatency_TypeID
}

func (s *ChildLatency) String() string {
	return fmt.Sprintf("Intralatency: %d\nIfID: %d\n",
		s.Intradelay, s.IfID)
}

type PeerLatency struct {
	Interdelay uint16          `capnp:"inter"`
	IntraDelay uint16          `capnp:"intra"`
	IfID       common.IFIDType `capnp:"ifID"`
}

func (s *PeerLatency) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_LatencyInfo_PeerLatency_TypeID
}

func (s *PeerLatency) String() string {
	return fmt.Sprintf("Intralatency: %d\n"+
		"Interlatency: %d\nIfID: %d\n", s.IntraDelay, s.Interdelay, s.IfID)
}

type BandwidthInfo struct {
	EgressBW          uint32               `capnp:"egressBW"`
	IngressToEgressBW uint32               `capnp:"ingressToEgressBW"`
	Bandwidths        []InterfaceBandwidth `capnp:"bandwidths"`
}

func (s *BandwidthInfo) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_BandwidthInfo_TypeID
}

func (s *BandwidthInfo) String() string {
	return fmt.Sprintf("IngressToEgressBW: %d\n"+
		"EgressBW: %d\nInterfaceBandwidths: %v\n", s.IngressToEgressBW,
		s.EgressBW, s.Bandwidths)
}

type InterfaceBandwidth struct {
	BW   uint32          `capnp:"bw"`
	IfID common.IFIDType `capnp:"ifID"`
}

func (s *InterfaceBandwidth) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_BandwidthInfo_InterfaceBandwidth_TypeID
}

func (s *InterfaceBandwidth) String() string {
	return fmt.Sprintf("BW: %d\nIfID: %d\n", s.BW, s.IfID)
}

type GeoInfo struct {
	Locations []Location `capnp:"locations"`
}

func (s *GeoInfo) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_GeoInfo_TypeID
}

func (s *GeoInfo) String() string {
	return fmt.Sprintf("Locations: %v\n", s.Locations)
}

type Location struct {
	GPSData Coordinates       `capnp:"gpsData"`
	IfIDs   []common.IFIDType `capnp:"interfaces"`
}

func (s *Location) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_GeoInfo_Location_TypeID
}

func (s *Location) String() string {
	return fmt.Sprintf("Location: %v\n"+
		"IfIDs: %v\n", s.GPSData, s.IfIDs)
}

type Coordinates struct {
	Latitude  float32 `capnp:"latitude"`
	Longitude float32 `capnp:"longitude"`
	Address   string  `capnp:"address"`
}

func (s *Coordinates) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_GeoInfo_Location_Coordinates_TypeID
}

func (s *Coordinates) String() string {
	return fmt.Sprintf("Latitude %f\n"+
		"Longitude: %f\nAddress: %s\n", s.Latitude,
		s.Longitude, s.Address)
}

type LinktypeInfo struct {
	EgressLinkType uint16              `capnp:"egressLinkType"`
	Peerlinks      []InterfaceLinkType `capnp:"peeringLinks"`
}

func (s *LinktypeInfo) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_LinkTypeInfo_TypeID
}

func (s *LinktypeInfo) String() string {
	return fmt.Sprintf("EgressLinkType: %d\n"+
		"PeerLinkTypes: %v\n", s.EgressLinkType, s.Peerlinks)
}

type InterfaceLinkType struct {
	IfID     common.IFIDType `capnp:"ifID"`
	LinkType uint16          `capnp:"linkType"`
}

func (s *InterfaceLinkType) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_LinkTypeInfo_InterfaceLinkType_TypeID
}

func (s *InterfaceLinkType) String() string {
	return fmt.Sprintf("LinkType: %d\n"+
		"IfID: %d\n", s.LinkType, s.IfID)
}

type InternalHopsInfo struct {
	InToOutHops   uint8           `capnp:"inToOutHops"`
	InterfaceHops []InterfaceHops `capnp:"interfaceHops"`
}

func (s *InternalHopsInfo) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_InternalHopsInfo_TypeID
}

func (s *InternalHopsInfo) String() string {
	return fmt.Sprintf("InToOutHops: %d\n"+
		"InterfaceHops: %v\n", s.InToOutHops, s.InterfaceHops)
}

type InterfaceHops struct {
	Hops uint8           `capnp:"hops"`
	IfID common.IFIDType `capnp:"ifID"`
}

func (s *InterfaceHops) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_InternalHopsInfo_InterfaceHops_TypeID
}

func (s *InterfaceHops) String() string {
	return fmt.Sprintf("Hops: %d\nIfID: %d\n", s.Hops, s.IfID)
}

type StaticInfoExtn struct {
	Latency   LatencyInfo      `capnp:"latency"`
	Geo       GeoInfo          `capnp:"geo"`
	Linktype  LinktypeInfo     `capnp:"linktype"`
	Bandwidth BandwidthInfo    `capnp:"bandwidth"`
	Hops      InternalHopsInfo `capnp:"internalHops"`
	Note      string           `capnp:"note"`
}

func (s *StaticInfoExtn) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_TypeID
}

func (s *StaticInfoExtn) String() string {
	return fmt.Sprintf("Latency: %v\nGeo: %v\n"+
		"Linktype: %v\nBandwidth: %v\nHops: %v\nNote: %v\n",
		s.Latency, s.Geo, s.Linktype, s.Bandwidth, s.Hops, s.Note)
}

func (s *StaticInfoExtn) AppendIfIDToSIForTesting (peer bool, ifID, egifID common.IFIDType) {
	if peer {
		s.Latency.Peerlatencies = append(s.Latency.Peerlatencies, PeerLatency{
			Interdelay: uint16(ifID),
			IntraDelay: uint16(ifID),
			IfID:       ifID,
		})
		s.Linktype.Peerlinks = append(s.Linktype.Peerlinks, InterfaceLinkType{
			IfID:     ifID,
			LinkType: uint16(ifID) % 3,
		})
	} else {
		s.Latency.Childlatencies = append(s.Latency.Childlatencies, ChildLatency{
				Intradelay: uint16(ifID),
				IfID:       ifID,
			})
	}
	s.Bandwidth.Bandwidths = append(s.Bandwidth.Bandwidths, InterfaceBandwidth{
			BW: uint32(ifID),
			IfID:       ifID,
		})
	s.Hops.InterfaceHops = append(s.Hops.InterfaceHops, InterfaceHops{
			Hops: uint8(ifID),
			IfID:       ifID,
		})
	s.Geo.Locations[0].IfIDs = append(s.Geo.Locations[0].IfIDs, ifID)

	if (ifID == egifID){
		s.Latency.IngressToEgressLatency = uint16(ifID)
		s.Latency.Egresslatency = uint16(ifID)
		s.Linktype.EgressLinkType = uint16(ifID) % 3
		s.Bandwidth.EgressBW = uint32(ifID)
		s.Bandwidth.IngressToEgressBW = uint32(ifID)
		s.Hops.InToOutHops = uint8(ifID)
	}
}

func (s *StaticInfoExtn) InitializeStaticInfo() {
	geo := GeoInfo{
		Locations: []Location{{}},
	}
	latency := LatencyInfo{
		Egresslatency:          0,
		IngressToEgressLatency: 0,
		Childlatencies:         []ChildLatency{{}},
		Peerlatencies:          []PeerLatency{{}},
	}
	linktype := LinktypeInfo{
		EgressLinkType: 0,
		Peerlinks:      []InterfaceLinkType{{}},
	}
	bandwidth := BandwidthInfo{
		EgressBW:          0,
		IngressToEgressBW: 0,
		Bandwidths:        []InterfaceBandwidth{{}},
	}
	hops :=  InternalHopsInfo{
		InToOutHops:   0,
		InterfaceHops: []InterfaceHops{{}},
	}
	s = &StaticInfoExtn{
		Latency: latency,
		Geo:       geo,
		Linktype:  linktype,
		Bandwidth: bandwidth,
		Hops: hops,
		Note:      "",
	}
}
