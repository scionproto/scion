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

type ChildLatency struct {
	Intradelay uint16          `capnp:"intra"`
	IfID       common.IFIDType `capnp:"ifID"`
}

type PeerLatency struct {
	Interdelay uint16          `capnp:"inter"`
	IntraDelay uint16          `capnp:"intra"`
	IfID       common.IFIDType `capnp:"ifID"`
}

type BandwidthInfo struct {
	EgressBW          uint32               `capnp:"egressBW"`
	IngressToEgressBW uint32               `capnp:"ingressToEgressBW"`
	Bandwidths        []InterfaceBandwidth `capnp:"bandwidths"`
}

type InterfaceBandwidth struct {
	BW   uint32          `capnp:"bw"`
	IfID common.IFIDType `capnp:"ifID"`
}

type GeoInfo struct {
	Locations []Location `capnp:"locations"`
}

type Location struct {
	GPSData Coordinates       `capnp:"gpsData"`
	IfIDs   []common.IFIDType `capnp:"interfaces"`
}

type Coordinates struct {
	Latitude  float32 `capnp:"latitude"`
	Longitude float32 `capnp:"longitude"`
	Address   string  `capnp:"address"`
}

type LinktypeInfo struct {
	EgressLinkType uint16              `capnp:"egressLinkType"`
	Peerlinks      []InterfaceLinkType `capnp:"peeringLinks"`
}

type InterfaceLinkType struct {
	IfID     common.IFIDType `capnp:"ifID"`
	LinkType uint16          `capnp:"linkType"`
}

type InternalHopsInfo struct {
	InToOutHops   uint8           `capnp:"inToOutHops"`
	InterfaceHops []InterfaceHops `capnp:"interfaceHops"`
}

type InterfaceHops struct {
	Hops uint8           `capnp:"hops"`
	IfID common.IFIDType `capnp:"ifID"`
}

type StaticInfoExtn struct {
	Latency   LatencyInfo      `capnp:"latency"`
	Geo       GeoInfo          `capnp:"geo"`
	Linktype  LinktypeInfo     `capnp:"linktype"`
	Bandwidth BandwidthInfo    `capnp:"bandwidth"`
	Hops      InternalHopsInfo `capnp:"internalHops"`
	Note      string           `capnp:"note"`
}

func (s *ChildLatency) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_LatencyInfo_ChildLatency_TypeID
}

func (s *ChildLatency) String() string{
	return fmt.Sprintf("Intralatency: %d\nIfID: %d\n", s.Intradelay, s.IfID)
}

func (s *PeerLatency) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_LatencyInfo_PeerLatency_TypeID
}

func (s *PeerLatency) String() string{
	return fmt.Sprintf("Intralatency: %d\nInterlatency: %d\nIfID: %d\n", s.IntraDelay, s.Interdelay, s.IfID)
}

func (s *LatencyInfo) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_LatencyInfo_TypeID
}

func (s *LatencyInfo) String() string{
	return fmt.Sprintf("IngressToEgressLatency: %d\nEgressLatency: %d\nChildlatencies: %v\nPeerlatencies: %v\n", s.IngressToEgressLatency, s.Egresslatency, s.Childlatencies, s.Peerlatencies)
}

func (s *InterfaceBandwidth) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_BandwidthInfo_InterfaceBandwidth_TypeID
}

func (s *InterfaceBandwidth) String() string{
	return fmt.Sprintf("BW: %d\nIfID: %d\n", s.BW, s.IfID)
}

func (s *BandwidthInfo) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_BandwidthInfo_TypeID
}

func (s *BandwidthInfo) String() string{
	return fmt.Sprintf("IngressToEgressBW: %d\nEgressBW: %d\nInterfaceBandwidths: %v\n", s.IngressToEgressBW, s.EgressBW, s.Bandwidths)
}

func (s *Coordinates) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_GeoInfo_Location_Coordinates_TypeID
}

func (s *Coordinates) String() string{
	return fmt.Sprintf("Latitude %f\nLongitude: %f\nAddress: %s\n", s.Latitude, s.Longitude, s.Address)
}

func (s *Location) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_GeoInfo_Location_TypeID
}

func (s *Location) String() string{
	return fmt.Sprintf("Location: %v\nIfIDs: %v\n", s.GPSData, s.IfIDs)
}

func (s *GeoInfo) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_GeoInfo_TypeID
}

func (s *GeoInfo) String() string{
	return fmt.Sprintf("Locations: %v\n", s.Locations)
}

func (s *InterfaceLinkType) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_LinkTypeInfo_InterfaceLinkType_TypeID
}

func (s *InterfaceLinkType) String() string{
	return fmt.Sprintf("LinkType: %d\nIfID: %d\n", s.LinkType, s.IfID)
}

func (s *LinktypeInfo) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_LinkTypeInfo_TypeID
}

func (s *LinktypeInfo) String() string{
	return fmt.Sprintf("EgressLinkType: %d\nPeerLinkTypes: %v\n", s.EgressLinkType, s.Peerlinks)
}

func (s *InterfaceHops) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_InternalHopsInfo_InterfaceHops_TypeID
}

func (s *InterfaceHops) String() string{
	return fmt.Sprintf("Hops: %d\nIfID: %d\n", s.Hops, s.IfID)
}

func (s *InternalHopsInfo) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_InternalHopsInfo_TypeID
}

func (s *InternalHopsInfo) String() string{
	return fmt.Sprintf("InToOutHops: %d\nInterfaceHops: %v\n", s.InToOutHops, s.InterfaceHops)
}

func (s *StaticInfoExtn) ProtoId() proto.ProtoIdType {
	return proto.StaticInfoExtn_TypeID
}

func (s *StaticInfoExtn) String() string{
	return fmt.Sprintf("Latency: %v\nGeo: %v\nLinktype: %v\nBandwidth: %v\nHops: %v\nNote: %v\n", s.Latency, s.Geo, s.Linktype, s.Bandwidth, s.Hops, s.Note)
}
