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

import "github.com/scionproto/scion/go/lib/common"

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
