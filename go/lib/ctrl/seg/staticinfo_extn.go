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
	"github.com/scionproto/scion/go/lib/common"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

type StaticInfoExtension struct {
	Latency   *LatencyInfo
	Geo       GeoInfo
	LinkType  LinkTypeInfo
	Bandwidth *BandwidthInfo
	Hops      InternalHopsInfo
	Note      string
}

// TODO(matzf): change to time.Duration
type LatencyInfo struct {
	Intra      uint32
	Inter      uint32
	XoverIntra map[common.IFIDType]uint32
	Peers      map[common.IFIDType]PeerLatencyInfo
}

type PeerLatencyInfo struct {
	Inter uint32
	Intra uint32
}

type GeoInfo map[common.IFIDType]GeoCoordinates

type GeoCoordinates struct {
	Latitude  float32
	Longitude float32
	Address   string
}

type LinkType uint8

const (
	LinkTypeDirect   = 0
	LinkTypeMultihop = 1
	LinkTypeOpennet  = 2
)

type LinkTypeInfo map[common.IFIDType]LinkType

type BandwidthInfo struct {
	Intra      uint32
	Inter      uint32
	XoverIntra map[common.IFIDType]uint32
	Peers      map[common.IFIDType]PeerBandwidthInfo
}

type PeerBandwidthInfo struct {
	Inter uint32
	Intra uint32
}

type InternalHopsInfo struct {
	InToOutHops   uint8
	InterfaceHops []InterfaceHops
}

type InterfaceHops struct {
	Hops uint8
	IfID common.IFIDType
}

func staticInfoExtensionFromPB(pb *cppb.StaticInfoExtension) (*StaticInfoExtension, error) {
	if pb == nil {
		return nil, nil
	}

	latency, err := latencyInfoFromPB(pb.Latency)
	if err != nil {
		return nil, err
	}

	geo, err := geoInfoFromPB(pb.Geo)
	if err != nil {
		return nil, err
	}

	staticInfo := &StaticInfoExtension{
		Latency: latency,
		Geo:     geo,
		Note:    pb.Note,
	}

	return staticInfo, nil
}

func latencyInfoFromPB(pb *cppb.LatencyInfo) (*LatencyInfo, error) {
	if pb == nil {
		return nil, nil
	}
	xoverIntra := make(map[common.IFIDType]uint32)
	for ifid, v := range pb.XoverIntra {
		xoverIntra[common.IFIDType(ifid)] = v
	}
	peers := make(map[common.IFIDType]PeerLatencyInfo)
	for ifid, v := range pb.Peers {
		peers[common.IFIDType(ifid)] = PeerLatencyInfo{
			Intra: v.Intra,
			Inter: v.Inter,
		}
	}
	return &LatencyInfo{
		Intra:      pb.Intra,
		Inter:      pb.Inter,
		XoverIntra: xoverIntra,
		Peers:      peers,
	}, nil
}

func geoInfoFromPB(pb map[uint64]*cppb.GeoCoordinates) (GeoInfo, error) {
	gi := make(GeoInfo)
	for ifid, v := range pb {
		gi[common.IFIDType(ifid)] = GeoCoordinates{
			Latitude:  v.Latitude,
			Longitude: v.Longitude,
			Address:   v.Address,
		}
	}
	return gi, nil
}

func staticInfoToPB(si *StaticInfoExtension) *cppb.StaticInfoExtension {
	if si == nil {
		return nil
	}

	return &cppb.StaticInfoExtension{
		Latency: latencyInfoToPB(si.Latency),
		Geo:     geoInfoToPB(si.Geo),
		Note:    si.Note,
	}
}

func latencyInfoToPB(li *LatencyInfo) *cppb.LatencyInfo {
	if li == nil {
		return nil
	}
	xoverIntra := make(map[uint64]uint32)
	for ifid, v := range li.XoverIntra {
		xoverIntra[uint64(ifid)] = v
	}
	peers := make(map[uint64]*cppb.LatencyInfo_PeerInfo)
	for ifid, v := range li.Peers {
		peers[uint64(ifid)] = &cppb.LatencyInfo_PeerInfo{
			Intra: v.Intra,
			Inter: v.Inter,
		}
	}
	return &cppb.LatencyInfo{
		Intra:      li.Intra,
		Inter:      li.Inter,
		XoverIntra: xoverIntra,
		Peers:      peers,
	}
}

func geoInfoToPB(gi GeoInfo) map[uint64]*cppb.GeoCoordinates {
	pb := make(map[uint64]*cppb.GeoCoordinates)
	for ifid, v := range gi {
		pb[uint64(ifid)] = &cppb.GeoCoordinates{
			Latitude:  v.Latitude,
			Longitude: v.Longitude,
			Address:   v.Address,
		}
	}
	return pb
}
