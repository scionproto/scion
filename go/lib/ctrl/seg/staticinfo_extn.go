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
	"time"

	"github.com/scionproto/scion/go/lib/common"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

type StaticInfoExtension struct {
	Latency   *LatencyInfo
	Geo       GeoInfo
	LinkType  LinkTypeInfo
	Bandwidth *BandwidthInfo
	Hops      *InternalHopsInfo
	Note      string
}

type LatencyInfo struct {
	Intra      time.Duration
	Inter      time.Duration
	XoverIntra map[common.IFIDType]time.Duration
	PeerInter  map[common.IFIDType]time.Duration
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
	PeerInter  map[common.IFIDType]uint32
}

type InternalHopsInfo struct {
	Hops      uint32
	XoverHops map[common.IFIDType]uint32
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
	xoverIntra := make(map[common.IFIDType]time.Duration)
	for ifid, v := range pb.XoverIntra {
		xoverIntra[common.IFIDType(ifid)] = time.Duration(v) * time.Microsecond
	}
	peerInter := make(map[common.IFIDType]time.Duration)
	for ifid, v := range pb.PeerInter {
		peerInter[common.IFIDType(ifid)] = time.Duration(v) * time.Microsecond
	}
	return &LatencyInfo{
		Intra:      time.Duration(pb.Intra) * time.Microsecond,
		Inter:      time.Duration(pb.Inter) * time.Microsecond,
		XoverIntra: xoverIntra,
		PeerInter:  peerInter,
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
		xoverIntra[uint64(ifid)] = uint32(v.Microseconds())
	}
	peerInter := make(map[uint64]uint32)
	for ifid, v := range li.PeerInter {
		peerInter[uint64(ifid)] = uint32(v.Microseconds())
	}
	return &cppb.LatencyInfo{
		Intra:      uint32(li.Intra.Microseconds()),
		Inter:      uint32(li.Inter.Microseconds()),
		XoverIntra: xoverIntra,
		PeerInter:  peerInter,
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
