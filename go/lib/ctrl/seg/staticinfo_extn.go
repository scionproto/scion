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
	"github.com/scionproto/scion/go/lib/serrors"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

type StaticInfoExtension struct {
	Latency      *LatencyInfo
	Geo          GeoInfo
	LinkType     LinkTypeInfo
	Bandwidth    *BandwidthInfo
	InternalHops InternalHopsInfo
	Note         string
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
	LinkTypeDirect = iota
	LinkTypeMultihop
	LinkTypeOpennet
)

type LinkTypeInfo map[common.IFIDType]LinkType

type BandwidthInfo struct {
	Intra      uint32
	Inter      uint32
	XoverIntra map[common.IFIDType]uint32
	PeerInter  map[common.IFIDType]uint32
}

type InternalHopsInfo map[common.IFIDType]uint32

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
	linkType, err := linkTypeInfoFromPB(pb.LinkType)
	if err != nil {
		return nil, err
	}
	bandwidth, err := bandwidthInfoFromPB(pb.Bandwidth)
	if err != nil {
		return nil, err
	}
	internalHops, err := internalHopsInfoFromPB(pb.InternalHops)
	if err != nil {
		return nil, err
	}

	staticInfo := &StaticInfoExtension{
		Latency:      latency,
		Geo:          geo,
		LinkType:     linkType,
		Bandwidth:    bandwidth,
		InternalHops: internalHops,
		Note:         pb.Note,
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

func linkTypeInfoFromPB(pb map[uint64]cppb.LinkType) (LinkTypeInfo, error) {
	lti := make(LinkTypeInfo)
	for ifid, vpb := range pb {
		var v LinkType
		switch vpb {
		case cppb.LinkType_LINK_TYPE_UNSPECIFIED:
			continue
		case cppb.LinkType_LINK_TYPE_DIRECT:
			v = LinkTypeDirect
		case cppb.LinkType_LINK_TYPE_MULTI_HOP:
			v = LinkTypeMultihop
		case cppb.LinkType_LINK_TYPE_OPEN_NET:
			v = LinkTypeOpennet
		default:
			return nil, serrors.New("invalid link type option", "link type", vpb)
		}
		lti[common.IFIDType(ifid)] = v
	}
	return lti, nil
}

func bandwidthInfoFromPB(pb *cppb.BandwidthInfo) (*BandwidthInfo, error) {
	if pb == nil {
		return nil, nil
	}
	xoverIntra := make(map[common.IFIDType]uint32)
	for ifid, v := range pb.XoverIntra {
		xoverIntra[common.IFIDType(ifid)] = v
	}
	peerInter := make(map[common.IFIDType]uint32)
	for ifid, v := range pb.PeerInter {
		peerInter[common.IFIDType(ifid)] = v
	}
	return &BandwidthInfo{
		Intra:      pb.Intra,
		Inter:      pb.Inter,
		XoverIntra: xoverIntra,
		PeerInter:  peerInter,
	}, nil
}

func internalHopsInfoFromPB(pb map[uint64]uint32) (InternalHopsInfo, error) {
	if pb == nil {
		return nil, nil
	}
	ihi := make(InternalHopsInfo)
	for ifid, v := range pb {
		ihi[common.IFIDType(ifid)] = v
	}
	return ihi, nil
}

func staticInfoExtensionToPB(si *StaticInfoExtension) *cppb.StaticInfoExtension {
	if si == nil {
		return nil
	}

	return &cppb.StaticInfoExtension{
		Latency:      latencyInfoToPB(si.Latency),
		Geo:          geoInfoToPB(si.Geo),
		LinkType:     linkTypeInfoToPB(si.LinkType),
		Bandwidth:    bandwidthInfoToPB(si.Bandwidth),
		InternalHops: internalHopsInfoToPB(si.InternalHops),
		Note:         si.Note,
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

func linkTypeInfoToPB(lti LinkTypeInfo) map[uint64]cppb.LinkType {
	pb := make(map[uint64]cppb.LinkType)
	for ifid, v := range lti {
		var vpb cppb.LinkType
		switch v {
		case LinkTypeDirect:
			vpb = cppb.LinkType_LINK_TYPE_DIRECT
		case LinkTypeMultihop:
			vpb = cppb.LinkType_LINK_TYPE_MULTI_HOP
		case LinkTypeOpennet:
			vpb = cppb.LinkType_LINK_TYPE_OPEN_NET
		default:
			continue
		}
		pb[uint64(ifid)] = vpb
	}
	return pb
}

func bandwidthInfoToPB(bwi *BandwidthInfo) *cppb.BandwidthInfo {
	if bwi == nil {
		return nil
	}
	xoverIntra := make(map[uint64]uint32)
	for ifid, v := range bwi.XoverIntra {
		xoverIntra[uint64(ifid)] = v
	}
	peerInter := make(map[uint64]uint32)
	for ifid, v := range bwi.PeerInter {
		peerInter[uint64(ifid)] = v
	}
	return &cppb.BandwidthInfo{
		Intra:      bwi.Intra,
		Inter:      bwi.Inter,
		XoverIntra: xoverIntra,
		PeerInter:  peerInter,
	}
}

func internalHopsInfoToPB(ihi InternalHopsInfo) map[uint64]uint32 {
	if ihi == nil {
		return nil
	}
	pb := make(map[uint64]uint32)
	for ifid, v := range ihi {
		pb[uint64(ifid)] = v
	}
	return pb
}
