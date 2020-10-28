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

// Package staticinfo contains the internal representation of the
// StaticInfoExtension path segment extension, and conversion from and to the
// corresponding protobuf representation.
// See also StaticInfoExtension in proto/control_plane/v1/seg_extensions.proto.
package staticinfo

import (
	"time"

	"github.com/scionproto/scion/go/lib/common"
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

// Extension is the internal repesentation of the StaticInfoExtension path
// segment extension.
type Extension struct {
	Latency      LatencyInfo
	Bandwidth    BandwidthInfo
	Geo          GeoInfo
	LinkType     LinkTypeInfo
	InternalHops InternalHopsInfo
	Note         string
}

// LatencyInfo is the internal repesentation of `latency` in the
// StaticInfoExtension.
type LatencyInfo struct {
	Intra map[common.IFIDType]time.Duration
	Inter map[common.IFIDType]time.Duration
}

// BandwidthInfo is the internal repesentation of `bandwidth` in the
// StaticInfoExtension.
type BandwidthInfo struct {
	Intra map[common.IFIDType]uint64
	Inter map[common.IFIDType]uint64
}

// GeoInfo is the internal repesentation of `geo` in the
// StaticInfoExtension.
type GeoInfo map[common.IFIDType]GeoCoordinates

// GeoCoordinates is the internal repesentation of the GeoCoordinates in the
// StaticInfoExtension.
type GeoCoordinates struct {
	Latitude  float32
	Longitude float32
	Address   string
}

// LinkType is the internal representation of the LinkType in the
// StaticInfoExtension.
// There is no UNSPECIFIED value here, as we can simply omit these from the
// internal map representation.
type LinkType uint8

const (
	LinkTypeDirect = iota
	LinkTypeMultihop
	LinkTypeOpennet
)

// LinkTypeInfo is the internal representation of `link_type` in the
// StaticInfoExtension.
type LinkTypeInfo map[common.IFIDType]LinkType

// InternalHopsInfo is the internal representation of `internal_hops` in the
// StaticInfoExtension.
type InternalHopsInfo map[common.IFIDType]uint32

// FromPB creates the staticinfo Extension from the protobuf representation.
func FromPB(pb *cppb.StaticInfoExtension) *Extension {
	if pb == nil {
		return nil
	}
	return &Extension{
		Latency:      latencyInfoFromPB(pb.Latency),
		Bandwidth:    bandwidthInfoFromPB(pb.Bandwidth),
		Geo:          geoInfoFromPB(pb.Geo),
		LinkType:     linkTypeInfoFromPB(pb.LinkType),
		InternalHops: internalHopsInfoFromPB(pb.InternalHops),
		Note:         pb.Note,
	}
}

func latencyInfoFromPB(pb *cppb.LatencyInfo) LatencyInfo {
	if pb == nil || len(pb.Intra) == 0 && len(pb.Inter) == 0 {
		return LatencyInfo{}
	}
	intra := make(map[common.IFIDType]time.Duration, len(pb.Intra))
	for ifid, v := range pb.Intra {
		intra[common.IFIDType(ifid)] = time.Duration(v) * time.Microsecond
	}
	inter := make(map[common.IFIDType]time.Duration, len(pb.Inter))
	for ifid, v := range pb.Inter {
		inter[common.IFIDType(ifid)] = time.Duration(v) * time.Microsecond
	}
	return LatencyInfo{
		Intra: intra,
		Inter: inter,
	}
}

func bandwidthInfoFromPB(pb *cppb.BandwidthInfo) BandwidthInfo {
	if pb == nil || len(pb.Intra) == 0 && len(pb.Inter) == 0 {
		return BandwidthInfo{}
	}
	intra := make(map[common.IFIDType]uint64, len(pb.Intra))
	for ifid, v := range pb.Intra {
		intra[common.IFIDType(ifid)] = v
	}
	inter := make(map[common.IFIDType]uint64, len(pb.Inter))
	for ifid, v := range pb.Inter {
		inter[common.IFIDType(ifid)] = v
	}
	return BandwidthInfo{
		Intra: intra,
		Inter: inter,
	}
}

func geoInfoFromPB(pb map[uint64]*cppb.GeoCoordinates) GeoInfo {
	if len(pb) == 0 {
		return nil
	}
	gi := make(GeoInfo, len(pb))
	for ifid, v := range pb {
		gi[common.IFIDType(ifid)] = GeoCoordinates{
			Latitude:  v.Latitude,
			Longitude: v.Longitude,
			Address:   v.Address,
		}
	}
	return gi
}

func linkTypeInfoFromPB(pb map[uint64]cppb.LinkType) LinkTypeInfo {
	if len(pb) == 0 {
		return nil
	}
	lti := make(LinkTypeInfo, len(pb))
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
			continue
		}
		lti[common.IFIDType(ifid)] = v
	}
	return lti
}

func internalHopsInfoFromPB(pb map[uint64]uint32) InternalHopsInfo {
	if len(pb) == 0 {
		return nil
	}
	ihi := make(InternalHopsInfo, len(pb))
	for ifid, v := range pb {
		ihi[common.IFIDType(ifid)] = v
	}
	return ihi
}

// FromPB creates the protobuf representation for the staticinfo Extension.
func ToPB(si *Extension) *cppb.StaticInfoExtension {
	if si == nil {
		return nil
	}

	return &cppb.StaticInfoExtension{
		Latency:      latencyInfoToPB(si.Latency),
		Bandwidth:    bandwidthInfoToPB(si.Bandwidth),
		Geo:          geoInfoToPB(si.Geo),
		LinkType:     linkTypeInfoToPB(si.LinkType),
		InternalHops: internalHopsInfoToPB(si.InternalHops),
		Note:         si.Note,
	}
}

func latencyInfoToPB(li LatencyInfo) *cppb.LatencyInfo {
	if len(li.Intra) == 0 && len(li.Inter) == 0 {
		return nil
	}
	intra := make(map[uint64]uint32, len(li.Intra))
	for ifid, v := range li.Intra {
		intra[uint64(ifid)] = uint32(v.Microseconds())
	}
	inter := make(map[uint64]uint32, len(li.Inter))
	for ifid, v := range li.Inter {
		inter[uint64(ifid)] = uint32(v.Microseconds())
	}
	return &cppb.LatencyInfo{
		Intra: intra,
		Inter: inter,
	}
}

func bandwidthInfoToPB(bwi BandwidthInfo) *cppb.BandwidthInfo {
	if len(bwi.Intra) == 0 && len(bwi.Inter) == 0 {
		return nil
	}
	intra := make(map[uint64]uint64, len(bwi.Intra))
	for ifid, v := range bwi.Intra {
		intra[uint64(ifid)] = v
	}
	inter := make(map[uint64]uint64, len(bwi.Inter))
	for ifid, v := range bwi.Inter {
		inter[uint64(ifid)] = v
	}
	return &cppb.BandwidthInfo{
		Intra: intra,
		Inter: inter,
	}
}

func geoInfoToPB(gi GeoInfo) map[uint64]*cppb.GeoCoordinates {
	if len(gi) == 0 {
		return nil
	}
	pb := make(map[uint64]*cppb.GeoCoordinates, len(gi))
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
	if len(lti) == 0 {
		return nil
	}
	pb := make(map[uint64]cppb.LinkType, len(lti))
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

func internalHopsInfoToPB(ihi InternalHopsInfo) map[uint64]uint32 {
	if len(ihi) == 0 {
		return nil
	}
	pb := make(map[uint64]uint32, len(ihi))
	for ifid, v := range ihi {
		pb[uint64(ifid)] = v
	}
	return pb
}
