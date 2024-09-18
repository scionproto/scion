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

	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/segment/iface"
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
	Intra map[iface.ID]time.Duration
	Inter map[iface.ID]time.Duration
}

// BandwidthInfo is the internal repesentation of `bandwidth` in the
// StaticInfoExtension.
type BandwidthInfo struct {
	Intra map[iface.ID]uint64
	Inter map[iface.ID]uint64
}

// GeoInfo is the internal repesentation of `geo` in the
// StaticInfoExtension.
type GeoInfo map[iface.ID]GeoCoordinates

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
type LinkTypeInfo map[iface.ID]LinkType

// InternalHopsInfo is the internal representation of `internal_hops` in the
// StaticInfoExtension.
type InternalHopsInfo map[iface.ID]uint32

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
	intra := make(map[iface.ID]time.Duration, len(pb.Intra))
	for ifID, v := range pb.Intra {
		intra[iface.ID(ifID)] = time.Duration(v) * time.Microsecond
	}
	inter := make(map[iface.ID]time.Duration, len(pb.Inter))
	for ifID, v := range pb.Inter {
		inter[iface.ID(ifID)] = time.Duration(v) * time.Microsecond
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
	intra := make(map[iface.ID]uint64, len(pb.Intra))
	for ifID, v := range pb.Intra {
		intra[iface.ID(ifID)] = v
	}
	inter := make(map[iface.ID]uint64, len(pb.Inter))
	for ifID, v := range pb.Inter {
		inter[iface.ID(ifID)] = v
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
	for ifID, v := range pb {
		gi[iface.ID(ifID)] = GeoCoordinates{
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
	for ifID, vpb := range pb {
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
		lti[iface.ID(ifID)] = v
	}
	return lti
}

func internalHopsInfoFromPB(pb map[uint64]uint32) InternalHopsInfo {
	if len(pb) == 0 {
		return nil
	}
	ihi := make(InternalHopsInfo, len(pb))
	for ifID, v := range pb {
		ihi[iface.ID(ifID)] = v
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
	for ifID, v := range li.Intra {
		intra[uint64(ifID)] = uint32(v.Microseconds())
	}
	inter := make(map[uint64]uint32, len(li.Inter))
	for ifID, v := range li.Inter {
		inter[uint64(ifID)] = uint32(v.Microseconds())
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
	for ifID, v := range bwi.Intra {
		intra[uint64(ifID)] = v
	}
	inter := make(map[uint64]uint64, len(bwi.Inter))
	for ifID, v := range bwi.Inter {
		inter[uint64(ifID)] = v
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
	for ifID, v := range gi {
		pb[uint64(ifID)] = &cppb.GeoCoordinates{
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
	for ifID, v := range lti {
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
		pb[uint64(ifID)] = vpb
	}
	return pb
}

func internalHopsInfoToPB(ihi InternalHopsInfo) map[uint64]uint32 {
	if len(ihi) == 0 {
		return nil
	}
	pb := make(map[uint64]uint32, len(ihi))
	for ifID, v := range ihi {
		pb[uint64(ifID)] = v
	}
	return pb
}
