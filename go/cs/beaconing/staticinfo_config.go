// Copyright 2020 ETH Zurich, Anapaya Systems
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

package beaconing

import (
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/serrors"
)

// TODO(matzf): parse as time.Duration values + sanity checks?
type InterfaceLatencies struct {
	Inter uint32                     `json:"Inter"`
	Intra map[common.IFIDType]uint32 `json:"Intra"`
}

type InterfaceBandwidths struct {
	Inter uint32                     `json:"Inter"`
	Intra map[common.IFIDType]uint32 `json:"Intra"`
}

type InterfaceGeodata struct {
	Longitude float32 `json:"Longitude"`
	Latitude  float32 `json:"Latitude"`
	Address   string  `json:"Address"`
}

type InterfaceHops struct {
	Intra map[common.IFIDType]uint8 `json:"Intra"`
}

type JSONLinkType seg.LinkType

func (l *JSONLinkType) MarshalText() ([]byte, error) {
	switch *l {
	case seg.LinkTypeDirect:
		return []byte("direct"), nil
	case seg.LinkTypeMultihop:
		return []byte("multihop"), nil
	case seg.LinkTypeOpennet:
		return []byte("opennet"), nil
	default:
		return nil, serrors.New("invalid link type value")
	}
}

func (l *JSONLinkType) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "direct":
		*l = seg.LinkTypeDirect
	case "multihop":
		*l = seg.LinkTypeMultihop
	case "opennet":
		*l = seg.LinkTypeOpennet
	default:
		return serrors.New("invalid link type", "link type", text)
	}
	return nil
}

// StaticInfoCfg is used to parse data from config.json.
type StaticInfoCfg struct {
	Latency   map[common.IFIDType]InterfaceLatencies  `json:"Latency"`
	Bandwidth map[common.IFIDType]InterfaceBandwidths `json:"Bandwidth"`
	LinkType  map[common.IFIDType]*JSONLinkType       `json:"LinkType"`
	Geo       map[common.IFIDType]InterfaceGeodata    `json:"Geo"`
	Hops      map[common.IFIDType]InterfaceHops       `json:"Hops"`
	Note      string                                  `json:"Note"`
}

// gatherLatency extracts latency values from a StaticInfoCfg struct and
// inserts them into the LatencyInfo portion of a StaticInfoExtn struct.
func (cfgdata StaticInfoCfg) gatherLatency(peers map[common.IFIDType]struct{},
	egifID common.IFIDType, inifID common.IFIDType) *seg.LatencyInfo {

	l := &seg.LatencyInfo{
		Inter:      cfgdata.Latency[egifID].Inter,
		Intra:      cfgdata.Latency[egifID].Intra[inifID],
		XoverIntra: make(map[common.IFIDType]uint32),
		Peers:      make(map[common.IFIDType]seg.PeerLatencyInfo),
	}
	// TODO(matzf): the interface-to-interface ("Intra") entries in the json file
	// are (expected to be) symmetric. Should fill this in for the places where this was omitted.
	for subintfid, intfdelay := range cfgdata.Latency[egifID].Intra {
		// If we're looking at a peering interface, always include the data
		if _, peer := peers[subintfid]; peer {
			l.Peers[subintfid] = seg.PeerLatencyInfo{
				Inter: cfgdata.Latency[subintfid].Inter,
				Intra: intfdelay,
			}
		} else {
			// If we're looking at a NON-peering interface, only include the data
			// if subintfid>egifID so as to not store redundant information
			// XXX(matzf): this is not handled in the combinator!?
			if subintfid > egifID {
				l.XoverIntra[subintfid] = intfdelay
			}
		}
	}
	return l
}

// gatherBW extracts bandwidth values from a StaticInfoCfg struct and
// inserts them into the BandwidthInfo portion of a StaticInfoExtn struct.
func (cfgdata StaticInfoCfg) gatherBW(peers map[common.IFIDType]struct{}, egifID common.IFIDType,
	inifID common.IFIDType) *seg.BandwidthInfo {

	bw := &seg.BandwidthInfo{
		Inter:      cfgdata.Bandwidth[egifID].Inter,
		Intra:      cfgdata.Bandwidth[egifID].Intra[inifID],
		XoverIntra: make(map[common.IFIDType]uint32),
		Peers:      make(map[common.IFIDType]seg.PeerBandwidthInfo),
	}
	for subintfid, intfbw := range cfgdata.Bandwidth[egifID].Intra {
		// If we're looking at a peering interface, always include the data
		if _, peer := peers[subintfid]; peer {
			bw.Peers[subintfid] = seg.PeerBandwidthInfo{
				Inter: cfgdata.Bandwidth[subintfid].Inter,
				Intra: intfbw,
			}
		} else {
			// If we're looking at a NON-peering interface, only include the
			// data if subintfid>egifID so as to not store redundant information
			if subintfid > egifID {
				bw.XoverIntra[subintfid] = intfbw
			}
		}
	}
	return bw
}

// gatherLinkType extracts linktype values from a StaticInfoCfg struct and
// inserts them into the LinkTypeInfo portion of a StaticInfoExtn struct.
func (cfgdata StaticInfoCfg) gatherLinkType(peers map[common.IFIDType]struct{},
	egifID common.IFIDType) seg.LinkTypeInfo {

	lt := make(seg.LinkTypeInfo)
	lt[egifID] = seg.LinkType(*cfgdata.LinkType[egifID])
	// Additionally add link type for peering links
	for ifid, intfLT := range cfgdata.LinkType {
		if _, peer := peers[ifid]; peer {
			lt[ifid] = seg.LinkType(*intfLT)
		}
	}
	return lt
}

// gatherHops extracts hop values from a StaticInfoCfg struct and
// inserts them into the InternalHopsinfo portion of a StaticInfoExtn struct.
func (cfgdata StaticInfoCfg) gatherHops(peers map[common.IFIDType]struct{},
	egifID common.IFIDType, inifID common.IFIDType) seg.InternalHopsInfo {

	l := seg.InternalHopsInfo{
		InToOutHops: cfgdata.Hops[egifID].Intra[inifID],
	}
	for intfid, intfHops := range cfgdata.Hops[egifID].Intra {
		// If we're looking at a peering interface or intfid>egifID, include
		// the data, otherwise drop it so as to not store redundant information
		if _, peer := peers[intfid]; peer || (intfid > egifID) {
			l.InterfaceHops = append(l.InterfaceHops, seg.InterfaceHops{
				Hops: intfHops,
				IfID: intfid,
			})
		}
	}
	return l
}

// gatherGeo extracts geo values from a StaticInfoCfg struct and
// inserts them into the GeoInfo portion of a StaticInfoExtn struct.
// TODO(matzf): this could be reduced to only include the relevant interfaces,
// i.e. ingress, egress, and peers.
func (cfgdata StaticInfoCfg) gatherGeo() seg.GeoInfo {
	gi := seg.GeoInfo{}
	for ifid, loc := range cfgdata.Geo {
		gi[ifid] = seg.GeoCoordinates{
			Longitude: loc.Longitude,
			Latitude:  loc.Latitude,
			Address:   loc.Address,
		}
	}
	return gi
}

// ParseStaticInfoCfg parses data from a config file into a StaticInfoCfg struct.
func ParseStaticInfoCfg(file string) (*StaticInfoCfg, error) {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, serrors.WrapStr("failed to read static info config: ",
			err, "file", file)
	}
	var cfg StaticInfoCfg
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, serrors.WrapStr("failed to parse static info config: ",
			err, "file ", file)
	}
	return &cfg, nil
}

// generateStaticinfo creates a StaticinfoExtn struct and
// populates it with data extracted from configdata.
func (cfgdata StaticInfoCfg) generateStaticinfo(peers map[common.IFIDType]struct{},
	egifID common.IFIDType, inifID common.IFIDType) seg.StaticInfoExtension {

	return seg.StaticInfoExtension{
		Latency:   cfgdata.gatherLatency(peers, egifID, inifID),
		Bandwidth: cfgdata.gatherBW(peers, egifID, inifID),
		LinkType:  cfgdata.gatherLinkType(peers, egifID),
		Geo:       cfgdata.gatherGeo(),
		Note:      cfgdata.Note,
		Hops:      cfgdata.gatherHops(peers, egifID, inifID),
	}
}
