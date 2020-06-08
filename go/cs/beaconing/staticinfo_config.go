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
	"math"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/serrors"
)

type InterfaceLatencies struct {
	Inter uint16                     `json:"Inter"`
	Intra map[common.IFIDType]uint16 `json:"Intra"`
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

// StaticInfoCfg is used to parse data from config.json.
type StaticInfoCfg struct {
	Latency   map[common.IFIDType]InterfaceLatencies  `json:"Latency"`
	Bandwidth map[common.IFIDType]InterfaceBandwidths `json:"Bandwidth"`
	Linktype  map[common.IFIDType]string              `json:"Linktype"`
	Geo       map[common.IFIDType]InterfaceGeodata    `json:"Geo"`
	Hops      map[common.IFIDType]InterfaceHops       `json:"Hops"`
	Note      string                                  `json:"Note"`
}

// gatherLatency extracts latency values from a StaticInfoCfg struct and
// inserts them into the LatencyInfo portion of a StaticInfoExtn struct.
func (cfgdata *StaticInfoCfg) gatherLatency(peers map[common.IFIDType]struct{},
	egifID common.IFIDType, inifID common.IFIDType) seg.LatencyInfo {

	l := seg.LatencyInfo{
		Egresslatency:          cfgdata.Latency[egifID].Inter,
		IngressToEgressLatency: cfgdata.Latency[egifID].Intra[inifID],
	}
	for subintfid, intfdelay := range cfgdata.Latency[egifID].Intra {
		// If we're looking at a peering interface, always include the data
		if _, peer := peers[subintfid]; peer {
			l.Peerlatencies = append(l.Peerlatencies, seg.PeerLatency{
				IfID:       subintfid,
				Interdelay: cfgdata.Latency[subintfid].Inter,
				IntraDelay: intfdelay,
			})
			continue
		}
		l.Childlatencies = append(l.Childlatencies, seg.ChildLatency{
			Intradelay: intfdelay,
			IfID:       subintfid,
		})
	}
	return l
}

// gatherBW extracts bandwidth values from a StaticInfoCfg struct and
// inserts them into the BandwidthInfo portion of a StaticInfoExtn struct.
func (cfgdata *StaticInfoCfg) gatherBW(peers map[common.IFIDType]struct{}, egifID common.IFIDType,
	inifID common.IFIDType) seg.BandwidthInfo {

	l := seg.BandwidthInfo{
		EgressBW:          cfgdata.Bandwidth[egifID].Inter,
		IngressToEgressBW: cfgdata.Bandwidth[egifID].Intra[inifID],
	}
	for subintfid, intfbw := range cfgdata.Bandwidth[egifID].Intra {
		// If we're looking at a peering interface, always include the data
		if _, peer := peers[subintfid]; peer {
			l.Bandwidths = append(l.Bandwidths, seg.InterfaceBandwidth{
				IfID: subintfid,
				BW: uint32(math.Min(float64(intfbw),
					float64(cfgdata.Bandwidth[subintfid].Inter))),
			})
			continue
		}
		l.Bandwidths = append(l.Bandwidths, seg.InterfaceBandwidth{
			BW:   intfbw,
			IfID: subintfid,
		})
	}
	return l
}

// transformLinkType transforms the linktype from a string into a
// value that can be automatically parsed into a capnp enum.
func transformLinkType(linktype string) uint16 {
	switch linktype {
	case "direct":
		return 1
	case "multihop":
		return 2
	case "opennet":
		return 3
	default:
		return 0
	}
}

func truncateString(s string, num int) string {
	if len(s) > num {
		return s[:num]
	}
	return s
}

// gatherLinktype extracts linktype values from a StaticInfoCfg struct and
// inserts them into the LinktypeInfo portion of a StaticInfoExtn struct.
func (cfgdata *StaticInfoCfg) gatherLinkType(peers map[common.IFIDType]struct{},
	egifID common.IFIDType) seg.LinktypeInfo {

	l := seg.LinktypeInfo{
		EgressLinkType: transformLinkType(cfgdata.Linktype[egifID]),
	}
	for intfid, intfLT := range cfgdata.Linktype {
		// If we're looking at a peering interface, include the data for
		// the peering link, otherwise drop it
		if _, peer := peers[intfid]; peer {
			l.Peerlinks = append(l.Peerlinks, seg.InterfaceLinkType{
				LinkType: transformLinkType(intfLT),
				IfID:     intfid,
			})
		}
	}
	return l
}

// gatherHops extracts hop values from a StaticInfoCfg struct and
// inserts them into the InternalHopsinfo portion of a StaticInfoExtn struct.
func (cfgdata *StaticInfoCfg) gatherHops(peers map[common.IFIDType]struct{},
	egifID common.IFIDType, inifID common.IFIDType) seg.InternalHopsInfo {

	l := seg.InternalHopsInfo{
		InToOutHops: cfgdata.Hops[egifID].Intra[inifID],
	}
	for intfid, intfHops := range cfgdata.Hops[egifID].Intra {
		l.InterfaceHops = append(l.InterfaceHops, seg.InterfaceHops{
			Hops: intfHops,
			IfID: intfid,
		})
	}
	return l
}

// gatherGeo extracts geo values from a StaticInfoCfg struct and
// inserts them into the GeoInfo portion of a StaticInfoExtn struct.
func (cfgdata *StaticInfoCfg) gatherGeo() seg.GeoInfo {
	l := seg.GeoInfo{}
	for intfid, loc := range cfgdata.Geo {
		assigned := false
		for k := 0; k < len(l.Locations); k++ {
			if (loc.Longitude == l.Locations[k].GPSData.Longitude) &&
				(loc.Latitude == l.Locations[k].GPSData.Latitude) &&
				(truncateString(loc.Address, 500) == l.Locations[k].GPSData.Address) && (!assigned) {
				l.Locations[k].IfIDs = append(l.Locations[k].IfIDs, intfid)
				assigned = true
			}
		}
		if !assigned {
			l.Locations = append(l.Locations, seg.Location{
				GPSData: seg.Coordinates{
					Longitude: loc.Longitude,
					Latitude:  loc.Latitude,
					Address:   truncateString(loc.Address, 500),
				},
				IfIDs: []common.IFIDType{intfid},
			})
		}
	}
	return l
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
func (cfgdata *StaticInfoCfg) generateStaticinfo(peers map[common.IFIDType]struct{},
	egifID common.IFIDType, inifID common.IFIDType) seg.StaticInfoExtn {

	return seg.StaticInfoExtn{
		Latency:   cfgdata.gatherLatency(peers, egifID, inifID),
		Bandwidth: cfgdata.gatherBW(peers, egifID, inifID),
		Linktype:  cfgdata.gatherLinkType(peers, egifID),
		Geo:       cfgdata.gatherGeo(),
		Note:      truncateString(cfgdata.Note, 2000),
		Hops:      cfgdata.gatherHops(peers, egifID, inifID),
	}
}
