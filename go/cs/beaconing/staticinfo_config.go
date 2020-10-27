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
	"time"

	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg/extensions/staticinfo"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
)

type InterfaceLatencies struct {
	Inter util.DurWrap                     `json:"Inter"`
	Intra map[common.IFIDType]util.DurWrap `json:"Intra"`
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
	Intra map[common.IFIDType]uint32 `json:"Intra"`
}

type LinkType staticinfo.LinkType

func (l *LinkType) MarshalText() ([]byte, error) {
	switch *l {
	case staticinfo.LinkTypeDirect:
		return []byte("direct"), nil
	case staticinfo.LinkTypeMultihop:
		return []byte("multihop"), nil
	case staticinfo.LinkTypeOpennet:
		return []byte("opennet"), nil
	default:
		return nil, serrors.New("invalid link type value")
	}
}

func (l *LinkType) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "direct":
		*l = staticinfo.LinkTypeDirect
	case "multihop":
		*l = staticinfo.LinkTypeMultihop
	case "opennet":
		*l = staticinfo.LinkTypeOpennet
	default:
		return serrors.New("invalid link type", "link type", text)
	}
	return nil
}

// StaticInfoCfg is used to parse data from config.json.
type StaticInfoCfg struct {
	Latency   map[common.IFIDType]InterfaceLatencies  `json:"Latency"`
	Bandwidth map[common.IFIDType]InterfaceBandwidths `json:"Bandwidth"`
	LinkType  map[common.IFIDType]LinkType            `json:"LinkType"`
	Geo       map[common.IFIDType]InterfaceGeodata    `json:"Geo"`
	Hops      map[common.IFIDType]InterfaceHops       `json:"Hops"`
	Note      string                                  `json:"Note"`
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
	// TODO(matzf): the interface-to-interface ("Intra") entries in the json file
	// are (expected to be!) symmetric. Check & fill in the symmetric entries.
	return &cfg, nil
}

// Generate creates a StaticInfoExtn struct and
// populates it with data extracted from the configuration.
func (cfg StaticInfoCfg) Generate(intfs *ifstate.Interfaces,
	ingress, egress common.IFIDType) *staticinfo.Extension {

	ifType := interfaceTypeTable(intfs)
	return cfg.gather(ifType, ingress, egress)
}

func (cfg StaticInfoCfg) gather(ifType map[common.IFIDType]topology.LinkType,
	ingress, egress common.IFIDType) *staticinfo.Extension {

	return &staticinfo.Extension{
		Latency:      cfg.gatherLatency(ifType, ingress, egress),
		Bandwidth:    cfg.gatherBW(ifType, ingress, egress),
		Geo:          cfg.gatherGeo(ifType, ingress, egress),
		LinkType:     cfg.gatherLinkType(ifType, egress),
		InternalHops: cfg.gatherHops(ifType, ingress, egress),
		Note:         cfg.Note,
	}
}

// gatherLatency extracts latency values from a StaticInfoCfg struct and
// inserts them into the LatencyInfo portion of a StaticInfoExtn struct.
func (cfg StaticInfoCfg) gatherLatency(ifType map[common.IFIDType]topology.LinkType,
	ingress, egress common.IFIDType) *staticinfo.LatencyInfo {

	l := &staticinfo.LatencyInfo{
		Intra: make(map[common.IFIDType]time.Duration),
		Inter: make(map[common.IFIDType]time.Duration),
	}
	if egress != 0 {
		for ifid, v := range cfg.Latency[egress].Intra {
			if includeIntraInfo(ifType, ifid, ingress, egress) {
				l.Intra[ifid] = v.Duration
			}
		}
	}
	for ifid, v := range cfg.Latency {
		t := ifType[ifid]
		if ifid == egress || t == topology.Peer {
			l.Inter[ifid] = v.Inter.Duration
		}
	}
	return l
}

// gatherBW extracts bandwidth values from a StaticInfoCfg struct and
// inserts them into the BandwidthInfo portion of a StaticInfoExtn struct.
func (cfg StaticInfoCfg) gatherBW(ifType map[common.IFIDType]topology.LinkType,
	ingress, egress common.IFIDType) *staticinfo.BandwidthInfo {

	bw := &staticinfo.BandwidthInfo{
		Intra: make(map[common.IFIDType]uint32),
		Inter: make(map[common.IFIDType]uint32),
	}
	if _, ok := cfg.Bandwidth[egress]; egress != 0 && ok {
		bw.Inter[egress] = cfg.Bandwidth[egress].Inter
		for ifid, v := range cfg.Bandwidth[egress].Intra {
			if includeIntraInfo(ifType, ifid, ingress, egress) {
				bw.Intra[ifid] = v
			}
		}
	}
	for ifid, v := range cfg.Bandwidth {
		t := ifType[ifid]
		if ifid == egress || t == topology.Peer {
			bw.Inter[ifid] = v.Inter
		}
	}
	return bw
}

// gatherLinkType extracts linktype values from a StaticInfoCfg struct and
// inserts them into the LinkTypeInfo portion of a StaticInfoExtn struct.
func (cfg StaticInfoCfg) gatherLinkType(ifType map[common.IFIDType]topology.LinkType,
	egress common.IFIDType) staticinfo.LinkTypeInfo {

	lt := make(staticinfo.LinkTypeInfo)
	for ifid, intfLT := range cfg.LinkType {
		t := ifType[ifid]
		if ifid == egress || t == topology.Peer {
			lt[ifid] = staticinfo.LinkType(intfLT)
		}
	}
	return lt
}

// gatherHops extracts hop values from a StaticInfoCfg struct and
// inserts them into the InternalHopsinfo portion of a StaticInfoExtn struct.
func (cfg StaticInfoCfg) gatherHops(ifType map[common.IFIDType]topology.LinkType,
	ingress, egress common.IFIDType) staticinfo.InternalHopsInfo {

	ihi := make(staticinfo.InternalHopsInfo)
	for ifid, v := range cfg.Hops[egress].Intra {
		if includeIntraInfo(ifType, ifid, ingress, egress) {
			ihi[ifid] = v
		}
	}
	return ihi
}

// gatherGeo extracts geo values from a StaticInfoCfg struct and
// inserts them into the GeoInfo portion of a StaticInfoExtn struct.
func (cfg StaticInfoCfg) gatherGeo(ifType map[common.IFIDType]topology.LinkType,
	ingress, egress common.IFIDType) staticinfo.GeoInfo {

	gi := staticinfo.GeoInfo{}
	for ifid, loc := range cfg.Geo {
		t := ifType[ifid]
		if ifid == egress || ifid == ingress || t == topology.Peer {
			gi[ifid] = staticinfo.GeoCoordinates{
				Longitude: loc.Longitude,
				Latitude:  loc.Latitude,
				Address:   loc.Address,
			}
		}
	}
	return gi
}

// includeIntraInfo determines if the intra-AS metadata info for the interface
// pair (ifid, egress) should be included in this beacon:
// Include information between the egress interface and
// - ingress interface
// - sibling child interfaces,
// - core interfaces, at start or end of a segment
// - peer interfaces
// For core/sibling child interfaces, we can skip some entries to avoid
// redundancy: by consistently only including latency to interfaces with
// ifid > egress, we ensure that for each cross-over, the latency from
// this AS Entry's egress interface to the other AS Entry's egress
// interface will be available in exactly one of the two AS Entries.
// Note that the choice of < or > is arbitrary.  At least each separate
// AS needs to pick one consistently (or decide to just include the full
// information all the time), otherwise information for cross-overs may
// be missing.
func includeIntraInfo(ifType map[common.IFIDType]topology.LinkType,
	ifid, ingress, egress common.IFIDType) bool {

	t := ifType[ifid]
	return ifid == ingress ||
		t == topology.Child && ifid > egress ||
		t == topology.Core && (egress == 0 || ingress == 0) && ifid > egress ||
		t == topology.Peer
}

func interfaceTypeTable(intfs *ifstate.Interfaces) map[common.IFIDType]topology.LinkType {
	ifTypes := make(map[common.IFIDType]topology.LinkType)
	for ifID, ifInfo := range intfs.All() {
		ifTypes[ifID] = ifInfo.TopoInfo().LinkType
	}
	return ifTypes
}
