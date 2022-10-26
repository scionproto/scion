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
	"os"
	"strings"
	"time"

	"github.com/scionproto/scion/control/ifstate"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/segment/extensions/staticinfo"
	"github.com/scionproto/scion/private/topology"
)

type InterfaceLatencies struct {
	Inter util.DurWrap                     `json:"Inter"`
	Intra map[common.IFIDType]util.DurWrap `json:"Intra"`
}

type InterfaceBandwidths struct {
	Inter uint64                     `json:"Inter"`
	Intra map[common.IFIDType]uint64 `json:"Intra"`
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
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, serrors.WrapStr("failed to read static info config: ",
			err, "file", file)
	}
	var cfg StaticInfoCfg
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, serrors.WrapStr("failed to parse static info config: ",
			err, "file ", file)
	}
	cfg.clean()
	return &cfg, nil
}

// clean checks or corrects the entries in the static info configuration.
// In particular, it will
//   - ensure there are no entries for the 0 interface ID (as this is invalid
//     and the beacon extender code uses 0 as the interface number for
//     originating/terminating beacons), and
//   - ensure the symmetry of the interface-to-interface ("Intra") entries,
//     allowing to specify them in only one direction.
func (cfg *StaticInfoCfg) clean() {

	delete(cfg.Latency, 0)
	for _, s := range cfg.Latency {
		delete(s.Intra, 0)
	}
	delete(cfg.Bandwidth, 0)
	for _, s := range cfg.Bandwidth {
		delete(s.Intra, 0)
	}
	delete(cfg.LinkType, 0)
	delete(cfg.Geo, 0)
	delete(cfg.Hops, 0)
	for _, s := range cfg.Hops {
		delete(s.Intra, 0)
	}

	symmetrizeLatency(cfg.Latency)
	symmetrizeBandwidth(cfg.Bandwidth)
	symmetrizeHops(cfg.Hops)
}

// symmetrizeLatency makes the Intra latency values symmetric
func symmetrizeLatency(latency map[common.IFIDType]InterfaceLatencies) {
	for i, sub := range latency {
		delete(sub.Intra, i) // Remove loopy entry
		for j, v := range sub.Intra {
			if _, ok := latency[j]; !ok {
				continue
			}
			if latency[j].Intra == nil {
				latency[j] = InterfaceLatencies{
					Inter: latency[j].Inter,
					Intra: make(map[common.IFIDType]util.DurWrap),
				}
			}
			vTransposed, ok := latency[j].Intra[i]
			// Set if not specified or pick more conservative value if both are specified
			if !ok || v.Duration > vTransposed.Duration {
				latency[j].Intra[i] = v
			}
		}
	}
}

// symmetrizeBandwidth makes the Intra bandwidth values symmetric
func symmetrizeBandwidth(bandwidth map[common.IFIDType]InterfaceBandwidths) {
	for i, sub := range bandwidth {
		delete(sub.Intra, i) // Remove loopy entry
		for j, v := range sub.Intra {
			if _, ok := bandwidth[j]; !ok {
				continue
			}
			if bandwidth[j].Intra == nil {
				bandwidth[j] = InterfaceBandwidths{
					Inter: bandwidth[j].Inter,
					Intra: make(map[common.IFIDType]uint64),
				}
			}
			vTransposed, ok := bandwidth[j].Intra[i]
			// Set if not specified or pick more conservative value if both are specified
			if !ok || v < vTransposed {
				bandwidth[j].Intra[i] = v
			}
		}
	}
}

// symmetrizeHops makes the Intra hops values symmetric
func symmetrizeHops(hops map[common.IFIDType]InterfaceHops) {
	for i, sub := range hops {
		delete(sub.Intra, i) // Remove loopy entry
		for j, v := range sub.Intra {
			if _, ok := hops[j]; !ok {
				hops[j] = InterfaceHops{
					Intra: make(map[common.IFIDType]uint32),
				}
			}
			vTransposed, ok := hops[j].Intra[i]
			// Set if not specified or pick more conservative value if both are specified
			if !ok || v < vTransposed {
				hops[j].Intra[i] = v
			}
		}
	}
}

// Generate creates a StaticInfoExtn struct and
// populates it with data extracted from the configuration.
func (cfg StaticInfoCfg) Generate(intfs *ifstate.Interfaces,
	ingress, egress uint16) *staticinfo.Extension {

	ifType := interfaceTypeTable(intfs)
	return cfg.generate(ifType, common.IFIDType(ingress), common.IFIDType(egress))
}

func (cfg StaticInfoCfg) generate(ifType map[common.IFIDType]topology.LinkType,
	ingress, egress common.IFIDType) *staticinfo.Extension {

	return &staticinfo.Extension{
		Latency:      cfg.generateLatency(ifType, ingress, egress),
		Bandwidth:    cfg.generateBandwidth(ifType, ingress, egress),
		Geo:          cfg.generateGeo(ifType, ingress, egress),
		LinkType:     cfg.generateLinkType(ifType, egress),
		InternalHops: cfg.generateInternalHops(ifType, ingress, egress),
		Note:         cfg.Note,
	}
}

// generateLatency creates the LatencyInfo by extracting the relevant values from
// the config.
func (cfg StaticInfoCfg) generateLatency(ifType map[common.IFIDType]topology.LinkType,
	ingress, egress common.IFIDType) staticinfo.LatencyInfo {

	l := staticinfo.LatencyInfo{
		Intra: make(map[common.IFIDType]time.Duration),
		Inter: make(map[common.IFIDType]time.Duration),
	}
	for ifid, v := range cfg.Latency[egress].Intra {
		if includeIntraInfo(ifType, ifid, ingress, egress) {
			l.Intra[ifid] = v.Duration
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

// generateBandwidth creates the BandwidthInfo by extracting the relevant values
// from the config.
func (cfg StaticInfoCfg) generateBandwidth(ifType map[common.IFIDType]topology.LinkType,
	ingress, egress common.IFIDType) staticinfo.BandwidthInfo {

	bw := staticinfo.BandwidthInfo{
		Intra: make(map[common.IFIDType]uint64),
		Inter: make(map[common.IFIDType]uint64),
	}
	for ifid, v := range cfg.Bandwidth[egress].Intra {
		if includeIntraInfo(ifType, ifid, ingress, egress) {
			bw.Intra[ifid] = v
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

// generateLinkType creates the LinkTypeInfo by extracting the relevant values from
// the config.
func (cfg StaticInfoCfg) generateLinkType(ifType map[common.IFIDType]topology.LinkType,
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

// generateInternalHops creates the InternalHopsInfo by extracting the relevant
// values from the config.
func (cfg StaticInfoCfg) generateInternalHops(ifType map[common.IFIDType]topology.LinkType,
	ingress, egress common.IFIDType) staticinfo.InternalHopsInfo {

	ihi := make(staticinfo.InternalHopsInfo)
	for ifid, v := range cfg.Hops[egress].Intra {
		if includeIntraInfo(ifType, ifid, ingress, egress) {
			ihi[ifid] = v
		}
	}
	return ihi
}

// generateGeo creates the GeoInfo by extracting the relevant values from
// the config.
func (cfg StaticInfoCfg) generateGeo(ifType map[common.IFIDType]topology.LinkType,
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

	isCoreIngress := (ifType[ingress] == topology.Core || ingress == 0)
	isCoreEgress := (ifType[egress] == topology.Core || egress == 0)
	isCoreSeg := isCoreIngress && isCoreEgress
	if isCoreSeg {
		return ifid == ingress
	}
	t := ifType[ifid]
	return ifid == ingress ||
		t == topology.Child && ifid > egress ||
		t == topology.Core ||
		t == topology.Peer
}

func interfaceTypeTable(intfs *ifstate.Interfaces) map[common.IFIDType]topology.LinkType {
	ifMap := intfs.All()
	ifTypes := make(map[common.IFIDType]topology.LinkType, len(ifMap))
	for ifID, ifInfo := range ifMap {
		ifTypes[common.IFIDType(ifID)] = ifInfo.TopoInfo().LinkType
	}
	return ifTypes
}
