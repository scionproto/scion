package seg

import (
	"math"
)

type LatencyInfo struct {
	Egresslatency    uint16                  `capnp:"egressLatency"`
	Intooutlatency   uint16                  `capnp:"ingressToEgressLatency"`
	Childlatencies   []Latencychildpair      `capnp:"childLatencies"`
	Peeringlatencies []Latencypeeringtriplet `capnp:"peeringLatencies"`
}

type Latencychildpair struct {
	Intradelay uint16 `capnp:"intra"`
	Interface  uint16 `capnp:"ifID"`
}

type Latencypeeringtriplet struct {
	Interdelay uint16 `capnp:"inter"`
	IntraDelay uint16 `capnp:"intra"`
	IntfID     uint16 `capnp:"ifID"`
}

type BandwidthInfo struct {
	EgressBW  uint32   `capnp:"egressBW"`
	IntooutBW uint32   `capnp:"ingressToEgressBW"`
	BWPairs   []BWPair `capnp:"bandwidths"`
}

type BWPair struct {
	BW     uint32 `capnp:"bw"`
	IntfID uint16 `capnp:"ifID"`
}

type GeoInfo struct {
	Locations []Location `capnp:"locations"`
}

type Location struct {
	GPSData Coordinates `capnp:"gpsData"`
	IntfIDs []uint16    `capnp:"interfaces"`
}

type Coordinates struct {
	Latitude  float32 `capnp:"latitude"`
	Longitude float32 `capnp:"longitude"`
	Address   string  `capnp:"address"`
}

type LinktypeInfo struct {
	EgressLT     string          `capnp:"egressLinkType"`
	Peeringlinks []LTPeeringpair `capnp:"peeringLinks"`
}

type LTPeeringpair struct {
	IntfID uint16 `capnp:"ifID"`
	IntfLT string `capnp:"linkType"`
}

type InternalHopsInfo struct {
	Intououthops uint8     `capnp:"inToOutHops"`
	Hoppairs     []Hoppair `capnp:"interfaceHops"`
}

type Hoppair struct {
	Hops   uint8  `capnp:"hops"`
	IntfID uint16 `capnp:"ifID"`
}

type StaticInfoExtn struct {
	Latency   LatencyInfo      `capnp:"latency"`
	Geo       GeoInfo          `capnp:"geo"`
	Linktype  LinktypeInfo     `capnp:"linktype"`
	Bandwidth BandwidthInfo    `capnp:"bandwidth"`
	Hops      InternalHopsInfo `capnp:"internalHops"`
	Note      string           `capnp:"note"`
}

// gatherlatency extracts latency values from a Configdata struct and
// inserts them into the LatencyInfo portion of a StaticInfoExtn struct.
func (latinf *LatencyInfo) gatherlatency(cfgdata Configdata, peers map[uint16]bool, egifID uint16, inifID uint16) {
	latinf.Egresslatency = cfgdata.Latency[egifID].Inter
	latinf.Intooutlatency = cfgdata.Latency[egifID].Intra[inifID]
	for subintfid, intfdelay := range cfgdata.Latency[egifID].Intra {
		if !(peers[subintfid]) {
			if subintfid > egifID {
				var latpair Latencychildpair
				latpair.Intradelay = intfdelay
				latpair.Interface = subintfid
				latinf.Childlatencies = append(latinf.Childlatencies, latpair)
			}
		} else {
			var lattriple Latencypeeringtriplet
			lattriple.IntfID = subintfid
			lattriple.Interdelay = cfgdata.Latency[subintfid].Inter
			lattriple.IntraDelay = intfdelay
			latinf.Peeringlatencies = append(latinf.Peeringlatencies, lattriple)
		}
	}
}

// gatherbw extracts bandwidth values from a Configdata struct and
// inserts them into the BandwidthInfo portion of a StaticInfoExtn struct.
func (bwinf *BandwidthInfo) gatherbw(cfgdata Configdata, peers map[uint16]bool, egifID uint16, inifID uint16) {
	bwinf.EgressBW = cfgdata.Bandwidth[egifID].Inter
	bwinf.IntooutBW = cfgdata.Bandwidth[egifID].Intra[inifID]
	for subintfid, intfbw := range cfgdata.Bandwidth[egifID].Intra {
		var minbw uint32
		if subintfid > egifID {
			if peers[subintfid] {
				minbw = uint32(math.Min(float64(intfbw), float64(cfgdata.Bandwidth[subintfid].Inter)))
			} else {
				minbw = intfbw
			}
			var bwpair BWPair
			bwpair.BW = minbw
			bwpair.IntfID = subintfid
			bwinf.BWPairs = append(bwinf.BWPairs, bwpair)
		}
	}
}

// gatherlinktype extracts linktype values from a Configdata struct and
// inserts them into the LinktypeInfo portion of a StaticInfoExtn struct.
func (ltinf *LinktypeInfo) gatherlinktype(cfgdata Configdata, peers map[uint16]bool, egifID uint16) {
	ltinf.EgressLT = cfgdata.Linktype[egifID]
	for intfid, intfLT := range cfgdata.Linktype {
		if peers[intfid] {
			var ltpair LTPeeringpair
			ltpair.IntfLT = intfLT
			ltpair.IntfID = intfid
			ltinf.Peeringlinks = append(ltinf.Peeringlinks, ltpair)
		}
	}
}

// gatherhops extracts hop values from a Configdata struct and
// inserts them into the InternalHopsinfo portion of a StaticInfoExtn struct.
func (nhinf *InternalHopsInfo) gatherhops(cfgdata Configdata, egifID uint16, inifID uint16) {
	nhinf.Intououthops = cfgdata.Hops[egifID].Intra[inifID]
	for subintfid, hops := range cfgdata.Hops[egifID].Intra {
		if subintfid > egifID {
			var hoppair Hoppair
			hoppair.Hops = hops
			hoppair.IntfID = subintfid
			nhinf.Hoppairs = append(nhinf.Hoppairs, hoppair)
		}
	}
}

// gathergeo extracts geo values from a Configdata struct and
// inserts them into the GeoInfo portion of a StaticInfoExtn struct.
func (geoinf *GeoInfo) gathergeo(cfgdata Configdata) {
	for intfid, loc := range cfgdata.Geo {
		var assigned = false
		for k := 0; k < len(geoinf.Locations); k++ {
			if (loc.Longitude == geoinf.Locations[k].GPSData.Longitude) && (loc.Latitude == geoinf.Locations[k].GPSData.Latitude) && (loc.Address == geoinf.Locations[k].GPSData.Address) && (!assigned) {
				geoinf.Locations[k].IntfIDs = append(geoinf.Locations[k].IntfIDs, intfid)
				assigned = true
			}
		}
		if !assigned {
			var locaction Location
			locaction.GPSData.Longitude = loc.Longitude
			locaction.GPSData.Latitude = loc.Latitude
			locaction.GPSData.Address = loc.Address
			locaction.IntfIDs = append(locaction.IntfIDs, intfid)
			geoinf.Locations = append(geoinf.Locations, locaction)
			assigned = true
		}
	}
}
