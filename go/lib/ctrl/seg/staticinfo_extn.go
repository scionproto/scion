package seg

import (
	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/lib/topology"
	"math"
)


type LatencyInfo struct {
	Egresslatency uint16 `capnp:"egressLatency"`
	Intooutlatency uint16 `capnp:"ingressToEgressLatency"`
	Childlatencies    []Latencychildpair `capnp:"childLatencies"`
	Peeringlatencies     []Latencypeeringtriplet `capnp:"peeringLatencies"`
}

type Latencychildpair struct {
	Intradelay uint16   `capnp:"intraDelay"`
	Interface  uint16 `capnp:"interface"`
}

type Latencypeeringtriplet struct {
	Interdelay uint16 `capnp:"interDelay"`
	IntraDelay uint16 `capnp:"intraDelay"`
	IntfID uint16 `capnp:"interface"`
}


type BandwidthInfo struct {
	EgressBW uint32 `capnp:"egressBW"`
	IntooutBW uint32 `capnp:"ingressToEgressBW"`
	BWPairs []BWPair `capnp:"bandwidthPairs"`
}

type BWPair struct {
	BW  uint32   `capnp:"BW"`
	IntfID uint16 `capnp:"interface"`
}


type GeoInfo struct {
	Locations []Location `capnp:"locations"`
}

type Location struct {
	GPSData      Coordinates `capnp:"gpsData"`
	IntfIDs []uint16 `capnp:"interfaces"`
}

type Coordinates struct {
	Latitude   float32 `capnp:"latitude"`
	Longitude   float32 `capnp:"longitude"`
	Address string  `capnp:"address"`
}


type LinktypeInfo struct {
	EgressLT   string `capnp:"egressLinkType"`
	Peeringlinks  []LTPeeringpair `capnp:"peeringLinks"`
}

type LTPeeringpair struct {
	IntfID uint16 `capnp:"interface"`
	IntfLT string `capnp:"peeringLinkType"`
}


type InternalHopsInfo struct {
	Intououthops uint8 `capnp:"inToOutHops"`
	Hoppairs []Hoppair `capnp:"hopPairs"`
}

type Hoppair struct {
	Hops uint8    `capnp:"Hops"`
	IntfID uint16 `capnp:"interface"`
}


type StaticInfoExtn struct {
	Latency LatencyInfo      `capnp:"latency"`
	Geo GeoInfo          `capnp:"geo"`
	Linktype LinktypeInfo     `capnp:"linktype"`
	Bandwidth BandwidthInfo    `capnp:"bandwidth"`
	Hops InternalHopsInfo `capnp:"internalHops"`
	Note string            `capnp:"note"`
}

// CreatePeerMap creates a map from interface IDs to booleans indicating whether the respective interface is used for
// peering or not.
func CreatePeerMap(cfg beaconing.ExtenderConf) map[uint16]bool{
	var peers map[uint16]bool
	for ifID, ifInfo := range cfg.Intfs.All(){
		peers[uint16(ifID)] = (ifInfo.TopoInfo().LinkType) == topology.Peer
	}
	return peers
}

// gatherlatency takes an intermediate struct only used to parse data from a config.json file, a map of interface IDs to
// booleans indicating whether the interface in question is used for peering, and egress interface ID and an
// ingress interface ID.
// Extracts latency values from that struct and inserts them into the latency portion of a StaticInfoExtn struct.
func (latinf *LatencyInfo) gatherlatency(somestruct Configdata, peers map[uint16]bool, egifID uint16, inifID uint16) {
	latinf.Egresslatency = somestruct.Latency[egifID].Inter
	latinf.Intooutlatency = somestruct.Latency[egifID].Intra[inifID]
	for subintfid, intfdelay := range somestruct.Latency[egifID].Intra{
		if !(peers[subintfid]) {
			if subintfid > egifID {
				var asdf Latencychildpair
				asdf.Intradelay = intfdelay
				asdf.Interface = subintfid
				latinf.Childlatencies = append(latinf.Childlatencies, asdf)
			}
		} else {
			var asdf Latencypeeringtriplet
			asdf.IntfID = subintfid
			asdf.Interdelay = somestruct.Latency[subintfid].Inter
			asdf.IntraDelay = intfdelay
			latinf.Peeringlatencies = append(latinf.Peeringlatencies, asdf)
		}
	}
}

// gatherbw takes an intermediate struct only used to parse data from a config.json file, a map of interface IDs to
// booleans indicating whether the interface in question is used for peering, and egress interface ID and an
// ingress interface ID.
// Extracts bandwidth values from that struct and inserts them into the bandwidth portion of a StaticInfoExtn struct.
func (bwinf *BandwidthInfo) gatherbw(somestruct Configdata, peers map[uint16]bool, egifID uint16, inifID uint16) {
	bwinf.EgressBW = somestruct.Bandwidth[egifID].Inter
	bwinf.IntooutBW = somestruct.Bandwidth[egifID].Intra[inifID]
	for subintfid, intfbw := range somestruct.Bandwidth[egifID].Intra{
		var minbw uint32
		if subintfid>egifID{
			if peers[subintfid]{
				minbw = uint32(math.Min(float64(intfbw), float64(somestruct.Bandwidth[subintfid].Inter)))
			} else {
				minbw = intfbw
			}
			var asdf BWPair
			asdf.BW = minbw
			asdf.IntfID = subintfid
			bwinf.BWPairs = append(bwinf.BWPairs, asdf)
		}
	}
}

// gatherlinktype takes an intermediate struct only used to parse data from a config.json file, a map of interface IDs to
// booleans indicating whether the interface in question is used for peering, and egress interface ID.
// Extracts linktype values from that struct and inserts them into the linktype portion of a StaticInfoExtn struct.
func (ltinf *LinktypeInfo) gatherlinktype(somestruct Configdata, peers map[uint16]bool, egifID uint16) {
	ltinf.EgressLT = somestruct.Linktype[egifID]
	for intfid, intfLT := range somestruct.Linktype {
		if (peers[intfid]) {
			var asdf LTPeeringpair
			asdf.IntfLT = intfLT
			asdf.IntfID = intfid
			ltinf.Peeringlinks = append(ltinf.Peeringlinks, asdf)
		}
	}
}

// gatherhops takes an intermediate struct only used to parse data from a config.json file, an egress and ingress
// interface ID.
// Extracts linktype values from that struct and inserts them into the linktype portion of a StaticInfoExtn struct.
func (nhinf *InternalHopsInfo) gatherhops(somestruct Configdata, egifID uint16, inifID uint16){
	nhinf.Intououthops = somestruct.Hops[egifID].Intra[inifID]
	for subintfid, hops := range somestruct.Hops[egifID].Intra {
		if (subintfid>egifID) {
			var asdf Hoppair
			asdf.Hops = hops
			asdf.IntfID = subintfid
			nhinf.Hoppairs = append(nhinf.Hoppairs, asdf)
		}
	}
}

// gathergeo takes an intermediate struct only used to parse data from a config.json file.
// Extracts geo values from that struct and inserts them into the geo portion of a StaticInfoExtn struct.
func (geoinf *GeoInfo) gathergeo(somestruct Configdata) {
	for intfid, loc := range somestruct.Geo {
		var assigned = false
		for k := 0; k < len(geoinf.Locations); k++ {
			if (loc.Longitude == geoinf.Locations[k].GPSData.Longitude) && (loc.Latitude == geoinf.Locations[k].GPSData.Latitude) && (loc.Address == geoinf.Locations[k].GPSData.Address) && (!assigned) {
				geoinf.Locations[k].IntfIDs = append(geoinf.Locations[k].IntfIDs, intfid)
				assigned = true
			}
		}
		if !assigned {
			var asdf Location
			asdf.GPSData.Longitude = loc.Longitude
			asdf.GPSData.Latitude = loc.Latitude
			asdf.GPSData.Address = loc.Address
			asdf.IntfIDs = append(asdf.IntfIDs, intfid)
			geoinf.Locations = append(geoinf.Locations, asdf)
			assigned = true
		}
	}
}
